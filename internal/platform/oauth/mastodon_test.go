package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// mastodonTestServer 是 Mastodon RFC 8414 metadata/token/userinfo/verify_credentials
// 的 mock 服务器。userinfo 非空时元数据声明 userinfo_endpoint（4.4+），
// 否则走 4.3 verify_credentials 回退。
type mastodonTestServer struct {
	srv           *httptest.Server
	userinfoCalls int
	verifyCalls   int
}

// mastodonTestOptions 配置 mock Mastodon 服务器的行为。
type mastodonTestOptions struct {
	// userinfo 是 userinfo 端点返回的 JSON；非空时元数据声明 userinfo_endpoint。
	userinfo map[string]any
	// verifyCred 是 verify_credentials 端点返回的 JSON。
	verifyCred map[string]any
	// metadataStatus 覆盖 metadata 端点状态码（默认 200）。
	metadataStatus int
	// tokenStatus 覆盖 token 端点状态码（默认 200）。
	tokenStatus int
	// tokenCheck 校验 token 请求参数；返回错误时拒绝。
	tokenCheck func(r *http.Request) error
}

// newMastodonTestServer 构造 Mastodon mock 服务器。
func newMastodonTestServer(t *testing.T, opts mastodonTestOptions) *mastodonTestServer {
	t.Helper()
	s := &mastodonTestServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		if opts.metadataStatus != 0 {
			http.Error(w, "metadata error", opts.metadataStatus)
			return
		}
		meta := map[string]any{
			"issuer":                           s.srv.URL,
			"authorization_endpoint":           s.srv.URL + "/oauth/authorize",
			"token_endpoint":                   s.srv.URL + "/oauth/token",
			"code_challenge_methods_supported": []string{"S256"},
			"scopes_supported":                 []string{"profile", "read:accounts"},
		}
		if opts.userinfo != nil {
			meta["userinfo_endpoint"] = s.srv.URL + "/oauth/userinfo"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if opts.tokenCheck != nil {
			if err := opts.tokenCheck(r); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if opts.tokenStatus != 0 {
			http.Error(w, "token endpoint error", opts.tokenStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mastodon-access-token",
			"token_type":   "Bearer",
			"scope":        "profile read:accounts",
			"created_at":   0,
		})
	})
	if opts.userinfo != nil {
		mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
			s.userinfoCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(opts.userinfo)
		})
	}
	mux.HandleFunc("/api/v1/accounts/verify_credentials", func(w http.ResponseWriter, r *http.Request) {
		s.verifyCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(opts.verifyCred)
	})

	s.srv = httptest.NewServer(mux)
	return s
}

// close 关闭 mock 服务器。
func (s *mastodonTestServer) close() {
	s.srv.Close()
}

// newMastodonProviderForTest 用 mock 服务器构造 mastodon 适配器。
func newMastodonProviderForTest(s *mastodonTestServer) (Provider, error) {
	return New(Config{
		ProviderKey:  "mastodon",
		Kind:         "oauth",
		ClientID:     "mastodon-client",
		ClientSecret: "mastodon-secret",
		InstanceURL:  s.srv.URL,
	})
}

// TestMastodonExchangeUserInfoActorSubject 验证 4.4+ userinfo 返回的
// ActivityPub actor URI 原样作为 subject，且 Identity 不含邮箱。
func TestMastodonExchangeUserInfoActorSubject(t *testing.T) {
	actorURI := "https://mastodon.example/users/alice"
	var gotClientID, gotSecret, gotRedirect, gotCode, gotVerifier string
	s := newMastodonTestServer(t, mastodonTestOptions{
		userinfo: map[string]any{"sub": actorURI},
		tokenCheck: func(r *http.Request) error {
			gotClientID = r.PostForm.Get("client_id")
			gotSecret = r.PostForm.Get("client_secret")
			gotRedirect = r.PostForm.Get("redirect_uri")
			gotCode = r.PostForm.Get("code")
			gotVerifier = r.PostForm.Get("code_verifier")
			return nil
		},
	})
	defer s.close()
	provider, err := newMastodonProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != actorURI {
		t.Fatalf("subject = %q, want %q", identity.Subject, actorURI)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty (bind-only)", identity.VerifiedEmail)
	}
	if s.verifyCalls != 0 {
		t.Fatalf("verify_credentials must not be called when userinfo is available, got %d calls", s.verifyCalls)
	}
	if gotClientID != "mastodon-client" {
		t.Fatalf("client_id = %q, want mastodon-client", gotClientID)
	}
	if gotSecret != "mastodon-secret" {
		t.Fatalf("client_secret = %q, want mastodon-secret", gotSecret)
	}
	if gotRedirect != "https://example.com/cb" {
		t.Fatalf("redirect_uri = %q, want https://example.com/cb", gotRedirect)
	}
	if gotCode != "code-1" {
		t.Fatalf("code = %q, want code-1", gotCode)
	}
	if gotVerifier != "verifier-1" {
		t.Fatalf("code_verifier = %q, want verifier-1", gotVerifier)
	}
}

// TestMastodonExchangeVerifyCredentialsFallback 验证 4.3（无 userinfo_endpoint）
// 时用 verify_credentials 的 Account ID 做实例作用域化 subject，且不含邮箱。
func TestMastodonExchangeVerifyCredentialsFallback(t *testing.T) {
	s := newMastodonTestServer(t, mastodonTestOptions{
		verifyCred: map[string]any{
			"id":  "123",
			"url": "https://mastodon.example/@alice",
		},
	})
	defer s.close()
	provider, err := newMastodonProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != ScopedSubject(s.srv.URL, "123") {
		t.Fatalf("subject = %q, want %q", identity.Subject, ScopedSubject(s.srv.URL, "123"))
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty (bind-only)", identity.VerifiedEmail)
	}
	if s.userinfoCalls != 0 {
		t.Fatalf("userinfo must not be called without a userinfo endpoint, got %d calls", s.userinfoCalls)
	}
	if s.verifyCalls != 1 {
		t.Fatalf("verify_credentials calls = %d, want 1", s.verifyCalls)
	}
}

// TestMastodonDiscoveryFailureFailsClosed 验证 metadata 端点不可用（404，实例低于
// 4.3）时硬失败：构建授权 URL 与交换均失败，绝不回退到硬编码端点。
func TestMastodonDiscoveryFailureFailsClosed(t *testing.T) {
	s := newMastodonTestServer(t, mastodonTestOptions{metadataStatus: http.StatusNotFound})
	defer s.close()
	provider, err := newMastodonProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	}); err == nil {
		t.Fatal("BuildAuthURL must fail when metadata is unavailable (4.3 floor)")
	}
	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("metadata failure err = %v, want ErrIdentity", err)
	}
	if s.userinfoCalls != 0 || s.verifyCalls != 0 {
		t.Fatalf("no actor resolution may run without metadata, userinfo=%d verify=%d", s.userinfoCalls, s.verifyCalls)
	}
}

// TestMastodonExchangeTokenErrorFailsClosed 验证 token 端点失败映射为 ErrIdentity。
func TestMastodonExchangeTokenErrorFailsClosed(t *testing.T) {
	s := newMastodonTestServer(t, mastodonTestOptions{
		userinfo:    map[string]any{"sub": "https://mastodon.example/users/alice"},
		tokenStatus: http.StatusBadRequest,
	})
	defer s.close()
	provider, err := newMastodonProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "secret-code", Verifier: "secret-verifier", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("token failure err = %v, want ErrIdentity", err)
	}
	msg := err.Error()
	for _, leak := range []string{"secret-code", "secret-verifier", "mastodon-secret", "mastodon-access-token"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q leaks %q", msg, leak)
		}
	}
}

// TestMastodonBuildAuthURLPKCEOnly 验证授权 URL 携带 S256 challenge（有 verifier 时）
// 且从不携带 nonce（Mastodon 无 ID token）。
func TestMastodonBuildAuthURLPKCEOnly(t *testing.T) {
	s := newMastodonTestServer(t, mastodonTestOptions{userinfo: map[string]any{"sub": "https://mastodon.example/users/alice"}})
	defer s.close()
	provider, err := newMastodonProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	authURL, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if got := parsed.Query().Get("code_challenge"); got == "" {
		t.Fatal("auth url must include code_challenge")
	}
	if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
	if _, ok := parsed.Query()["nonce"]; ok {
		t.Fatal("mastodon auth url must never include nonce")
	}
}

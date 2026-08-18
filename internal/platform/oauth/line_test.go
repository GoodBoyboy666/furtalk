package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// lineTestOptions 配置 LINE token/verify mock 服务器的行为。
type lineTestOptions struct {
	channelID string
	// verifyStatus 覆盖 verify 端点状态码（默认 200）。
	verifyStatus int
	// verifyClaims 是 verify 端点返回的 claims JSON；nil 时使用默认 claims。
	verifyClaims map[string]any
	// expectNonce 断言 verify 请求携带该 nonce；空不检查。
	expectNonce string
	// tokenStatus 覆盖 token 端点状态码（默认 200）。
	tokenStatus int
	// requireVerifier 断言 token 请求携带 code_verifier。
	requireVerifier bool
}

// lineTestServer 是 LINE token/verify 的 mock 服务器。
type lineTestServer struct {
	srv            *httptest.Server
	opts           lineTestOptions
	tokenCalls     int
	verifyCalls    int
	lastVerifyForm url.Values
}

// newLINETestServer 构造 LINE token/verify mock 服务器。
func newLINETestServer(t *testing.T, opts lineTestOptions) *lineTestServer {
	t.Helper()
	if opts.channelID == "" {
		opts.channelID = "line-channel"
	}
	s := &lineTestServer{opts: opts}
	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		s.tokenCalls++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		// 机密客户端：channel ID/secret 必须在 body（AuthStyleInParams）。
		if r.PostForm.Get("client_id") != s.opts.channelID || r.PostForm.Get("client_secret") == "" {
			http.Error(w, "bad client auth", http.StatusBadRequest)
			return
		}
		if s.opts.requireVerifier && r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		if s.opts.tokenStatus != 0 {
			http.Error(w, "token error", s.opts.tokenStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "line-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     "line-id-token",
		})
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		s.verifyCalls++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		s.lastVerifyForm = r.PostForm
		if r.PostForm.Get("id_token") == "" || r.PostForm.Get("client_id") != s.opts.channelID {
			http.Error(w, "bad verify request", http.StatusBadRequest)
			return
		}
		if s.opts.expectNonce != "" && r.PostForm.Get("nonce") != s.opts.expectNonce {
			http.Error(w, "nonce mismatch", http.StatusBadRequest)
			return
		}
		if s.opts.verifyStatus != 0 {
			http.Error(w, "verify error", s.opts.verifyStatus)
			return
		}
		claims := map[string]any{
			"iss":   lineIssuer,
			"sub":   "line-subject-1",
			"aud":   s.opts.channelID,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Add(-time.Minute).Unix(),
			"nonce": r.PostForm.Get("nonce"),
		}
		for k, v := range s.opts.verifyClaims {
			claims[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	})

	s.srv = httptest.NewServer(mux)
	return s
}

// lineProviderFor 用 mock 服务器构造 LINE provider。
func lineProviderFor(t *testing.T, s *lineTestServer) Provider {
	t.Helper()
	provider, err := New(Config{
		ProviderKey:  "line",
		Kind:         "oidc",
		ClientID:     s.opts.channelID,
		ClientSecret: "channel-secret",
		AuthURL:      s.srv.URL + "/authorize",
		TokenURL:     s.srv.URL + "/token",
		APIURL:       s.srv.URL + "/verify",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return provider
}

// TestLINECExchangeSuccess 验证合法 LINE claims 返回作用域化 subject，
// VerifiedEmail 恒为空，并且 verify 请求携带预期 nonce 与 channel ID。
func TestLINECExchangeSuccess(t *testing.T) {
	s := newLINETestServer(t, lineTestOptions{
		channelID: "line-channel", expectNonce: "nonce-1", requireVerifier: true,
	})
	defer s.srv.Close()
	provider := lineProviderFor(t, s)

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != ScopedSubject(lineIssuer, "line-subject-1") {
		t.Fatalf("subject = %q, want scoped subject", identity.Subject)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty (line is bind-only)", identity.VerifiedEmail)
	}
	if s.lastVerifyForm.Get("nonce") != "nonce-1" {
		t.Fatalf("verify nonce = %q, want nonce-1", s.lastVerifyForm.Get("nonce"))
	}
	if s.lastVerifyForm.Get("client_id") != "line-channel" {
		t.Fatalf("verify client_id = %q, want line-channel", s.lastVerifyForm.Get("client_id"))
	}
}

// TestLINECVerifyNon200 验证 verify 端点非 200 时拒绝。
func TestLINECVerifyNon200(t *testing.T) {
	s := newLINETestServer(t, lineTestOptions{
		channelID: "line-channel", verifyStatus: http.StatusInternalServerError,
	})
	defer s.srv.Close()
	provider := lineProviderFor(t, s)

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("verify non-200 err = %v, want ErrIdentity", err)
	}
}

// TestLINECVerifyMissingSubject 验证 verify 返回缺失 sub 时拒绝。
func TestLINECVerifyMissingSubject(t *testing.T) {
	s := newLINETestServer(t, lineTestOptions{
		channelID: "line-channel", verifyClaims: map[string]any{"sub": ""},
	})
	defer s.srv.Close()
	provider := lineProviderFor(t, s)

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("missing subject err = %v, want ErrIdentity", err)
	}
}

// TestLINECVerifyWrongIssuer 验证 verify 返回错误 iss 时拒绝。
func TestLINECVerifyWrongIssuer(t *testing.T) {
	s := newLINETestServer(t, lineTestOptions{
		channelID: "line-channel", verifyClaims: map[string]any{"iss": "https://evil.example.com"},
	})
	defer s.srv.Close()
	provider := lineProviderFor(t, s)

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("wrong issuer err = %v, want ErrIdentity", err)
	}
}

// TestLINECExchangeMissingNonce 验证请求 nonce 缺失时直接拒绝且零网络请求。
func TestLINECExchangeMissingNonce(t *testing.T) {
	s := newLINETestServer(t, lineTestOptions{channelID: "line-channel"})
	defer s.srv.Close()
	provider := lineProviderFor(t, s)

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("missing nonce err = %v, want ErrIdentity", err)
	}
	if s.tokenCalls != 0 || s.verifyCalls != 0 {
		t.Fatalf("missing nonce must not trigger network calls, token=%d verify=%d", s.tokenCalls, s.verifyCalls)
	}
}

// TestLINECEmailIgnored 验证 verify 返回 email 时也被忽略（bind-only）。
func TestLINECEmailIgnored(t *testing.T) {
	s := newLINETestServer(t, lineTestOptions{
		channelID: "line-channel",
		verifyClaims: map[string]any{
			"email": "user@example.com",
		},
	})
	defer s.srv.Close()
	provider := lineProviderFor(t, s)

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty even when line returns email", identity.VerifiedEmail)
	}
	if identity.Subject == "" {
		t.Fatal("subject must be present")
	}
}

// TestLINECExchangeErrorRedaction 验证 token 失败统一映射为 ErrIdentity，
// 错误文本不包含 code/verifier/nonce/channel secret。
func TestLINECExchangeErrorRedaction(t *testing.T) {
	s := newLINETestServer(t, lineTestOptions{
		channelID: "line-channel", tokenStatus: http.StatusBadRequest,
	})
	defer s.srv.Close()
	provider := lineProviderFor(t, s)

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "secret-code", Verifier: "secret-verifier", Nonce: "secret-nonce", RedirectURI: "https://example.com/cb",
	})
	if err == nil {
		t.Fatal("exchange must fail")
	}
	msg := err.Error()
	for _, leak := range []string{"secret-code", "secret-verifier", "secret-nonce", "channel-secret", "line-access-token"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q leaks %q", msg, leak)
		}
	}
	if !strings.Contains(msg, ErrIdentity.Error()) {
		t.Fatalf("error %q must wrap ErrIdentity", msg)
	}
}

// TestLINECBuildAuthURLParams 验证授权 URL 携带 S256 challenge 与 nonce，
// 无 verifier/nonce 时省略对应参数。
func TestLINECBuildAuthURLParams(t *testing.T) {
	s := newLINETestServer(t, lineTestOptions{channelID: "line-channel"})
	defer s.srv.Close()
	provider := lineProviderFor(t, s)

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
	q := parsed.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("auth url must include s256 code_challenge: %s", authURL)
	}
	if q.Get("nonce") != "nonce-1" {
		t.Fatalf("nonce param = %q, want nonce-1", q.Get("nonce"))
	}

	noPKCE, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL without pkce: %v", err)
	}
	parsed, _ = url.Parse(noPKCE)
	if _, ok := parsed.Query()["code_challenge"]; ok {
		t.Fatal("code_challenge must be omitted without a verifier")
	}
	if _, ok := parsed.Query()["nonce"]; ok {
		t.Fatal("nonce must be omitted without a nonce")
	}
}

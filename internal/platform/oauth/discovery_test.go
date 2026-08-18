package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// discoveryTestServer 是 GitLab/Gitea discovery/token/userinfo/JWKS 的 mock 服务器。
// discoveredIssuer 可与实例地址不同，用于验证适配器信任 discovery 文档返回的 issuer。
type discoveryTestServer struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	clientID  string
	kid       string
	issuer    string // discovery 文档返回的 issuer
	userinfo  map[string]any
	userCalls int
}

// discoveryTestOptions 配置 mock discovery 服务器的行为。
type discoveryTestOptions struct {
	clientID string
	// discoveredIssuer 覆盖 discovery 文档中的 issuer；默认与实例地址相同。
	discoveredIssuer string
	// idTokenClaims 覆盖默认 ID token claims（默认含 iss/aud/sub/exp/iat）。
	idTokenClaims map[string]any
	// signKey 覆盖签名 ID token 的密钥；默认使用服务器自身密钥。
	signKey *rsa.PrivateKey
	// userinfo 是 userinfo 端点返回的 JSON；nil 时端点返回 404。
	userinfo map[string]any
	// tokenStatus 覆盖 token 端点状态码（默认 200）。
	tokenStatus int
	// discoveryStatus 覆盖 discovery 端点状态码（默认 200）。
	discoveryStatus int
	// tokenCheck 校验 token 请求（如 client_secret/code_verifier 参数）；返回错误时拒绝。
	tokenCheck func(r *http.Request) error
}

// newDiscoveryTestServer 构造 discovery/token/userinfo/JWKS mock 服务器。
func newDiscoveryTestServer(t *testing.T, opts discoveryTestOptions) *discoveryTestServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	clientID := opts.clientID
	if clientID == "" {
		clientID = "test-client"
	}
	s := &discoveryTestServer{key: key, clientID: clientID, kid: "test-kid", userinfo: opts.userinfo}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if opts.discoveryStatus != 0 {
			http.Error(w, "discovery error", opts.discoveryStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 s.issuer,
			"authorization_endpoint": s.srv.URL + "/authorize",
			"token_endpoint":         s.srv.URL + "/token",
			"userinfo_endpoint":      s.srv.URL + "/userinfo",
			"jwks_uri":               s.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rsaJWKS(key, s.kid))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
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
		claims := oidcDefaultClaims(s.issuer, clientID)
		for k, v := range opts.idTokenClaims {
			claims[k] = v
		}
		signKey := opts.signKey
		if signKey == nil {
			signKey = key
		}
		idToken := signIDToken(t, signKey, s.kid, claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		s.userCalls++
		if s.userinfo == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.userinfo)
	})

	s.srv = httptest.NewServer(mux)
	if opts.discoveredIssuer != "" {
		s.issuer = opts.discoveredIssuer
	} else {
		s.issuer = s.srv.URL
	}
	return s
}

// close 关闭 mock 服务器。
func (s *discoveryTestServer) close() {
	s.srv.Close()
}

// newDiscoveryProviderForTest 用 mock 服务器构造 gitlab discovery 适配器。
func newDiscoveryProviderForTest(s *discoveryTestServer, providerKey string) (Provider, error) {
	return New(Config{
		ProviderKey:  providerKey,
		Kind:         "oidc",
		ClientID:     s.clientID,
		ClientSecret: "secret",
		InstanceURL:  s.srv.URL,
	})
}

// TestDiscoveryExchangeVerifiedEmailFromIDToken 验证 ID token 携带已验证邮箱时
// 直接返回 Identity，subject 为 (discovered issuer, sub) 的作用域化编码，
// 且不触发 userinfo 请求。
func TestDiscoveryExchangeVerifiedEmailFromIDToken(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		idTokenClaims: map[string]any{
			"nonce":          "nonce-1",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != ScopedSubject(s.issuer, "subject-1") {
		t.Fatalf("subject = %q, want %q", identity.Subject, ScopedSubject(s.issuer, "subject-1"))
	}
	if identity.VerifiedEmail != "user@example.com" {
		t.Fatalf("verified email = %q, want user@example.com", identity.VerifiedEmail)
	}
	if s.userCalls != 0 {
		t.Fatalf("userinfo must not be called when the id token has a verified email, got %d calls", s.userCalls)
	}
}

// TestDiscoveryExchangeUserInfoEmailFallback 验证 ID token 缺少已验证邮箱时，
// 用 UserInfo（sub 一致且 email_verified=true）回退得到可信邮箱。
func TestDiscoveryExchangeUserInfoEmailFallback(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo: map[string]any{
			"sub":            "subject-1",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitea")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != ScopedSubject(s.issuer, "subject-1") {
		t.Fatalf("subject = %q, want %q", identity.Subject, ScopedSubject(s.issuer, "subject-1"))
	}
	if identity.VerifiedEmail != "user@example.com" {
		t.Fatalf("verified email = %q, want user@example.com", identity.VerifiedEmail)
	}
	if s.userCalls != 1 {
		t.Fatalf("userinfo calls = %d, want 1", s.userCalls)
	}
}

// TestDiscoveryExchangeUserInfoSubjectMismatch 验证 UserInfo 的 sub 与 ID token
// 不一致时拒绝。
func TestDiscoveryExchangeUserInfoSubjectMismatch(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo: map[string]any{
			"sub":            "different-subject",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("subject mismatch err = %v, want ErrIdentity", err)
	}
}

// TestDiscoveryExchangeUnverifiedEmailKeepsSubject 验证 UserInfo 邮箱未验证时
// 保留 subject 并返回空的 VerifiedEmail，而不是拒绝。
func TestDiscoveryExchangeUnverifiedEmailKeepsSubject(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo: map[string]any{
			"sub":            "subject-1",
			"email":          "user@example.com",
			"email_verified": false,
		},
	})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != ScopedSubject(s.issuer, "subject-1") {
		t.Fatalf("subject = %q, want %q", identity.Subject, ScopedSubject(s.issuer, "subject-1"))
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
}

// TestDiscoveryExchangeMissingEmailKeepsSubject 验证 UserInfo 缺失邮箱时保留
// subject 并返回空的 VerifiedEmail（缺失邮箱不否定 subject）。
func TestDiscoveryExchangeMissingEmailKeepsSubject(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo:      map[string]any{"sub": "subject-1"},
	})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != ScopedSubject(s.issuer, "subject-1") {
		t.Fatalf("subject = %q, want %q", identity.Subject, ScopedSubject(s.issuer, "subject-1"))
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
}

// TestDiscoveryExchangeNonceMismatch 验证 nonce 与 ID token 不一致时返回 ErrIdentity。
func TestDiscoveryExchangeNonceMismatch(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		idTokenClaims: map[string]any{
			"nonce":          "wrong-nonce",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "expected-nonce", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("nonce mismatch err = %v, want ErrIdentity", err)
	}
}

// TestDiscoveryExchangeTrustsDiscoveredIssuer 验证适配器信任 discovery 文档返回的
// issuer：实例地址与 discovered issuer 不同时，以 discovered issuer 签名且含 nonce
// 的 ID token 仍通过校验，subject 使用 discovered issuer 作用域化。
func TestDiscoveryExchangeTrustsDiscoveredIssuer(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		discoveredIssuer: "https://git.example/gitlab",
		idTokenClaims: map[string]any{
			"nonce":          "nonce-1",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	if s.issuer == s.srv.URL {
		t.Fatal("test setup: discovered issuer must differ from the instance url")
	}
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != ScopedSubject(s.issuer, "subject-1") {
		t.Fatalf("subject = %q, want %q", identity.Subject, ScopedSubject(s.issuer, "subject-1"))
	}
}

// TestDiscoveryExchangeIssuerMismatchRejected 验证与 discovered issuer 不一致的
// ID token 被拒绝（签名、issuer、audience 校验不因发现逻辑而放松）。
func TestDiscoveryExchangeIssuerMismatchRejected(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		idTokenClaims: map[string]any{
			"iss":            "https://evil.example.com",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("issuer mismatch err = %v, want ErrIdentity", err)
	}
}

// TestDiscoveryReconfigurationCollisionProtection 验证实例重配置碰撞保护：
// 同一固定 key 下，相同数字 sub 在不同 discovered issuer 产生不同 subject。
func TestDiscoveryReconfigurationCollisionProtection(t *testing.T) {
	issuerA := newDiscoveryTestServer(t, discoveryTestOptions{
		discoveredIssuer: "https://old.example",
		idTokenClaims: map[string]any{
			"sub": "123", "nonce": "nonce-1",
			"email": "a@example.com", "email_verified": true,
		},
	})
	defer issuerA.close()
	issuerB := newDiscoveryTestServer(t, discoveryTestOptions{
		discoveredIssuer: "https://new.example",
		idTokenClaims: map[string]any{
			"sub": "123", "nonce": "nonce-1",
			"email": "a@example.com", "email_verified": true,
		},
	})
	defer issuerB.close()

	providerA, err := newDiscoveryProviderForTest(issuerA, "gitlab")
	if err != nil {
		t.Fatalf("New A: %v", err)
	}
	providerB, err := newDiscoveryProviderForTest(issuerB, "gitlab")
	if err != nil {
		t.Fatalf("New B: %v", err)
	}
	req := ExchangeRequest{Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb"}
	identityA, err := providerA.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange A: %v", err)
	}
	identityB, err := providerB.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange B: %v", err)
	}
	if identityA.Subject == identityB.Subject {
		t.Fatalf("subjects must differ across issuers, both %q", identityA.Subject)
	}
	if identityA.Subject != ScopedSubject(issuerA.issuer, "123") {
		t.Fatalf("subject A = %q, want %q", identityA.Subject, ScopedSubject(issuerA.issuer, "123"))
	}
	if identityB.Subject != ScopedSubject(issuerB.issuer, "123") {
		t.Fatalf("subject B = %q, want %q", identityB.Subject, ScopedSubject(issuerB.issuer, "123"))
	}
}

// TestDiscoveryExchangeTokenRequestParams 验证 token 请求为 form-urlencoded 机密
// 客户端：client_id/client_secret/redirect_uri/code/code_verifier 全部放入请求体。
func TestDiscoveryExchangeTokenRequestParams(t *testing.T) {
	var gotClientID, gotSecret, gotRedirect, gotCode, gotVerifier string
	s := newDiscoveryTestServer(t, discoveryTestOptions{
		idTokenClaims: map[string]any{
			"nonce":          "nonce-1",
			"email":          "user@example.com",
			"email_verified": true,
		},
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
	provider, err := newDiscoveryProviderForTest(s, "gitea")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if gotClientID != s.clientID {
		t.Fatalf("client_id = %q, want %q", gotClientID, s.clientID)
	}
	if gotSecret != "secret" {
		t.Fatalf("client_secret = %q, want secret", gotSecret)
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

// TestDiscoveryBuildAuthURLParams 验证 discovery 授权 URL 携带 S256 challenge 与
// nonce（按请求能力），二者缺省时省略。
func TestDiscoveryBuildAuthURLParams(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
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
	if got := parsed.Query().Get("nonce"); got != "nonce-1" {
		t.Fatalf("nonce = %q, want nonce-1", got)
	}

	noOptions, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL without options: %v", err)
	}
	parsed, _ = url.Parse(noOptions)
	if _, ok := parsed.Query()["code_challenge"]; ok {
		t.Fatal("auth url must omit code_challenge without a verifier")
	}
	if _, ok := parsed.Query()["nonce"]; ok {
		t.Fatal("auth url must omit nonce without a nonce")
	}
}

// TestDiscoveryDiscoveryFailureFailsClosed 验证 discovery 端点不可用（404）时
// 构建授权 URL 与交换均失败关闭，不回退到硬编码端点。
func TestDiscoveryDiscoveryFailureFailsClosed(t *testing.T) {
	s := newDiscoveryTestServer(t, discoveryTestOptions{discoveryStatus: http.StatusNotFound})
	defer s.close()
	provider, err := newDiscoveryProviderForTest(s, "gitlab")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	}); err == nil {
		t.Fatal("BuildAuthURL must fail when discovery is unavailable")
	}
	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("discovery failure err = %v, want ErrIdentity", err)
	}
}

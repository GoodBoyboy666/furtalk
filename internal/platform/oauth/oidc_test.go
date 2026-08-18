package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// oidcTestServer 是 OIDC discovery/token/userinfo/JWKS 的 mock 服务器。
// 每个测试构造独立实例，避免并发读写共享状态。
type oidcTestServer struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	clientID  string
	issuer    string
	kid       string
	userinfo  map[string]any
	userCalls int
}

// oidcTestOptions 配置 mock OIDC 服务器的行为。
type oidcTestOptions struct {
	clientID string
	// idTokenClaims 覆盖默认 ID token claims（默认含 iss/aud/sub/exp/iat）。
	idTokenClaims map[string]any
	// signKey 覆盖签名 ID token 的密钥；默认使用服务器自身密钥。
	signKey *rsa.PrivateKey
	// userinfo 是 userinfo 端点返回的 JSON；nil 时端点返回 404。
	userinfo map[string]any
	// userinfoDelay 延迟 userinfo 响应（超时测试）。
	userinfoDelay time.Duration
	// tokenStatus 覆盖 token 端点状态码（默认 200）。
	tokenStatus int
	// tokenBody 覆盖 token 端点响应体；空时按 ID token claims 生成。
	tokenBody string
	// requireVerifier 断言 token 请求携带 code_verifier。
	requireVerifier bool
}

// newOIDCTestServer 构造 discovery/token/userinfo/JWKS mock 服务器。
func newOIDCTestServer(t *testing.T, opts oidcTestOptions) *oidcTestServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	clientID := opts.clientID
	if clientID == "" {
		clientID = "test-client"
	}
	s := &oidcTestServer{key: key, clientID: clientID, kid: "test-kid", userinfo: opts.userinfo}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                s.issuer,
			"authorization_endpoint":                s.srv.URL + "/authorize",
			"token_endpoint":                        s.srv.URL + "/token",
			"userinfo_endpoint":                     s.srv.URL + "/userinfo",
			"jwks_uri":                              s.srv.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "email", "profile"},
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
		if opts.requireVerifier && r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		if opts.tokenStatus != 0 {
			http.Error(w, "token endpoint error", opts.tokenStatus)
			return
		}
		if opts.tokenBody != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(opts.tokenBody))
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
		if opts.userinfoDelay > 0 {
			time.Sleep(opts.userinfoDelay)
		}
		if s.userinfo == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.userinfo)
	})

	s.srv = httptest.NewServer(mux)
	s.issuer = s.srv.URL
	return s
}

// close 关闭 mock 服务器。
func (s *oidcTestServer) close() {
	s.srv.Close()
}

// rsaJWKS 从 RSA 私钥构造 JWKS JSON。
func rsaJWKS(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	}
}

// oidcDefaultClaims 返回可被测试覆盖的默认 ID token claims。
func oidcDefaultClaims(issuer, clientID string) gojwt.MapClaims {
	now := time.Now().UTC()
	return gojwt.MapClaims{
		"iss": issuer,
		"aud": clientID,
		"sub": "subject-1",
		"iat": now.Add(-time.Minute).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

// signIDToken 用指定密钥与 claims 签发 RS256 ID token。
func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims gojwt.MapClaims) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return signed
}

// TestOIDCBuildAuthURLIncludesNonce 验证 OIDC 授权 URL 在携带 nonce 时包含 nonce 参数，
// 在 nonce 为空时省略。
func TestOIDCBuildAuthURLIncludesNonce(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	withNonce, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL with nonce: %v", err)
	}
	parsed, err := url.Parse(withNonce)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if got := parsed.Query().Get("nonce"); got != "nonce-1" {
		t.Fatalf("nonce param = %q, want nonce-1", got)
	}

	withoutNonce, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL without nonce: %v", err)
	}
	parsed, err = url.Parse(withoutNonce)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if _, ok := parsed.Query()["nonce"]; ok {
		t.Fatalf("nonce param must be omitted: %s", withoutNonce)
	}
}

// TestOIDCBuildAuthURLPKCE 验证 OIDC 授权 URL 仅在携带 verifier 时附加
// S256 code_challenge，verifier 为空时不附加。
func TestOIDCBuildAuthURLPKCE(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	withPKCE, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL with pkce: %v", err)
	}
	parsed, _ := url.Parse(withPKCE)
	if got := parsed.Query().Get("code_challenge"); got == "" {
		t.Fatal("code_challenge must be present with a verifier")
	}
	if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}

	withoutPKCE, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL without pkce: %v", err)
	}
	parsed, _ = url.Parse(withoutPKCE)
	if _, ok := parsed.Query()["code_challenge"]; ok {
		t.Fatal("code_challenge must be omitted without a verifier")
	}
}

// TestOIDCExchangeVerifiedEmail 验证 ID token 携带已验证邮箱时直接返回
// Identity，且不触发 userinfo 请求（Google/自定义 OIDC 兼容路径）。
func TestOIDCExchangeVerifiedEmail(t *testing.T) {
	emailVerified := true
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{
			"nonce":          "nonce-1",
			"email":          "user@example.com",
			"email_verified": emailVerified,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "google", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "subject-1" {
		t.Fatalf("subject = %q, want subject-1", identity.Subject)
	}
	if identity.VerifiedEmail != "user@example.com" {
		t.Fatalf("verified email = %q, want user@example.com", identity.VerifiedEmail)
	}
	if s.userCalls != 0 {
		t.Fatalf("userinfo must not be called when the id token has a verified email, got %d calls", s.userCalls)
	}
}

// TestOIDCExchangeNonceMismatch 验证 nonce 与 ID token 不一致时返回 ErrIdentity。
func TestOIDCExchangeNonceMismatch(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{
			"nonce":          "wrong-nonce",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
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

// TestOIDCExchangeNonceRequiredWhenSent 验证流程发送 nonce 后 ID token 缺失 nonce 也拒绝。
func TestOIDCExchangeNonceRequiredWhenSent(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "expected-nonce", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("missing nonce err = %v, want ErrIdentity", err)
	}
}

// TestOIDCExchangeIssuerMismatch 验证错误 issuer 被拒绝。
func TestOIDCExchangeIssuerMismatch(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{
			"iss":            "https://evil.example.com",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("issuer mismatch err = %v, want ErrIdentity", err)
	}
}

// TestOIDCExchangeAudienceMismatch 验证错误 audience 被拒绝。
func TestOIDCExchangeAudienceMismatch(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{
			"aud":            "another-client",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("audience mismatch err = %v, want ErrIdentity", err)
	}
}

// TestOIDCExchangeSignatureMismatch 验证用错误密钥签名的 ID token 被拒绝。
func TestOIDCExchangeSignatureMismatch(t *testing.T) {
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	s := newOIDCTestServer(t, oidcTestOptions{
		signKey: otherKey,
		idTokenClaims: map[string]any{
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("signature mismatch err = %v, want ErrIdentity", err)
	}
}

// TestOIDCExchangeUserInfoVerifiedEmailFallback 验证 ID token 缺少已验证邮箱时，
// 用 UserInfo（sub 一致且 email_verified=true）回退得到可信邮箱。
func TestOIDCExchangeUserInfoVerifiedEmailFallback(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo: map[string]any{
			"sub":            "subject-1",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "subject-1" {
		t.Fatalf("subject = %q, want subject-1", identity.Subject)
	}
	if identity.VerifiedEmail != "user@example.com" {
		t.Fatalf("verified email = %q, want user@example.com", identity.VerifiedEmail)
	}
	if s.userCalls != 1 {
		t.Fatalf("userinfo calls = %d, want 1", s.userCalls)
	}
}

// TestOIDCExchangeUserInfoSubjectMismatch 验证 UserInfo 的 sub 与 ID token 不一致时拒绝。
func TestOIDCExchangeUserInfoSubjectMismatch(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo: map[string]any{
			"sub":            "different-subject",
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
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

// TestOIDCExchangeUserInfoUnverifiedEmailKeepsSubject 验证 UserInfo 邮箱未验证时
// 保留 subject 并返回空的 VerifiedEmail，而不是拒绝。
func TestOIDCExchangeUserInfoUnverifiedEmailKeepsSubject(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo: map[string]any{
			"sub":            "subject-1",
			"email":          "user@example.com",
			"email_verified": false,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "subject-1" {
		t.Fatalf("subject = %q, want subject-1", identity.Subject)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
}

// TestOIDCExchangeMissingUserInfoKeepsSubject 验证 userinfo 返回 200 但没有邮箱时
// 保留 subject 并返回空的 VerifiedEmail（缺失邮箱不否定 subject）。
func TestOIDCExchangeMissingUserInfoKeepsSubject(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo:      map[string]any{"sub": "subject-1"},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "subject-1" {
		t.Fatalf("subject = %q, want subject-1", identity.Subject)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
}

// TestOIDCExchangeUserInfoUnavailableFailsClosed 验证 userinfo 端点不可用（404）
// 时按设计失败关闭，返回 ErrIdentity 而不是空的 VerifiedEmail。
func TestOIDCExchangeUserInfoUnavailableFailsClosed(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo:      nil,
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("userinfo unavailable err = %v, want ErrIdentity", err)
	}
}

// TestOIDCExchangeErrorRedaction 验证 token/userinfo 失败统一映射为 ErrIdentity，
// 错误文本不包含 code/token/client secret。
func TestOIDCExchangeErrorRedaction(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{tokenStatus: http.StatusBadRequest})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "top-secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "secret-code", Verifier: "secret-verifier", RedirectURI: "https://example.com/cb",
	})
	if err == nil {
		t.Fatal("exchange must fail")
	}
	msg := err.Error()
	for _, leak := range []string{"secret-code", "secret-verifier", "top-secret", "test-access-token"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q leaks %q", msg, leak)
		}
	}
	if !strings.Contains(msg, ErrIdentity.Error()) {
		t.Fatalf("error %q must wrap ErrIdentity", msg)
	}
}

// TestOIDCExchangeTimeoutFailsClosed 验证 provider 网络超时（userinfo 延迟）时
// 返回 ErrIdentity 而不是超时细节。
func TestOIDCExchangeTimeoutFailsClosed(t *testing.T) {
	s := newOIDCTestServer(t, oidcTestOptions{
		idTokenClaims: map[string]any{"nonce": "nonce-1"},
		userinfo: map[string]any{
			"sub":            "subject-1",
			"email":          "user@example.com",
			"email_verified": true,
		},
		userinfoDelay: 200 * time.Millisecond,
	})
	defer s.close()
	provider, err := New(Config{
		ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer,
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("timeout err = %v, want ErrIdentity", err)
	}
}

// TestGitHubBuildAuthURLParams 验证 GitHub 授权 URL 携带 S256 challenge 且不带 nonce。
func TestGitHubBuildAuthURLParams(t *testing.T) {
	provider, err := New(Config{
		ProviderKey: "github", Kind: "oauth", ClientID: "id", ClientSecret: "secret",
		AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token",
	})
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
		t.Fatal("github auth url must include code_challenge")
	}
	if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
	if _, ok := parsed.Query()["nonce"]; ok {
		t.Fatal("github auth url must not include nonce")
	}

	noPKCE, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL without pkce: %v", err)
	}
	parsed, _ = url.Parse(noPKCE)
	if _, ok := parsed.Query()["code_challenge"]; ok {
		t.Fatal("github auth url must omit code_challenge without a verifier")
	}
}

// TestOIDCExchangeFormPKCE 验证 exchange 携带 verifier 时 token 请求包含 code_verifier。
func TestOIDCExchangeFormPKCE(t *testing.T) {
	emailVerified := true
	s := newOIDCTestServer(t, oidcTestOptions{
		requireVerifier: true,
		idTokenClaims: map[string]any{
			"nonce":          "nonce-1",
			"email":          "user@example.com",
			"email_verified": emailVerified,
		},
	})
	defer s.close()
	provider, err := New(Config{ProviderKey: "custom", Kind: "oidc", ClientID: s.clientID, ClientSecret: "secret", IssuerURL: s.issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	}); err != nil {
		t.Fatalf("Exchange with verifier: %v", err)
	}
}

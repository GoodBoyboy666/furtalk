package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// appleTestOptions 配置 Apple token/JWKS mock 服务器的行为。
type appleTestOptions struct {
	clientID string
	// idTokenClaims 覆盖默认 ID token claims。
	idTokenClaims map[string]any
	// idTokenOverride 覆盖整个 id_token 值（alg/密钥自定义测试）。
	idTokenOverride string
	// tokenStatus 覆盖 token 端点状态码（默认 200）。
	tokenStatus int
	// jwksStatus 覆盖 JWKS 端点状态码（默认 200）。
	jwksStatus int
}

// appleTestServer 是 Apple token/JWKS 的 mock 服务器。
type appleTestServer struct {
	srv            *httptest.Server
	key            *rsa.PrivateKey
	kid            string
	opts           appleTestOptions
	capturedSecret string
	tokenCalls     int
	jwksCalls      int
}

// newAppleTestServer 构造 Apple token/JWKS mock 服务器。
func newAppleTestServer(t *testing.T, opts appleTestOptions) *appleTestServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	if opts.clientID == "" {
		opts.clientID = "apple-services-id"
	}
	s := &appleTestServer{key: key, kid: "apple-kid", opts: opts}
	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		s.tokenCalls++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("client_id") != s.opts.clientID || r.PostForm.Get("client_secret") == "" {
			http.Error(w, "bad client auth", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("code") == "" || r.PostForm.Get("redirect_uri") == "" ||
			r.PostForm.Get("grant_type") != "authorization_code" {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		// Apple 网页流程未定义 PKCE：token 请求不得携带 code_verifier。
		if r.PostForm.Get("code_verifier") != "" {
			http.Error(w, "unexpected code_verifier", http.StatusBadRequest)
			return
		}
		s.capturedSecret = r.PostForm.Get("client_secret")
		if s.opts.tokenStatus != 0 {
			http.Error(w, "token error", s.opts.tokenStatus)
			return
		}
		idToken := s.opts.idTokenOverride
		if idToken == "" {
			claims := appleDefaultClaims(s.opts.clientID)
			for k, v := range s.opts.idTokenClaims {
				claims[k] = v
			}
			idToken = signIDToken(t, s.key, s.kid, claims)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "apple-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		s.jwksCalls++
		if s.opts.jwksStatus != 0 {
			http.Error(w, "jwks error", s.opts.jwksStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rsaJWKS(s.key, s.kid))
	})

	s.srv = httptest.NewServer(mux)
	return s
}

// appleDefaultClaims 返回 Apple ID token 的默认 claims。
func appleDefaultClaims(clientID string) gojwt.MapClaims {
	now := time.Now().UTC()
	return gojwt.MapClaims{
		"iss":   appleIssuer,
		"aud":   clientID,
		"sub":   "apple-subject-1",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"nonce": "nonce-1",
	}
}

// newP256Key 生成测试用的 P-256 私钥。
func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p256 key: %v", err)
	}
	return key
}

// testP256PEM 把 P-256 私钥编码为 PKCS#8 DER PEM。
func testP256PEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// appleProviderFor 用 mock 服务器与测试私钥构造 Apple provider。
func appleProviderFor(t *testing.T, s *appleTestServer, ecKey *ecdsa.PrivateKey, teamID, keyID string) Provider {
	t.Helper()
	provider, err := New(Config{
		ProviderKey:     "apple",
		Kind:            "oidc",
		ClientID:        s.opts.clientID,
		AppleTeamID:     teamID,
		AppleKeyID:      keyID,
		ApplePrivateKey: testP256PEM(t, ecKey),
		AuthURL:         s.srv.URL + "/authorize",
		TokenURL:        s.srv.URL + "/token",
		APIURL:          s.srv.URL + "/keys",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return provider
}

// TestAppleExchangeVerifiedEmailBool 验证 email_verified 为 bool true 时返回
// 已验证邮箱。
func TestAppleExchangeVerifiedEmailBool(t *testing.T) {
	s := newAppleTestServer(t, appleTestOptions{
		idTokenClaims: map[string]any{
			"email":          "user@example.com",
			"email_verified": true,
		},
	})
	defer s.srv.Close()
	provider := appleProviderFor(t, s, newP256Key(t), "team-1", "key-1")

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != ScopedSubject(appleIssuer, "apple-subject-1") {
		t.Fatalf("subject = %q, want scoped subject", identity.Subject)
	}
	if identity.VerifiedEmail != "user@example.com" {
		t.Fatalf("verified email = %q, want user@example.com", identity.VerifiedEmail)
	}
}

// TestAppleExchangeVerifiedEmailString 验证 email_verified 为字符串 "True"
// （大小写不敏感）时返回已验证邮箱。
func TestAppleExchangeVerifiedEmailString(t *testing.T) {
	s := newAppleTestServer(t, appleTestOptions{
		idTokenClaims: map[string]any{
			"email":          "user@example.com",
			"email_verified": "True",
		},
	})
	defer s.srv.Close()
	provider := appleProviderFor(t, s, newP256Key(t), "team-1", "key-1")

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.VerifiedEmail != "user@example.com" {
		t.Fatalf("verified email = %q, want user@example.com", identity.VerifiedEmail)
	}
}

// TestAppleExchangeEmailVerifiedFalse 验证 email_verified 为 false 时邮箱为空。
func TestAppleExchangeEmailVerifiedFalse(t *testing.T) {
	s := newAppleTestServer(t, appleTestOptions{
		idTokenClaims: map[string]any{
			"email":          "user@example.com",
			"email_verified": false,
		},
	})
	defer s.srv.Close()
	provider := appleProviderFor(t, s, newP256Key(t), "team-1", "key-1")

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
}

// TestAppleExchangeMissingEmail 验证 email 缺失时邮箱为空但 subject 有效。
func TestAppleExchangeMissingEmail(t *testing.T) {
	s := newAppleTestServer(t, appleTestOptions{})
	defer s.srv.Close()
	provider := appleProviderFor(t, s, newP256Key(t), "team-1", "key-1")

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
	if identity.Subject == "" {
		t.Fatal("subject must be present even without an email")
	}
}

// TestAppleExchangeNonceMismatch 验证 nonce 与 ID token 不一致时拒绝。
func TestAppleExchangeNonceMismatch(t *testing.T) {
	s := newAppleTestServer(t, appleTestOptions{
		idTokenClaims: map[string]any{"nonce": "wrong-nonce"},
	})
	defer s.srv.Close()
	provider := appleProviderFor(t, s, newP256Key(t), "team-1", "key-1")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Nonce: "expected-nonce", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("nonce mismatch err = %v, want ErrIdentity", err)
	}
}

// TestAppleExchangeWrongIssuer 验证错误 issuer 被拒绝。
func TestAppleExchangeWrongIssuer(t *testing.T) {
	s := newAppleTestServer(t, appleTestOptions{
		idTokenClaims: map[string]any{"iss": "https://evil.example.com"},
	})
	defer s.srv.Close()
	provider := appleProviderFor(t, s, newP256Key(t), "team-1", "key-1")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("wrong issuer err = %v, want ErrIdentity", err)
	}
}

// TestAppleExchangeRejectsNonRS256 验证非 RS256（ES256）签名的 ID token 被拒绝。
func TestAppleExchangeRejectsNonRS256(t *testing.T) {
	ecKey := newP256Key(t)
	claims := appleDefaultClaims("apple-services-id")
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, claims)
	signed, err := tok.SignedString(ecKey)
	if err != nil {
		t.Fatalf("sign es256 token: %v", err)
	}
	s := newAppleTestServer(t, appleTestOptions{idTokenOverride: signed})
	defer s.srv.Close()
	provider := appleProviderFor(t, s, ecKey, "team-1", "key-1")

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("non-rs256 err = %v, want ErrIdentity", err)
	}
}

// TestAppleClientSecretJWT 验证 token 请求的 client_secret 是 ES256 JWT：
// header alg=ES256、kid=key_id，claims iss=team_id、sub=client_id、
// aud=appleid.apple.com，且 exp-iat 不超过 TTL。
func TestAppleClientSecretJWT(t *testing.T) {
	s := newAppleTestServer(t, appleTestOptions{})
	defer s.srv.Close()
	ecKey := newP256Key(t)
	provider := appleProviderFor(t, s, ecKey, "team-1", "key-1")

	if _, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if s.capturedSecret == "" {
		t.Fatal("token request must carry a client_secret")
	}
	parsed, err := gojwt.ParseWithClaims(s.capturedSecret, &gojwt.MapClaims{}, func(token *gojwt.Token) (any, error) {
		if token.Method != gojwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected signing method %v", token.Method.Alg())
		}
		return &ecKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse client secret jwt: %v", err)
	}
	if parsed.Header["alg"] != "ES256" {
		t.Fatalf("client secret alg = %v, want ES256", parsed.Header["alg"])
	}
	if parsed.Header["kid"] != "key-1" {
		t.Fatalf("client secret kid = %v, want key-1", parsed.Header["kid"])
	}
	claims := parsed.Claims.(*gojwt.MapClaims)
	if (*claims)["iss"] != "team-1" {
		t.Fatalf("client secret iss = %v, want team-1", (*claims)["iss"])
	}
	if (*claims)["sub"] != "apple-services-id" {
		t.Fatalf("client secret sub = %v, want apple-services-id", (*claims)["sub"])
	}
	if (*claims)["aud"] != "https://appleid.apple.com" {
		t.Fatalf("client secret aud = %v, want appleid.apple.com", (*claims)["aud"])
	}
	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("client secret exp: %v", err)
	}
	iat, err := claims.GetIssuedAt()
	if err != nil {
		t.Fatalf("client secret iat: %v", err)
	}
	diff := exp.Time.Unix() - iat.Time.Unix()
	if diff <= 0 || diff > int64(appleClientSecretTTL.Seconds()) {
		t.Fatalf("client secret lifetime %ds exceeds ttl %ds", diff, int64(appleClientSecretTTL.Seconds()))
	}
}

// TestAppleParsePrivateKeyRejectsNonP256 验证非 P-256 私钥（P-384）被拒绝。
func TestAppleParsePrivateKeyRejectsNonP256(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := parseApplePrivateKey(pemStr); err == nil {
		t.Fatal("non-p-256 private key must be rejected")
	}
}

// TestAppleParsePrivateKeyRejectsInvalidPEM 验证无效 PEM 私钥被拒绝。
func TestAppleParsePrivateKeyRejectsInvalidPEM(t *testing.T) {
	if _, err := parseApplePrivateKey("not-a-pem-key"); err == nil {
		t.Fatal("invalid pem must be rejected")
	}
}

// TestAppleBuildAuthURLParams 验证授权 URL 携带 nonce 与 response_mode=form_post，
// 且不携带 code_challenge。
func TestAppleBuildAuthURLParams(t *testing.T) {
	s := newAppleTestServer(t, appleTestOptions{})
	defer s.srv.Close()
	provider := appleProviderFor(t, s, newP256Key(t), "team-1", "key-1")

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
	if q.Get("response_mode") != "form_post" {
		t.Fatalf("response_mode = %q, want form_post", q.Get("response_mode"))
	}
	if q.Get("nonce") != "nonce-1" {
		t.Fatalf("nonce param = %q, want nonce-1", q.Get("nonce"))
	}
	if _, ok := q["code_challenge"]; ok {
		t.Fatal("apple auth url must not include code_challenge")
	}
}

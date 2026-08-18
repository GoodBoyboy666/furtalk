package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// Microsoft mock 测试使用的固定 GUID。
const (
	testMSTenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testMSObjectID = "11111111-2222-3333-4444-555555555555"
)

// microsoftTestOptions 配置 Microsoft token/JWKS mock 服务器的行为。
type microsoftTestOptions struct {
	clientID string
	tid      string
	oid      string
	nonce    string
	// jwksIssuer 是签名 key 的 issuer 元数据；nil 表示不输出该字段。
	jwksIssuer []string
	// tokenStatus 覆盖 token 端点状态码（默认 200）。
	tokenStatus int
	// jwksStatus 覆盖 JWKS 端点状态码（默认 200）。
	jwksStatus int
	// idTokenClaims 覆盖默认 ID token claims。
	idTokenClaims map[string]any
	// tokenBody 覆盖 token 端点响应体；空时按 ID token claims 生成。
	tokenBody string
	// jwksBody 覆盖 JWKS 端点响应体；空时按服务器密钥生成。
	jwksBody string
	// requireVerifier 断言 token 请求携带 code_verifier。
	requireVerifier bool
}

// microsoftTestServer 是 Microsoft token/JWKS 的 mock 服务器。
type microsoftTestServer struct {
	srv        *httptest.Server
	key        *rsa.PrivateKey
	kid        string
	opts       microsoftTestOptions
	tokenCalls int
	jwksCalls  int
}

// newMicrosoftTestServer 构造 Microsoft token/JWKS mock 服务器。
func newMicrosoftTestServer(t *testing.T, opts microsoftTestOptions) *microsoftTestServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	if opts.clientID == "" {
		opts.clientID = "ms-client"
	}
	if opts.tid == "" {
		opts.tid = testMSTenantID
	}
	if opts.oid == "" {
		opts.oid = testMSObjectID
	}
	s := &microsoftTestServer{key: key, kid: "ms-kid", opts: opts}
	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		s.tokenCalls++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		// 机密客户端：client_id 与 client_secret 必须在 body（AuthStyleInParams）。
		if r.PostForm.Get("client_id") != s.opts.clientID || r.PostForm.Get("client_secret") == "" {
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
		if s.opts.tokenBody != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(s.opts.tokenBody))
			return
		}
		claims := microsoftDefaultClaims(s.opts.clientID, s.opts.tid, s.opts.oid, s.opts.nonce)
		for k, v := range s.opts.idTokenClaims {
			claims[k] = v
		}
		idToken := signIDToken(t, s.key, s.kid, claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ms-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		s.jwksCalls++
		if s.opts.jwksStatus != 0 {
			http.Error(w, "jwks error", s.opts.jwksStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if s.opts.jwksBody != "" {
			_, _ = w.Write([]byte(s.opts.jwksBody))
			return
		}
		_ = json.NewEncoder(w).Encode(microsoftJWKS(s.key, s.kid, s.opts.jwksIssuer))
	})

	s.srv = httptest.NewServer(mux)
	return s
}

// microsoftDefaultClaims 返回 Microsoft ID token 的默认 claims（iss 按 tid 展开）。
func microsoftDefaultClaims(clientID, tid, oid, nonce string) gojwt.MapClaims {
	now := time.Now().UTC()
	return gojwt.MapClaims{
		"iss":   "https://login.microsoftonline.com/" + tid + "/v2.0",
		"aud":   clientID,
		"sub":   "pairwise-subject",
		"exp":   now.Add(time.Hour).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"nonce": nonce,
		"tid":   tid,
		"oid":   oid,
	}
}

// microsoftJWKS 从 RSA 私钥构造带可选 issuer 元数据的 JWKS JSON。
func microsoftJWKS(key *rsa.PrivateKey, kid string, issuer []string) map[string]any {
	entry := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
	if issuer != nil {
		entry["issuer"] = issuer
	}
	return map[string]any{"keys": []any{entry}}
}

// microsoftProviderFor 用 mock 服务器构造 Microsoft provider。
func microsoftProviderFor(t *testing.T, s *microsoftTestServer, secret string) Provider {
	t.Helper()
	provider, err := New(Config{
		ProviderKey:  "microsoft",
		Kind:         "oidc",
		ClientID:     s.opts.clientID,
		ClientSecret: secret,
		AuthURL:      s.srv.URL + "/authorize",
		TokenURL:     s.srv.URL + "/token",
		APIURL:       s.srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return provider
}

// TestMicrosoftExchangeSuccess 验证合法 Microsoft ID token（GUID tid/oid）返回
// tid:oid subject、VerifiedEmail 恒为空，并且 token 请求携带 code_verifier。
func TestMicrosoftExchangeSuccess(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		requireVerifier: true,
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != testMSTenantID+":"+testMSObjectID {
		t.Fatalf("subject = %q, want %s:%s", identity.Subject, testMSTenantID, testMSObjectID)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty (microsoft is bind-only)", identity.VerifiedEmail)
	}
}

// TestMicrosoftExchangeTenantConfusion 验证 token issuer 指向与 tid 不同的租户时
// 按租户混淆拒绝。
func TestMicrosoftExchangeTenantConfusion(t *testing.T) {
	const otherTenant = "ffffffff-1111-2222-3333-444444444444"
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		idTokenClaims: map[string]any{"iss": "https://login.microsoftonline.com/" + otherTenant + "/v2.0"},
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("tenant confusion err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeKeyIssuerConstraintMatch 验证签名 key 带 tenant 模板 issuer
// 元数据且与 token tid 一致时通过。
func TestMicrosoftExchangeKeyIssuerConstraintMatch(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		jwksIssuer: []string{"https://login.microsoftonline.com/{tenantid}/v2.0"},
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != testMSTenantID+":"+testMSObjectID {
		t.Fatalf("subject = %q, want %s:%s", identity.Subject, testMSTenantID, testMSObjectID)
	}
}

// TestMicrosoftExchangeKeyIssuerConstraintViolation 验证签名 key 的 issuer 元数据
// 指向另一租户（与 token iss 不符）时拒绝。
func TestMicrosoftExchangeKeyIssuerConstraintViolation(t *testing.T) {
	const otherTenant = "ffffffff-1111-2222-3333-444444444444"
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		jwksIssuer: []string{"https://login.microsoftonline.com/" + otherTenant + "/v2.0"},
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("key issuer constraint err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeMalformedKeyIssuer 验证签名 key 的 issuer 元数据畸形时拒绝。
func TestMicrosoftExchangeMalformedKeyIssuer(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
	})
	defer s.srv.Close()
	n := base64.RawURLEncoding.EncodeToString(s.key.N.Bytes())
	s.opts.jwksBody = fmt.Sprintf(
		`{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":%q,"n":%q,"e":"AQAB","issuer":"https://evil.example.com"}]}`,
		s.kid, n)
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("malformed key issuer err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeNonceMismatch 验证 nonce 与 ID token 不一致时拒绝。
func TestMicrosoftExchangeNonceMismatch(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "expected-nonce",
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "different-nonce", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("nonce mismatch err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeMissingNonce 验证请求 nonce 缺失时拒绝。
func TestMicrosoftExchangeMissingNonce(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "token-nonce",
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("missing nonce err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeExpiredToken 验证过期 token 被拒绝。
func TestMicrosoftExchangeExpiredToken(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		idTokenClaims: map[string]any{"exp": time.Now().Add(-time.Hour).Unix()},
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("expired token err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeMissingOID 验证 oid 缺失/空时拒绝。
func TestMicrosoftExchangeMissingOID(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		idTokenClaims: map[string]any{"oid": ""},
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("missing oid err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeJWKSFailure 验证 JWKS 端点失败（500）时失败关闭。
func TestMicrosoftExchangeJWKSFailure(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		jwksStatus: http.StatusInternalServerError,
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("jwks failure err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeRejectsNonRS256 验证非 RS256（HS256）签名的 ID token 被拒绝。
func TestMicrosoftExchangeRejectsNonRS256(t *testing.T) {
	claims := microsoftDefaultClaims("ms-client", testMSTenantID, testMSObjectID, "nonce-1")
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("hmac-secret"))
	if err != nil {
		t.Fatalf("sign hs256 token: %v", err)
	}
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		tokenBody: fmt.Sprintf(`{"access_token":"x","token_type":"Bearer","expires_in":3600,"id_token":%q}`, signed),
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", Nonce: "nonce-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("non-rs256 err = %v, want ErrIdentity", err)
	}
}

// TestMicrosoftExchangeErrorRedaction 验证 token 失败统一映射为 ErrIdentity，
// 错误文本不包含 code/verifier/nonce/client secret/access token。
func TestMicrosoftExchangeErrorRedaction(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{
		clientID: "ms-client", tid: testMSTenantID, oid: testMSObjectID, nonce: "nonce-1",
		tokenStatus: http.StatusBadRequest,
	})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "secret-code", Verifier: "secret-verifier", Nonce: "secret-nonce", RedirectURI: "https://example.com/cb",
	})
	if err == nil {
		t.Fatal("exchange must fail")
	}
	msg := err.Error()
	for _, leak := range []string{"secret-code", "secret-verifier", "secret-nonce", "top-secret", "ms-access-token"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q leaks %q", msg, leak)
		}
	}
	if !strings.Contains(msg, ErrIdentity.Error()) {
		t.Fatalf("error %q must wrap ErrIdentity", msg)
	}
}

// TestMicrosoftBuildAuthURLParams 验证授权 URL 携带 S256 challenge 与 nonce，
// 无 verifier/nonce 时省略对应参数。
func TestMicrosoftBuildAuthURLParams(t *testing.T) {
	s := newMicrosoftTestServer(t, microsoftTestOptions{clientID: "ms-client"})
	defer s.srv.Close()
	provider := microsoftProviderFor(t, s, "top-secret")

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

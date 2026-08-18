package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// twitterTestServer 是 Twitter/X OAuth2 的 mock 服务器（authorize/token/userinfo）。
// BuildAuthURL 只在本进程构造 URL，不访问 authorize 端点；/authorize 仅为 fixture 完整性注册。
type twitterTestServer struct {
	srv *httptest.Server
}

// twitterTestOptions 配置 mock Twitter/X 服务器的行为。
type twitterTestOptions struct {
	// tokenCheck 校验 token 请求（如 Basic 认证与 code_verifier）；返回错误时拒绝。
	tokenCheck func(r *http.Request) error
	// tokenStatus 覆盖 token 端点状态码（默认 200）。
	tokenStatus int
	// userinfo 是 /users/me 返回的 JSON 对象（外层含 data 字段）。
	userinfo map[string]any
	// userBody 是 /users/me 返回的原始响应体；非空时优先于 userinfo。
	userBody string
	// userStatus 覆盖 userinfo 端点状态码（默认 200）。
	userStatus int
}

// newTwitterTestServer 构造 Twitter/X mock 服务器。
func newTwitterTestServer(t *testing.T, opts twitterTestOptions) *twitterTestServer {
	t.Helper()
	s := &twitterTestServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"authorize": true})
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "twitter-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		if opts.userStatus != 0 {
			http.Error(w, "userinfo error", opts.userStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if opts.userBody != "" {
			_, _ = w.Write([]byte(opts.userBody))
			return
		}
		body := opts.userinfo
		if body == nil {
			body = map[string]any{"data": map[string]any{}}
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	s.srv = httptest.NewServer(mux)
	return s
}

// close 关闭 mock 服务器。
func (s *twitterTestServer) close() {
	s.srv.Close()
}

// newTwitterProviderForTest 用 mock 服务器构造 twitter 适配器。
func newTwitterProviderForTest(s *twitterTestServer) (Provider, error) {
	return New(Config{
		ProviderKey:  "twitter",
		Kind:         "oauth",
		ClientID:     "twitter-client",
		ClientSecret: "twitter-secret",
		AuthURL:      s.srv.URL + "/authorize",
		TokenURL:     s.srv.URL + "/token",
		APIURL:       s.srv.URL,
	})
}

// basicAuthValue 构造 HTTP Basic 认证头的期望值，
// 与 x/oauth2 AuthStyleInHeader 的编码一致（client_id/secret 各自 QueryEscape）。
func basicAuthValue(clientID, clientSecret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(clientSecret)))
}

// TestTwitterBuildAuthURLParams 验证授权 URL 携带 S256 challenge、固定 scopes 且不带 nonce。
func TestTwitterBuildAuthURLParams(t *testing.T) {
	s := newTwitterTestServer(t, twitterTestOptions{})
	defer s.close()
	provider, err := newTwitterProviderForTest(s)
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
		t.Fatal("twitter auth url must include code_challenge")
	}
	if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
	if got := parsed.Query().Get("scope"); got != "tweet.read users.read users.email" {
		t.Fatalf("scope = %q, want tweet.read users.read users.email", got)
	}
	if got := parsed.Query().Get("state"); got != "state-1" {
		t.Fatalf("state = %q, want state-1", got)
	}
	if got := parsed.Query().Get("redirect_uri"); got != "https://example.com/cb" {
		t.Fatalf("redirect_uri = %q, want https://example.com/cb", got)
	}
	if _, ok := parsed.Query()["nonce"]; ok {
		t.Fatal("twitter auth url must never include nonce")
	}

	noPKCE, err := provider.BuildAuthURL(context.Background(), AuthorizationRequest{
		State: "state-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL without pkce: %v", err)
	}
	parsed, _ = url.Parse(noPKCE)
	if _, ok := parsed.Query()["code_challenge"]; ok {
		t.Fatal("twitter auth url must omit code_challenge without a verifier")
	}
}

// TestTwitterExchangeVerifiedEmail 验证成功交换：token 请求走 HTTP Basic 并携带
// code_verifier，userinfo 返回 id + confirmed_email 时得到完整 Identity。
func TestTwitterExchangeVerifiedEmail(t *testing.T) {
	var gotAuth, gotCode, gotVerifier string
	s := newTwitterTestServer(t, twitterTestOptions{
		userinfo: map[string]any{
			"data": map[string]any{
				"id":              "12345",
				"confirmed_email": "user@example.com",
			},
		},
		tokenCheck: func(r *http.Request) error {
			gotAuth = r.Header.Get("Authorization")
			gotCode = r.PostForm.Get("code")
			gotVerifier = r.PostForm.Get("code_verifier")
			return nil
		},
	})
	defer s.close()
	provider, err := newTwitterProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "12345" {
		t.Fatalf("subject = %q, want 12345", identity.Subject)
	}
	if identity.VerifiedEmail != "user@example.com" {
		t.Fatalf("verified email = %q, want user@example.com", identity.VerifiedEmail)
	}
	if want := basicAuthValue("twitter-client", "twitter-secret"); gotAuth != want {
		t.Fatalf("authorization header = %q, want %q", gotAuth, want)
	}
	if gotCode != "code-1" {
		t.Fatalf("code = %q, want code-1", gotCode)
	}
	if gotVerifier != "verifier-1" {
		t.Fatalf("code_verifier = %q, want verifier-1", gotVerifier)
	}
}

// TestTwitterExchangeMissingEmailKeepsSubject 验证 userinfo 缺失 confirmed_email 时
// 保留 subject 并返回空的 VerifiedEmail。
func TestTwitterExchangeMissingEmailKeepsSubject(t *testing.T) {
	s := newTwitterTestServer(t, twitterTestOptions{
		userinfo: map[string]any{"data": map[string]any{"id": "12345"}},
	})
	defer s.close()
	provider, err := newTwitterProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "12345" {
		t.Fatalf("subject = %q, want 12345", identity.Subject)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
}

// TestTwitterExchangeUserinfoNon200 验证 userinfo 非 200 返回 ErrIdentity。
func TestTwitterExchangeUserinfoNon200(t *testing.T) {
	s := newTwitterTestServer(t, twitterTestOptions{
		userStatus: http.StatusInternalServerError,
	})
	defer s.close()
	provider, err := newTwitterProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("userinfo status err = %v, want ErrIdentity", err)
	}
}

// TestTwitterExchangeMalformedJSON 验证 userinfo 返回非法 JSON 时返回 ErrIdentity。
func TestTwitterExchangeMalformedJSON(t *testing.T) {
	s := newTwitterTestServer(t, twitterTestOptions{
		userBody: "{invalid json",
	})
	defer s.close()
	provider, err := newTwitterProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("malformed userinfo err = %v, want ErrIdentity", err)
	}
}

// TestTwitterExchangeMissingSubject 验证 userinfo 缺失 id 时返回 ErrIdentity。
func TestTwitterExchangeMissingSubject(t *testing.T) {
	s := newTwitterTestServer(t, twitterTestOptions{
		userinfo: map[string]any{"data": map[string]any{}},
	})
	defer s.close()
	provider, err := newTwitterProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("missing subject err = %v, want ErrIdentity", err)
	}
}

// TestTwitterExchangeErrorRedaction 验证 token/userinfo 失败统一映射为 ErrIdentity，
// 错误文本不包含 code/verifier/client secret/access token。
func TestTwitterExchangeErrorRedaction(t *testing.T) {
	s := newTwitterTestServer(t, twitterTestOptions{
		tokenStatus: http.StatusBadRequest,
	})
	defer s.close()
	provider, err := newTwitterProviderForTest(s)
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
	for _, leak := range []string{"secret-code", "secret-verifier", "twitter-secret", "twitter-access-token"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q leaks %q", msg, leak)
		}
	}
	if !strings.Contains(msg, ErrIdentity.Error()) {
		t.Fatalf("error %q must wrap ErrIdentity", msg)
	}
}

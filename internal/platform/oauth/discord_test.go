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

// discordTestServer 是 Discord OAuth2 的 mock 服务器（authorize/token/userinfo）。
// BuildAuthURL 只在本进程构造 URL，不访问 authorize 端点；/authorize 仅为 fixture 完整性注册。
type discordTestServer struct {
	srv *httptest.Server
}

// discordTestOptions 配置 mock Discord 服务器的行为。
type discordTestOptions struct {
	// tokenCheck 校验 token 请求（如 Basic 认证与缺省的 code_verifier）；返回错误时拒绝。
	tokenCheck func(r *http.Request) error
	// tokenStatus 覆盖 token 端点状态码（默认 200）。
	tokenStatus int
	// userinfo 是 /users/@me 返回的 JSON 对象。
	userinfo map[string]any
	// userBody 是 /users/@me 返回的原始响应体；非空时优先于 userinfo。
	userBody string
	// userStatus 覆盖 userinfo 端点状态码（默认 200）。
	userStatus int
}

// newDiscordTestServer 构造 Discord mock 服务器。
func newDiscordTestServer(t *testing.T, opts discordTestOptions) *discordTestServer {
	t.Helper()
	s := &discordTestServer{}
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
			"access_token": "discord-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/@me" {
			http.NotFound(w, r)
			return
		}
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
			body = map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	s.srv = httptest.NewServer(mux)
	return s
}

// close 关闭 mock 服务器。
func (s *discordTestServer) close() {
	s.srv.Close()
}

// newDiscordProviderForTest 用 mock 服务器构造 discord 适配器。
func newDiscordProviderForTest(s *discordTestServer) (Provider, error) {
	return New(Config{
		ProviderKey:  "discord",
		Kind:         "oauth",
		ClientID:     "discord-client",
		ClientSecret: "discord-secret",
		AuthURL:      s.srv.URL + "/authorize",
		TokenURL:     s.srv.URL + "/token",
		APIURL:       s.srv.URL,
	})
}

// TestDiscordBuildAuthURLParams 验证授权 URL 携带固定 scopes 且从不附加
// code_challenge（普通网页登录未定义 PKCE）与 nonce。
func TestDiscordBuildAuthURLParams(t *testing.T) {
	s := newDiscordTestServer(t, discordTestOptions{})
	defer s.close()
	provider, err := newDiscordProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// 即使请求带 verifier 与 nonce，适配器也不得启用任一能力。
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
	if got := parsed.Query().Get("scope"); got != "identify email" {
		t.Fatalf("scope = %q, want identify email", got)
	}
	if got := parsed.Query().Get("state"); got != "state-1" {
		t.Fatalf("state = %q, want state-1", got)
	}
	if got := parsed.Query().Get("redirect_uri"); got != "https://example.com/cb" {
		t.Fatalf("redirect_uri = %q, want https://example.com/cb", got)
	}
	if _, ok := parsed.Query()["code_challenge"]; ok {
		t.Fatal("discord auth url must never include code_challenge")
	}
	if _, ok := parsed.Query()["nonce"]; ok {
		t.Fatal("discord auth url must never include nonce")
	}
}

// TestDiscordExchangeVerifiedEmail 验证成功交换：token 请求走 HTTP Basic 且不带
// code_verifier，userinfo 返回 id + email + verified=true 时得到完整 Identity。
func TestDiscordExchangeVerifiedEmail(t *testing.T) {
	var gotAuth, gotCode, gotVerifier string
	s := newDiscordTestServer(t, discordTestOptions{
		userinfo: map[string]any{
			"id":       "123456",
			"email":    "user@example.com",
			"verified": true,
		},
		tokenCheck: func(r *http.Request) error {
			gotAuth = r.Header.Get("Authorization")
			gotCode = r.PostForm.Get("code")
			gotVerifier = r.PostForm.Get("code_verifier")
			return nil
		},
	})
	defer s.close()
	provider, err := newDiscordProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "123456" {
		t.Fatalf("subject = %q, want 123456", identity.Subject)
	}
	if identity.VerifiedEmail != "user@example.com" {
		t.Fatalf("verified email = %q, want user@example.com", identity.VerifiedEmail)
	}
	if want := basicAuthValue("discord-client", "discord-secret"); gotAuth != want {
		t.Fatalf("authorization header = %q, want %q", gotAuth, want)
	}
	if gotCode != "code-1" {
		t.Fatalf("code = %q, want code-1", gotCode)
	}
	if gotVerifier != "" {
		t.Fatalf("code_verifier = %q, want empty (no PKCE)", gotVerifier)
	}
}

// TestDiscordExchangeUnverifiedEmailKeepsSubject 验证 verified=false 时保留
// subject 并返回空的 VerifiedEmail。
func TestDiscordExchangeUnverifiedEmailKeepsSubject(t *testing.T) {
	s := newDiscordTestServer(t, discordTestOptions{
		userinfo: map[string]any{
			"id":       "123456",
			"email":    "user@example.com",
			"verified": false,
		},
	})
	defer s.close()
	provider, err := newDiscordProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "123456" {
		t.Fatalf("subject = %q, want 123456", identity.Subject)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
}

// TestDiscordExchangeMissingEmailKeepsSubject 验证缺失 email 时保留 subject
// 并返回空的 VerifiedEmail。
func TestDiscordExchangeMissingEmailKeepsSubject(t *testing.T) {
	s := newDiscordTestServer(t, discordTestOptions{
		userinfo: map[string]any{"id": "123456"},
	})
	defer s.close()
	provider, err := newDiscordProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "123456" {
		t.Fatalf("subject = %q, want 123456", identity.Subject)
	}
	if identity.VerifiedEmail != "" {
		t.Fatalf("verified email = %q, want empty", identity.VerifiedEmail)
	}
}

// TestDiscordExchangeUserinfoNon200 验证 userinfo 非 200 返回 ErrIdentity。
func TestDiscordExchangeUserinfoNon200(t *testing.T) {
	s := newDiscordTestServer(t, discordTestOptions{
		userStatus: http.StatusInternalServerError,
	})
	defer s.close()
	provider, err := newDiscordProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("userinfo status err = %v, want ErrIdentity", err)
	}
}

// TestDiscordExchangeMalformedJSON 验证 userinfo 返回非法 JSON 时返回 ErrIdentity。
func TestDiscordExchangeMalformedJSON(t *testing.T) {
	s := newDiscordTestServer(t, discordTestOptions{
		userBody: "{invalid json",
	})
	defer s.close()
	provider, err := newDiscordProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("malformed userinfo err = %v, want ErrIdentity", err)
	}
}

// TestDiscordExchangeMissingSubject 验证 userinfo 缺失 id 时返回 ErrIdentity。
func TestDiscordExchangeMissingSubject(t *testing.T) {
	s := newDiscordTestServer(t, discordTestOptions{
		userinfo: map[string]any{},
	})
	defer s.close()
	provider, err := newDiscordProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("missing subject err = %v, want ErrIdentity", err)
	}
}

// TestDiscordExchangeErrorRedaction 验证 token/userinfo 失败统一映射为 ErrIdentity，
// 错误文本不包含 code/client secret/access token。
func TestDiscordExchangeErrorRedaction(t *testing.T) {
	s := newDiscordTestServer(t, discordTestOptions{
		tokenStatus: http.StatusBadRequest,
	})
	defer s.close()
	provider, err := newDiscordProviderForTest(s)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "secret-code", RedirectURI: "https://example.com/cb",
	})
	if err == nil {
		t.Fatal("exchange must fail")
	}
	msg := err.Error()
	for _, leak := range []string{"secret-code", "discord-secret", "discord-access-token"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q leaks %q", msg, leak)
		}
	}
	if !strings.Contains(msg, ErrIdentity.Error()) {
		t.Fatalf("error %q must wrap ErrIdentity", msg)
	}
}

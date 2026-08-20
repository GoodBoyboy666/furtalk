package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// githubTestServer 是 GitHub token/user/emails 的 mock 服务器。
// 每个测试构造独立实例，避免并发读写共享状态。
type githubTestServer struct {
	srv *httptest.Server
	// accessToken 是 token 端点返回的 access token。
	accessToken string
	// tokenCalls 记录 token 请求次数。
	tokenCalls int
	// requireBearer 断言 /user 与 /user/emails 都携带预期的 Bearer Header。
	requireBearer bool
	// verifiedEmails 是 /user/emails 返回的邮箱列表。
	verifiedEmails []githubEmail
	// userStatus 覆盖 /user 端点状态码（默认 200）。
	userStatus int
	// emailsStatus 覆盖 /user/emails 端点状态码（默认 200）。
	emailsStatus int
}

// githubTestOptions 配置 mock GitHub 服务器的行为。
type githubTestOptions struct {
	accessToken    string
	requireBearer  bool
	verifiedEmails []githubEmail
	userStatus     int
	emailsStatus   int
}

// newGitHubTestServer 构造 token/user/emails mock 服务器。
func newGitHubTestServer(t *testing.T, opts githubTestOptions) *githubTestServer {
	t.Helper()
	accessToken := opts.accessToken
	if accessToken == "" {
		accessToken = "test-access-token"
	}
	s := &githubTestServer{
		accessToken:    accessToken,
		requireBearer:  opts.requireBearer,
		verifiedEmails: opts.verifiedEmails,
		userStatus:     opts.userStatus,
		emailsStatus:   opts.emailsStatus,
	}
	guarded := func(handler func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if opts.requireBearer && r.Header.Get("Authorization") != "Bearer "+accessToken {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			handler(w, r)
		}
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		s.tokenCalls++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("code") == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("redirect_uri") == "" {
			http.Error(w, "missing redirect_uri", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": s.accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/user", guarded(func(w http.ResponseWriter, r *http.Request) {
		if s.userStatus != 0 {
			http.Error(w, "user endpoint error", s.userStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 12345})
	}))

	mux.HandleFunc("/user/emails", guarded(func(w http.ResponseWriter, r *http.Request) {
		if s.emailsStatus != 0 {
			http.Error(w, "emails endpoint error", s.emailsStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.verifiedEmails)
	}))

	s.srv = httptest.NewServer(mux)
	return s
}

// close 关闭 mock 服务器。
func (s *githubTestServer) close() {
	s.srv.Close()
}

// provider 用给定配置构造共享 HTTP client 的 GitHub provider。
func (s *githubTestServer) provider(t *testing.T, client *http.Client) Provider {
	t.Helper()
	provider, err := New(Config{
		ProviderKey:  "github",
		Kind:         "oauth",
		ClientID:     "id",
		ClientSecret: "secret",
		AuthURL:      s.srv.URL + "/authorize",
		TokenURL:     s.srv.URL + "/token",
		APIURL:       s.srv.URL,
		HTTPClient:   client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return provider
}

// githubClient 构造用于 GitHub 请求的共享 HTTP client。
func githubClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = time.Second
	}
	return &http.Client{Timeout: timeout}
}

// TestGitHubExchangeCarriesBearer 验证 /user 与 /user/emails 请求携带
// 交换得到的 Bearer Header，并生成预期 subject 与 verified email。
func TestGitHubExchangeCarriesBearer(t *testing.T) {
	s := newGitHubTestServer(t, githubTestOptions{
		requireBearer: true,
		verifiedEmails: []githubEmail{
			{Email: "primary@example.com", Verified: true, Primary: true},
		},
	})
	defer s.close()
	provider := s.provider(t, githubClient(0))

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Subject != "12345" {
		t.Fatalf("subject = %q, want 12345", identity.Subject)
	}
	if identity.VerifiedEmail != "primary@example.com" {
		t.Fatalf("verified email = %q, want primary@example.com", identity.VerifiedEmail)
	}
	if s.tokenCalls != 1 {
		t.Fatalf("token calls = %d, want 1", s.tokenCalls)
	}
}

// TestGitHubExchangeVerifiedEmailPrecedence 验证已验证 primary 邮箱优先；
// 无 primary 时取首个已验证邮箱。
func TestGitHubExchangeVerifiedEmailPrecedence(t *testing.T) {
	s := newGitHubTestServer(t, githubTestOptions{
		requireBearer: true,
		verifiedEmails: []githubEmail{
			{Email: "first@example.com", Verified: true, Primary: false},
			{Email: "second@example.com", Verified: true, Primary: true},
		},
	})
	defer s.close()
	provider := s.provider(t, githubClient(0))

	identity, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.VerifiedEmail != "second@example.com" {
		t.Fatalf("verified email = %q, want second@example.com", identity.VerifiedEmail)
	}

	fallback := newGitHubTestServer(t, githubTestOptions{
		requireBearer: true,
		verifiedEmails: []githubEmail{
			{Email: "unverified@example.com", Verified: false, Primary: false},
			{Email: "verified@example.com", Verified: true, Primary: false},
		},
	})
	defer fallback.close()
	fallbackProvider := fallback.provider(t, githubClient(0))

	identity, err = fallbackProvider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange fallback: %v", err)
	}
	if identity.VerifiedEmail != "verified@example.com" {
		t.Fatalf("fallback verified email = %q, want verified@example.com", identity.VerifiedEmail)
	}
}

// TestGitHubExchangeTokenFailureFailsClosed 验证 token 请求失败时返回 ErrIdentity，
// 错误不泄露 code、access token 与 client secret。
func TestGitHubExchangeTokenFailureFailsClosed(t *testing.T) {
	s := newGitHubTestServer(t, githubTestOptions{})
	defer s.close()
	provider := s.provider(t, githubClient(0))

	// 无法让原 mock 返回 token 失败，这里用拒绝 Bearer 的独立服务器模拟 token 失败。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad credentials", http.StatusBadRequest)
	}))
	defer srv.Close()
	provider, err := New(Config{
		ProviderKey: "github", Kind: "oauth", ClientID: "id", ClientSecret: "top-secret",
		AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token", APIURL: srv.URL,
		HTTPClient: githubClient(0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "secret-code", Verifier: "secret-verifier", RedirectURI: "https://example.com/cb",
	})
	assertErrIdentityNoLeak(t, err, []string{"secret-code", "secret-verifier", "top-secret", "test-access-token"})
}

// TestGitHubExchangeUserFailureFailsClosed 验证 /user 失败时失败关闭。
func TestGitHubExchangeUserFailureFailsClosed(t *testing.T) {
	s := newGitHubTestServer(t, githubTestOptions{userStatus: http.StatusInternalServerError})
	defer s.close()
	provider := s.provider(t, githubClient(0))

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	assertErrIdentityNoLeak(t, err, []string{"code-1", "verifier-1", "secret", "test-access-token"})
}

// TestGitHubExchangeEmailsFailureFailsClosed 验证 /user/emails 失败时失败关闭。
func TestGitHubExchangeEmailsFailureFailsClosed(t *testing.T) {
	s := newGitHubTestServer(t, githubTestOptions{emailsStatus: http.StatusInternalServerError})
	defer s.close()
	provider := s.provider(t, githubClient(0))

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	assertErrIdentityNoLeak(t, err, []string{"code-1", "verifier-1", "secret", "test-access-token"})
}

// TestGitHubExchangeMissingIdentityFailsClosed 验证没有已验证邮箱时失败关闭。
func TestGitHubExchangeMissingIdentityFailsClosed(t *testing.T) {
	s := newGitHubTestServer(t, githubTestOptions{})
	defer s.close()
	provider := s.provider(t, githubClient(0))

	_, err := provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	assertErrIdentityNoLeak(t, err, []string{"code-1", "verifier-1", "secret", "test-access-token"})
}

// TestGitHubExchangeSharedClientTimeout 验证共享 HTTP client 的有界超时作用于
// GitHub 请求：延迟响应按失败关闭映射为 ErrIdentity。
func TestGitHubExchangeSharedClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "t", "token_type": "Bearer", "expires_in": 3600,
			})
		default:
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	provider, err := New(Config{
		ProviderKey: "github", Kind: "oauth", ClientID: "id", ClientSecret: "secret",
		AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token", APIURL: srv.URL,
		HTTPClient: &http.Client{Timeout: 50 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = provider.Exchange(context.Background(), ExchangeRequest{
		Code: "code-1", Verifier: "verifier-1", RedirectURI: "https://example.com/cb",
	})
	if err == nil || !strings.Contains(err.Error(), ErrIdentity.Error()) {
		t.Fatalf("timeout err = %v, want ErrIdentity", err)
	}
}

// assertErrIdentityNoLeak 断言 err 失败关闭且不泄露任何敏感值。
func assertErrIdentityNoLeak(t *testing.T, err error, leaks []string) {
	t.Helper()
	if err == nil {
		t.Fatal("exchange must fail")
	}
	msg := err.Error()
	for _, leak := range leaks {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q leaks %q", msg, leak)
		}
	}
	if !strings.Contains(msg, ErrIdentity.Error()) {
		t.Fatalf("error %q must wrap ErrIdentity", msg)
	}
}

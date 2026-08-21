package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/oauth"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

// oauthCallbackSigner 签发固定的会话 token。
type oauthCallbackSigner struct{}

func (oauthCallbackSigner) SignFirstParty(int64, int64) (string, error) { return "session-token", nil }
func (oauthCallbackSigner) Lifetime() time.Duration                     { return 7 * 24 * time.Hour }

// oauthCallbackProvider 把 state 回显到授权 URL，并按脚本返回交换结果。
type oauthCallbackProvider struct {
	identity *oauth.Identity
}

func (p *oauthCallbackProvider) Name() string { return "Apple" }

func (p *oauthCallbackProvider) BuildAuthURL(ctx context.Context, req oauth.AuthorizationRequest) (string, error) {
	return "https://auth.example.com/start?state=" + url.QueryEscape(req.State), nil
}

func (p *oauthCallbackProvider) Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.Identity, error) {
	return p.identity, nil
}

// oauthCallbackFactory 按 key 返回脚本化 provider。
type oauthCallbackFactory struct {
	provider identity.OAuthProvider
}

func (f *oauthCallbackFactory) build(cfg identity.OAuthProviderConfig) (identity.OAuthProvider, error) {
	return f.provider, nil
}

// oauthCallbackProviders 是回调测试的 provider 读取器替身。
type oauthCallbackProviders struct {
	provider *identity.AuthProvider
}

func (p oauthCallbackProviders) OAuthProviders(context.Context) ([]identity.AuthProvider, error) {
	return nil, nil
}

func (p oauthCallbackProviders) OAuthProvider(context.Context, string) (*identity.AuthProvider, error) {
	return p.provider, nil
}

// oauthCallbackFixture 是回调 HTTP 测试的装配结果。
type oauthCallbackFixture struct {
	router     *gin.Engine
	svc        *identity.Service
	users      *repository.UserRepo
	identities *repository.ExternalIdentityRepo
}

// newOAuthCallbackRouter 装配带真实 SQLite 仓储、内存缓存、脚本化 OAuth provider
// 与固定 signer 的认证路由；complete 端点不挂 CSRF 中间件（一次性 state 即 CSRF 边界）。
func newOAuthCallbackRouter(t *testing.T, scripted *oauth.Identity) *oauthCallbackFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "handler-oauth-callback-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.ExternalIdentity{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	store := cache.NewMemory(10000)
	factory := &oauthCallbackFactory{provider: &oauthCallbackProvider{identity: scripted}}
	svc := identity.NewService(identity.Dependencies{
		TxRunner:     gormtx.NewRunner(db),
		Users:        repository.NewUserRepo(db),
		Identities:   repository.NewExternalIdentityRepo(db),
		Cache:        store,
		Policy:       authPolicyReader{},
		Signer:       oauthCallbackSigner{},
		Providers:    oauthCallbackProviders{provider: &identity.AuthProvider{ProviderKey: "apple", Kind: domain.ProviderKindOIDC}},
		OAuthFactory: factory.build,
		BaseURL:      "https://example.com",
	})
	translator, err := NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	RegisterAuth(router.Group("/api/v1"), svc)
	return &oauthCallbackFixture{router: router, svc: svc, users: repository.NewUserRepo(db), identities: repository.NewExternalIdentityRepo(db)}
}

// seedBoundOAuthUser 插入一个已验证用户及其 (apple, subject) 绑定。
func (f *oauthCallbackFixture) seedBoundOAuthUser(t *testing.T, email, subject string) {
	t.Helper()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	user := &domain.User{
		Email:           email,
		EmailNormalized: email,
		Nickname:        "tester",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := f.users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := f.identities.Create(context.Background(), &domain.ExternalIdentity{
		UserID:          user.ID,
		ProviderKey:     "apple",
		ProviderSubject: subject,
	}); err != nil {
		t.Fatalf("create identity: %v", err)
	}
}

// startOAuthState 通过 BeginOAuth 生成并落库一次性 state，返回 state 值。
func (f *oauthCallbackFixture) startOAuthState(t *testing.T, purpose string, userID int64, redirect string) string {
	t.Helper()
	start, err := f.svc.BeginOAuth(context.Background(), "apple", purpose, userID, redirect)
	if err != nil {
		t.Fatalf("BeginOAuth: %v", err)
	}
	u, err := url.Parse(start.AuthURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("auth url missing state")
	}
	return state
}

// postOAuthComplete 以 JSON body 调用 complete 端点。
func (f *oauthCallbackFixture) postOAuthComplete(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/apple/complete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	f.router.ServeHTTP(rec, req)
	return rec
}

// assertNoStore 断言响应携带 Cache-Control: no-store。
func assertNoStore(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

// assertSessionCookie 断言响应写入了第一方会话 Cookie。
func assertSessionCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == middleware.FirstPartyCookieName {
			return
		}
	}
	t.Fatalf("response cookies = %v, want %s", rec.Result().Cookies(), middleware.FirstPartyCookieName)
}

// assertNoSessionCookie 断言响应没有写入第一方会话 Cookie。
func assertNoSessionCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == middleware.FirstPartyCookieName {
			t.Fatalf("response must not set %s", middleware.FirstPartyCookieName)
		}
	}
}

// TestOAuthCompleteDirectSuccess 验证直接 JSON 回调成功：200 返回净化后的回跳地址，
// 写入会话 Cookie 且 no-store。
func TestOAuthCompleteDirectSuccess(t *testing.T) {
	fx := newOAuthCallbackRouter(t, &oauth.Identity{Subject: "apple-sub-1"})
	fx.seedBoundOAuthUser(t, "user@example.com", "apple-sub-1")
	state := fx.startOAuthState(t, "login", 0, "/account/security")

	rec := fx.postOAuthComplete(t, `{"state":"`+state+`","code":"code-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body OAuthCompleteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Redirect != "/account/security" {
		t.Fatalf("redirect = %q, want /account/security", body.Redirect)
	}
	assertNoStore(t, rec)
	assertSessionCookie(t, rec)
}

// TestOAuthCompleteHandoffSuccess 验证 Apple handoff 路径：创建 handoff 后
// 提交 opaque token，成功返回回跳地址并写入会话 Cookie。
func TestOAuthCompleteHandoffSuccess(t *testing.T) {
	fx := newOAuthCallbackRouter(t, &oauth.Identity{Subject: "apple-sub-2"})
	fx.seedBoundOAuthUser(t, "user@example.com", "apple-sub-2")
	state := fx.startOAuthState(t, "login", 0, "/account/security")
	token, err := fx.svc.CreateOAuthHandoff(context.Background(), "apple", state, "code-2", "")
	if err != nil {
		t.Fatalf("CreateOAuthHandoff: %v", err)
	}

	rec := fx.postOAuthComplete(t, `{"handoff":"`+token+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body OAuthCompleteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Redirect != "/account/security" {
		t.Fatalf("redirect = %q, want /account/security", body.Redirect)
	}
	assertNoStore(t, rec)
	assertSessionCookie(t, rec)
}

// TestOAuthCompleteAccessDenied 验证提供方 error（Apple access_denied）：
// 消费 state，返回 400 oauth_access_denied 且 details.redirect 指向回跳地址，
// 绝不签发会话 Cookie。
func TestOAuthCompleteAccessDenied(t *testing.T) {
	fx := newOAuthCallbackRouter(t, &oauth.Identity{Subject: "apple-sub-3"})
	state := fx.startOAuthState(t, "login", 0, "/account/security")

	rec := fx.postOAuthComplete(t, `{"state":"`+state+`","error":"access_denied"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "oauth_access_denied") {
		t.Fatalf("body = %s, want oauth_access_denied code", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"redirect":"/account/security"`) {
		t.Fatalf("body = %s, want details.redirect", rec.Body.String())
	}
	assertNoStore(t, rec)
	assertNoSessionCookie(t, rec)
}

// TestOAuthCompleteHandoffAccessDenied 验证 Apple handoff 携带 error 时同样
// 返回 oauth_access_denied 且不签发会话。
func TestOAuthCompleteHandoffAccessDenied(t *testing.T) {
	fx := newOAuthCallbackRouter(t, &oauth.Identity{Subject: "apple-sub-4"})
	state := fx.startOAuthState(t, "login", 0, "/account/security")
	token, err := fx.svc.CreateOAuthHandoff(context.Background(), "apple", state, "", "access_denied")
	if err != nil {
		t.Fatalf("CreateOAuthHandoff: %v", err)
	}

	rec := fx.postOAuthComplete(t, `{"handoff":"`+token+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "oauth_access_denied") {
		t.Fatalf("body = %s, want oauth_access_denied code", rec.Body.String())
	}
	assertNoStore(t, rec)
	assertNoSessionCookie(t, rec)
}

// TestOAuthCompleteInvalidInput 验证缺失/混杂参数一律 400 invalid_request。
func TestOAuthCompleteInvalidInput(t *testing.T) {
	fx := newOAuthCallbackRouter(t, &oauth.Identity{Subject: "apple-sub-5"})

	tests := []struct {
		name string
		body string
	}{
		{name: "empty body", body: `{}`},
		{name: "state only no code", body: `{"state":"unknown-state"}`},
		{name: "code only no state", body: `{"code":"code-x"}`},
		{name: "handoff mixed with state", body: `{"handoff":"h","state":"s"}`},
		{name: "handoff mixed with code", body: `{"handoff":"h","code":"c"}`},
		{name: "handoff mixed with error", body: `{"handoff":"h","error":"access_denied"}`},
		{name: "error without state", body: `{"error":"access_denied"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := fx.postOAuthComplete(t, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid_request") {
				t.Fatalf("body = %s, want invalid_request code", rec.Body.String())
			}
			assertNoStore(t, rec)
			assertNoSessionCookie(t, rec)
		})
	}
}

// TestOAuthCompleteStateReplay 验证已消费/未知 state 返回 oauth_callback_invalid，
// 且不签发会话。
func TestOAuthCompleteStateReplay(t *testing.T) {
	fx := newOAuthCallbackRouter(t, &oauth.Identity{Subject: "apple-sub-6"})
	fx.seedBoundOAuthUser(t, "user@example.com", "apple-sub-6")
	state := fx.startOAuthState(t, "login", 0, "/account/security")

	first := fx.postOAuthComplete(t, `{"state":"`+state+`","code":"code-1"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200; body=%s", first.Code, first.Body.String())
	}
	replay := fx.postOAuthComplete(t, `{"state":"`+state+`","code":"code-1"}`)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400; body=%s", replay.Code, replay.Body.String())
	}
	if !strings.Contains(replay.Body.String(), "oauth_callback_invalid") {
		t.Fatalf("body = %s, want oauth_callback_invalid code", replay.Body.String())
	}
	assertNoSessionCookie(t, replay)
}

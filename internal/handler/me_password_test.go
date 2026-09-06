package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// mePasswordStore 是 /me/password 端点的缓存替身（读/写用例不需要失效语义）。
type mePasswordStore struct{}

func (mePasswordStore) Get(ctx context.Context, key string, out any) error { return cache.ErrNotFound }
func (mePasswordStore) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return nil
}
func (mePasswordStore) Delete(ctx context.Context, key string) error { return nil }
func (mePasswordStore) AtomicConsume(ctx context.Context, key string) (string, error) {
	return "", cache.ErrNotFound
}
func (mePasswordStore) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	return nil
}

// mePasswordPolicy 返回公开注册开启与认证评论模式。
type mePasswordPolicy struct{}

func (mePasswordPolicy) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}
func (mePasswordPolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, nil, "https://www.gravatar.com/avatar", nil
}

// mePasswordEnv 聚合 /me/password 端点的数据库与缓存替身。
type mePasswordEnv struct {
	svc    *identity.Service
	userDB *gorm.DB
}

// newMePasswordEnv 装配带真实 SQLite 仓储的 /me 路由环境。
func newMePasswordEnv(t *testing.T) *mePasswordEnv {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "handler-me-password-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.NotificationPreferences{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	svc := identity.NewService(identity.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
		Prefs:    repository.NewPreferenceRepo(db),
		Cache:    mePasswordStore{},
		Policy:   mePasswordPolicy{},
		Signer:   identity.NewSigner(identity.SignerConfig{Issuer: "test", Key: []byte("test-key"), Lifetime: time.Hour}),
	})
	return &mePasswordEnv{svc: svc, userDB: db}
}

// userPrincipal 注入指定用户 id 的活跃主体，模拟 RequireUser 门禁通过。
func userPrincipal(userID int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("current_principal", domain.Principal{UserID: userID, Role: domain.RoleUser, Status: domain.UserStatusActive})
		c.Next()
	}
}

// mePasswordRouter 装配含翻译器、主体注入、用户门禁与 CSRF 的 /me 路由。
func mePasswordRouter(t *testing.T, svc *identity.Service, userID int64) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	translator, err := NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	api := router.Group("/api/v1", userPrincipal(userID))
	RegisterMeWithAdmission(api, svc, svc, nil, middleware.CSRFProtection())
	return router
}

// doMePasswordPost 发送带 CSRF 的 /me/password 请求。
func doMePasswordPost(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/me/password", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	return rec
}

// seedPasswordUser 通过管理员命令创建带密码用户并返回其 ID。
func seedPasswordUser(t *testing.T, env *mePasswordEnv, email, password string) int64 {
	t.Helper()
	profile, err := env.svc.AdminCreateUser(context.Background(), identity.AdminCreateUserInput{
		Email: email, Nickname: "seed", Role: domain.RoleUser, Password: &password,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return profile.ID
}

// TestMePasswordSetsFirstPassword 验证无密码用户首设密码返回 204 且不回显密码。
func TestMePasswordSetsFirstPassword(t *testing.T) {
	env := newMePasswordEnv(t)
	profile, err := env.svc.AdminCreateUser(context.Background(), identity.AdminCreateUserInput{
		Email: "first@example.com", Nickname: "first", Role: domain.RoleUser,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := mePasswordRouter(t, env.svc, profile.ID)

	rec := doMePasswordPost(t, router, `{"new_password":"newpassword123"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "newpassword123") {
		t.Fatal("response must not echo the password")
	}
	assertSessionCookiesSet(t, rec)
	has, err := repository.NewUserRepo(env.userDB).HasPassword(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("has password: %v", err)
	}
	if !has {
		t.Fatal("first password must be persisted")
	}
}

// assertSessionCookiesSet 断言成功的改密/重签响应写入了会话与 CSRF Cookie。
func assertSessionCookiesSet(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	cookies := rec.Result().Cookies()
	names := map[string]bool{}
	for _, cookie := range cookies {
		names[cookie.Name] = true
	}
	if !names[middleware.FirstPartyCookieName] || !names[middleware.CSRFCookieName] {
		t.Fatalf("response cookies = %v, want fresh session and CSRF cookies", names)
	}
}

// TestMePasswordWrongCurrentRejected 验证错误当前密码返回 401 且零写入。
func TestMePasswordWrongCurrentRejected(t *testing.T) {
	env := newMePasswordEnv(t)
	id := seedPasswordUser(t, env, "wrong@example.com", "oldpassword123")
	router := mePasswordRouter(t, env.svc, id)

	before, err := repository.NewUserRepo(env.userDB).PasswordHash(context.Background(), id)
	if err != nil {
		t.Fatalf("password hash before: %v", err)
	}

	rec := doMePasswordPost(t, router, `{"current_password":"bad-current","new_password":"newpassword123"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "bad-current") || strings.Contains(rec.Body.String(), "newpassword123") {
		t.Fatal("response must not echo credentials")
	}
	after, err := repository.NewUserRepo(env.userDB).PasswordHash(context.Background(), id)
	if err != nil {
		t.Fatalf("password hash after: %v", err)
	}
	if after != before {
		t.Fatal("failed change must leave the password hash unchanged")
	}
}

// TestMePasswordCorrectCurrentUpdates 验证正确当前密码后替换为新密码。
func TestMePasswordCorrectCurrentUpdates(t *testing.T) {
	env := newMePasswordEnv(t)
	id := seedPasswordUser(t, env, "update@example.com", "oldpassword123")
	router := mePasswordRouter(t, env.svc, id)

	rec := doMePasswordPost(t, router, `{"current_password":"oldpassword123","new_password":"newpassword456"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	assertSessionCookiesSet(t, rec)
	hash, err := repository.NewUserRepo(env.userDB).PasswordHash(context.Background(), id)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("password hash = %q, want argon2id envelope", hash)
	}
}

// TestMePasswordRequiresCSRF 验证 /me/password 被 CSRF 保护。
func TestMePasswordRequiresCSRF(t *testing.T) {
	env := newMePasswordEnv(t)
	profile, err := env.svc.AdminCreateUser(context.Background(), identity.AdminCreateUserInput{
		Email: "csrf@example.com", Nickname: "csrf", Role: domain.RoleUser,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := mePasswordRouter(t, env.svc, profile.ID)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/me/password", strings.NewReader(`{"new_password":"newpassword123"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"invalid_csrf_token"`) {
		t.Fatalf("status = %d, want 403 invalid_csrf_token; body=%s", rec.Code, rec.Body.String())
	}
}

// doMeRevokePost 发送带 CSRF 的 /me/sessions/revoke 请求。
func doMeRevokePost(t *testing.T, router *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/me/sessions/revoke", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	return rec
}

// TestMeRevokeAllSessionsBumpsVersionAndClearsCookies 验证 revoke-all 递增会话
// 代次、清除当前 Cookie 并返回 204，不重签会话。
func TestMeRevokeAllSessionsBumpsVersionAndClearsCookies(t *testing.T) {
	env := newMePasswordEnv(t)
	profile, err := env.svc.AdminCreateUser(context.Background(), identity.AdminCreateUserInput{
		Email: "revoke@example.com", Nickname: "revoke", Role: domain.RoleUser,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	before, err := repository.NewUserRepo(env.userDB).FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	router := mePasswordRouter(t, env.svc, profile.ID)

	rec := doMeRevokePost(t, router)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	cleared := map[string]bool{}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge != -1 || cookie.Value != "" {
			t.Errorf("revoke cookie was not expired: %+v", cookie)
		}
		cleared[cookie.Name] = true
	}
	if !cleared[middleware.FirstPartyCookieName] || !cleared[middleware.CSRFCookieName] {
		t.Fatalf("revoke cleared cookies = %v", cleared)
	}
	after, err := repository.NewUserRepo(env.userDB).FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user after revoke: %v", err)
	}
	if after.SessionVersion != before.SessionVersion+1 {
		t.Fatalf("session version after revoke = %d, want %d", after.SessionVersion, before.SessionVersion+1)
	}
}

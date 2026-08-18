package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
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

// adminUsersCache 是管理员用户端点的缓存替身，记录 authz 失效键。
type adminUsersCache struct {
	deleted []string
}

func (c *adminUsersCache) Get(ctx context.Context, key string, out any) error {
	return cache.ErrNotFound
}
func (c *adminUsersCache) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return nil
}
func (c *adminUsersCache) Delete(ctx context.Context, key string) error {
	c.deleted = append(c.deleted, key)
	return nil
}
func (c *adminUsersCache) AtomicConsume(ctx context.Context, key string) (string, error) {
	return "", cache.ErrNotFound
}
func (c *adminUsersCache) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	return nil
}

// adminUsersPolicy 返回公开注册开启与认证模式，供登录相关断言使用。
type adminUsersPolicy struct{}

func (adminUsersPolicy) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}
func (adminUsersPolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, nil, "https://www.gravatar.com/avatar", nil
}

// adminUsersTestEnv 聚合管理员用户端点的数据库与缓存替身。
type adminUsersTestEnv struct {
	svc    *identity.Service
	cache  *adminUsersCache
	userDB *gorm.DB
}

// newAdminUsersEnv 装配带真实 SQLite 仓储的服务与替身缓存。
func newAdminUsersEnv(t *testing.T) *adminUsersTestEnv {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "handler-admin-users-test.db")
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
	store := &adminUsersCache{}
	svc := identity.NewService(identity.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
		Prefs:    repository.NewPreferenceRepo(db),
		Cache:    store,
		Policy:   adminUsersPolicy{},
	})
	return &adminUsersTestEnv{svc: svc, cache: store, userDB: db}
}

// adminPrincipal 把请求上下文注入活跃管理员主体，模拟完成认证的 RequireAdmin 门禁。
func adminPrincipal(c *gin.Context) {
	c.Set("current_principal", domain.Principal{UserID: 1, Role: domain.RoleAdmin, Status: domain.UserStatusActive})
	c.Next()
}

// adminUsersRouter 装配含翻译器、管理员门禁与 CSRF 的管理员用户路由。
func adminUsersRouter(t *testing.T, svc *identity.Service) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	translator, err := NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	admin := router.Group("/api/v1/admin", adminPrincipal, middleware.RequireAdmin(svc), middleware.CSRFProtection())
	RegisterAdminUsers(admin, svc)
	return router
}

// csrf 返回可复用的 43 字符 CSRF token。
const csrf = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// TestAdminUsersCreateWritesAllFields 验证创建端点原子写入资料、密码与验证时间。
func TestAdminUsersCreateWritesAllFields(t *testing.T) {
	env := newAdminUsersEnv(t)
	router := adminUsersRouter(t, env.svc)
	body := `{"email":"admin@example.com","nickname":"Admin","website_url":"https://example.com","role":"admin","password":"supersecret","email_verified":true}`
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"email_verified":true`, `"has_password":true`, `"website_url":"https://example.com"`, `"role":"admin"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("body missing %s: %s", want, rec.Body.String())
		}
	}

	// 密码哈希可通过仓储读取并验证。
	user, err := repository.NewUserRepo(env.userDB).FindByEmailNormalized(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("find created user: %v", err)
	}
	hash, err := repository.NewUserRepo(env.userDB).PasswordHash(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("password hash = %q, want argon2id envelope", hash)
	}
}

// TestAdminUsersCreateLegacyPayloadStillWorks 验证旧客户端只提交 email/nickname/role 仍然可用。
func TestAdminUsersCreateLegacyPayloadStillWorks(t *testing.T) {
	env := newAdminUsersEnv(t)
	router := adminUsersRouter(t, env.svc)
	body := `{"email":"user@example.com","nickname":"user","role":"user"}`
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"has_password":true`) {
		t.Fatal("legacy create must not set a password")
	}
	if strings.Contains(rec.Body.String(), `"email_verified":true`) {
		t.Fatal("legacy create must not verify the email")
	}
}

// TestAdminUsersCreateRejectsDuplicateEmail 验证重复邮箱返回 409。
func TestAdminUsersCreateRejectsDuplicateEmail(t *testing.T) {
	env := newAdminUsersEnv(t)
	router := adminUsersRouter(t, env.svc)
	body := `{"email":"dup@example.com","nickname":"a","role":"user"}`
	send := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
		request.Header.Set(middleware.CSRFHeaderName, csrf)
		router.ServeHTTP(rec, request)
		return rec
	}
	if rec := send(); rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want 201", rec.Code)
	}
	if rec := send(); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminUsersUpdateMergesFields 验证 PATCH 合并更新资料、验证状态并保留未提供字段。
func TestAdminUsersUpdateMergesFields(t *testing.T) {
	env := newAdminUsersEnv(t)
	created := createAdminUser(t, env, `{"email":"before@example.com","nickname":"before","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	body := `{"email":"after@example.com","nickname":"after","email_verified":true}`
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/"+created, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"email":"after@example.com"`, `"nickname":"after"`, `"email_verified":true`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("body missing %s: %s", want, rec.Body.String())
		}
	}
}

// TestAdminUsersUpdatePreservesVerificationOnEmailChange 验证邮箱变化保留验证状态。
func TestAdminUsersUpdatePreservesVerificationOnEmailChange(t *testing.T) {
	env := newAdminUsersEnv(t)
	created := createAdminUser(t, env, `{"email":"v@example.com","nickname":"v","role":"user","email_verified":true}`)
	router := adminUsersRouter(t, env.svc)

	body := `{"email":"v2@example.com"}`
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/"+created, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"email_verified":true`) {
		t.Fatalf("email change must preserve verification: %s", rec.Body.String())
	}
}

// TestAdminUsersUpdateWebsiteNullVsOmitted 验证省略保留、显式 null 清除网站。
func TestAdminUsersUpdateWebsiteNullVsOmitted(t *testing.T) {
	env := newAdminUsersEnv(t)
	created := createAdminUser(t, env, `{"email":"site@example.com","nickname":"site","role":"user","website_url":"https://example.com"}`)
	router := adminUsersRouter(t, env.svc)

	// 省略保留网站。
	rec := doAdminPatch(t, router, created, `{"nickname":"site-2"}`)
	if !strings.Contains(rec.Body.String(), `"website_url":"https://example.com"`) {
		t.Fatalf("omitted website_url must be preserved: %s", rec.Body.String())
	}

	// 显式 null 清除网站。
	rec = doAdminPatch(t, router, created, `{"website_url":null}`)
	if !strings.Contains(rec.Body.String(), `"website_url":null`) {
		t.Fatalf("explicit null website_url must clear: %s", rec.Body.String())
	}
}

// TestAdminUsersUpdateLastAdminConflict 验证最后活跃管理员降级返回 409。
func TestAdminUsersUpdateLastAdminConflict(t *testing.T) {
	env := newAdminUsersEnv(t)
	created := createAdminUser(t, env, `{"email":"admin@example.com","nickname":"admin","role":"admin"}`)
	router := adminUsersRouter(t, env.svc)

	rec := doAdminPatch(t, router, created, `{"role":"user"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminUsersResetPassword 验证独立重置密码端点设置新密码且不改变验证状态。
func TestAdminUsersResetPassword(t *testing.T) {
	env := newAdminUsersEnv(t)
	created := createAdminUser(t, env, `{"email":"reset@example.com","nickname":"reset","role":"user","email_verified":true}`)
	router := adminUsersRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+created+"/password", strings.NewReader(`{"password":"newpassword123"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	user, err := repository.NewUserRepo(env.userDB).FindByEmailNormalized(context.Background(), "reset@example.com")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	hash, err := repository.NewUserRepo(env.userDB).PasswordHash(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("password hash = %q, want argon2id envelope", hash)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("reset password must preserve verification time")
	}
}

// TestAdminUsersResetPasswordRejectsShort 验证过短密码返回 422。
func TestAdminUsersResetPasswordRejectsShort(t *testing.T) {
	env := newAdminUsersEnv(t)
	created := createAdminUser(t, env, `{"email":"short@example.com","nickname":"short","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+created+"/password", strings.NewReader(`{"password":"short"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminUsersRoutesRequireCSRF 验证所有不安全写路由都被 CSRF 保护。
func TestAdminUsersRoutesRequireCSRF(t *testing.T) {
	env := newAdminUsersEnv(t)
	router := adminUsersRouter(t, env.svc)
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/v1/admin/users", `{}`},
		{http.MethodPatch, "/api/v1/admin/users/1", `{}`},
		{http.MethodPost, "/api/v1/admin/users/1/password", `{}`},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"invalid_csrf_token"`) {
			t.Fatalf("%s %s without CSRF = %d %s, want 403 invalid_csrf_token", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

// TestAdminUsersRejectModeratorAndSuspended 验证后端拒绝无效枚举值。
func TestAdminUsersRejectModeratorAndSuspended(t *testing.T) {
	env := newAdminUsersEnv(t)
	router := adminUsersRouter(t, env.svc)

	rec := doAdminPost(t, router, `{"email":"m@example.com","nickname":"m","role":"moderator"}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("moderator role status = %d, want 422", rec.Code)
	}
	created := createAdminUser(t, env, `{"email":"u@example.com","nickname":"u","role":"user"}`)
	rec = doAdminPatch(t, router, created, `{"status":"suspended"}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("suspended status = %d, want 422", rec.Code)
	}
}

// createAdminUser 通过端点创建一个用户并返回其 ID。
func createAdminUser(t *testing.T, env *adminUsersTestEnv, body string) string {
	t.Helper()
	router := adminUsersRouter(t, env.svc)
	rec := doAdminPost(t, router, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(rec.Body.String()), &parsed); err != nil {
		t.Fatalf("parse create response: %v; body=%s", err, rec.Body.String())
	}
	return parsed.ID
}

// TestAdminUsersDeleteSoft 验证软删除端点把用户置为 deleted。
func TestAdminUsersDeleteSoft(t *testing.T) {
	env := newAdminUsersEnv(t)
	// adminPrincipal 使用 UserID=1，创建 UserID=1 作为操作者并补充第二名管理员。
	createAdminUser(t, env, `{"email":"act@example.com","nickname":"act","role":"admin"}`)
	createAdminUser(t, env, `{"email":"other@example.com","nickname":"other","role":"admin"}`)
	created := createAdminUser(t, env, `{"email":"victim@example.com","nickname":"victim","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+created+"?mode=soft", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	user, err := repository.NewUserRepo(env.userDB).FindByID(context.Background(), idOf(t, created))
	if err != nil {
		t.Fatalf("find deleted user: %v", err)
	}
	if user.Status != domain.UserStatusDeleted || user.DeletedAt == nil {
		t.Fatalf("soft-deleted user = %+v", user)
	}
}

// TestAdminUsersDeleteSelfForbidden 验证删除自己返回 403。
func TestAdminUsersDeleteSelfForbidden(t *testing.T) {
	env := newAdminUsersEnv(t)
	router := adminUsersRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/1?mode=soft", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self delete status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminUsersDeleteLastAdminConflict 验证删除最后一名活跃管理员返回 409。
func TestAdminUsersDeleteLastAdminConflict(t *testing.T) {
	env := newAdminUsersEnv(t)
	// 用 UserID=1 的普通占位用户占用该 id，随后创建唯一的管理员。
	createAdminUser(t, env, `{"email":"placeholder@example.com","nickname":"placeholder","role":"user"}`)
	other := createAdminUser(t, env, `{"email":"o@example.com","nickname":"o","role":"admin"}`)
	router := adminUsersRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+other+"?mode=soft", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusConflict {
		t.Fatalf("last admin delete status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminUsersHardDeleteRequiresConfirm 验证硬删除缺少 confirm 返回 422。
func TestAdminUsersHardDeleteRequiresConfirm(t *testing.T) {
	env := newAdminUsersEnv(t)
	createAdminUser(t, env, `{"email":"h1@example.com","nickname":"h1","role":"admin"}`)
	createAdminUser(t, env, `{"email":"h2@example.com","nickname":"h2","role":"admin"}`)
	created := createAdminUser(t, env, `{"email":"v@example.com","nickname":"v","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+created+"?mode=hard", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("hard delete without confirm status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminUsersHardDeleteRemovesUser 验证硬删除端点物理移除用户。
func TestAdminUsersHardDeleteRemovesUser(t *testing.T) {
	env := newAdminUsersEnv(t)
	createAdminUser(t, env, `{"email":"a@example.com","nickname":"a","role":"admin"}`)
	createAdminUser(t, env, `{"email":"b@example.com","nickname":"b","role":"admin"}`)
	created := createAdminUser(t, env, `{"email":"gone@example.com","nickname":"gone","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+created+"?mode=hard&confirm=true", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := repository.NewUserRepo(env.userDB).FindByID(context.Background(), idOf(t, created)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("hard-deleted user still exists: %v", err)
	}
}

// TestAdminUsersRestore 验证恢复端点把软删除用户带回删除前状态。
func TestAdminUsersRestore(t *testing.T) {
	env := newAdminUsersEnv(t)
	createAdminUser(t, env, `{"email":"r1@example.com","nickname":"r1","role":"admin"}`)
	createAdminUser(t, env, `{"email":"r2@example.com","nickname":"r2","role":"admin"}`)
	created := createAdminUser(t, env, `{"email":"rv@example.com","nickname":"rv","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	delRec := httptest.NewRecorder()
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+created+"?mode=soft", nil)
	delReq.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	delReq.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("soft delete status = %d, want 204", delRec.Code)
	}

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+created+"/restore", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("restore status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var parsed struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(rec.Body.String()), &parsed); err != nil {
		t.Fatalf("parse restore: %v", err)
	}
	if parsed.Status != "active" {
		t.Fatalf("restored status = %q, want active", parsed.Status)
	}
}

// TestAdminUsersListCarriesTotal 验证列表响应携带真实总数。
func TestAdminUsersListCarriesTotal(t *testing.T) {
	env := newAdminUsersEnv(t)
	createAdminUser(t, env, `{"email":"t1@example.com","nickname":"t1","role":"user"}`)
	createAdminUser(t, env, `{"email":"t2@example.com","nickname":"t2","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?limit=1", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var parsed struct {
		Users []json.RawMessage `json:"users"`
		Total int64             `json:"total"`
	}
	if err := json.Unmarshal([]byte(rec.Body.String()), &parsed); err != nil {
		t.Fatalf("parse list: %v", err)
	}
	if len(parsed.Users) != 1 {
		t.Fatalf("page users = %d, want 1", len(parsed.Users))
	}
	if parsed.Total != 2 {
		t.Fatalf("total = %d, want 2 (independent of limit)", parsed.Total)
	}
}

// TestAdminUsersListPageOffsets 验证 page 参数真正改变偏移：limit=1 时第 2 页
// 返回不同于第 1 页的用户，且总数保持不变。
func TestAdminUsersListPageOffsets(t *testing.T) {
	env := newAdminUsersEnv(t)
	createAdminUser(t, env, `{"email":"p1@example.com","nickname":"p1","role":"user"}`)
	createAdminUser(t, env, `{"email":"p2@example.com","nickname":"p2","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	var first struct {
		Users []struct {
			Email string `json:"email"`
		} `json:"users"`
		Total int64 `json:"total"`
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?limit=1&page=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("page 1 status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode page 1: %v", err)
	}
	if len(first.Users) != 1 || first.Total != 2 {
		t.Fatalf("page 1 = %d users total=%d, want 1 + total 2", len(first.Users), first.Total)
	}

	var second struct {
		Users []struct {
			Email string `json:"email"`
		} `json:"users"`
		Total int64 `json:"total"`
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?limit=1&page=2", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("page 2 status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if len(second.Users) != 1 || second.Total != 2 {
		t.Fatalf("page 2 = %d users total=%d, want 1 + total 2", len(second.Users), second.Total)
	}
	if first.Users[0].Email == second.Users[0].Email {
		t.Fatalf("page 1 and page 2 returned the same user %q", first.Users[0].Email)
	}
}

// TestAdminUsersListRejectsInvalidPage 验证非正整数页码返回参数错误。
func TestAdminUsersListRejectsInvalidPage(t *testing.T) {
	env := newAdminUsersEnv(t)
	createAdminUser(t, env, `{"email":"q@example.com","nickname":"q","role":"user"}`)
	router := adminUsersRouter(t, env.svc)
	for _, page := range []string{"0", "-1", "abc", "1.5"} {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?page="+page, nil)
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("page=%s status = %d, want 400; body=%s", page, rec.Code, rec.Body.String())
		}
	}
}

// TestAdminUsersListAcceptsSortDirection 验证管理用户列表接受受控 sort 参数：
// asc/desc 均返回 200，缺省等价 desc，非法值返回 422。
func TestAdminUsersListAcceptsSortDirection(t *testing.T) {
	env := newAdminUsersEnv(t)
	createAdminUser(t, env, `{"email":"a@example.com","nickname":"a","role":"user"}`)
	router := adminUsersRouter(t, env.svc)

	for _, sort := range []string{"asc", "desc"} {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?sort="+sort, nil)
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusOK {
			t.Fatalf("sort=%s status = %d, want 200; body=%s", sort, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?sort=sideways", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid sort status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"invalid_input"`) {
		t.Fatalf("invalid sort body = %s, want code invalid_input", rec.Body.String())
	}
}

// idOf 把十进制字符串 ID 转为 int64。
func idOf(t *testing.T, raw string) int64 {
	t.Helper()
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		t.Fatalf("parse id %q: %v", raw, err)
	}
	return id
}

// doAdminPost 发送带 CSRF 的 POST 请求。
func doAdminPost(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	return rec
}

// doAdminPatch 发送带 CSRF 的 PATCH 请求。
func doAdminPatch(t *testing.T, router *gin.Engine, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/"+id, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	return rec
}

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

// disabledLoginStore 是登录端点用的缓存替身。
type disabledLoginStore struct{}

func (disabledLoginStore) Get(ctx context.Context, key string, out any) error {
	return cache.ErrNotFound
}
func (disabledLoginStore) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return nil
}
func (disabledLoginStore) Delete(ctx context.Context, key string) error { return nil }
func (disabledLoginStore) AtomicConsume(ctx context.Context, key string) (string, error) {
	return "", cache.ErrNotFound
}
func (disabledLoginStore) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	return nil
}

// disabledLoginPolicy 返回认证模式与公开注册开启的策略。
type disabledLoginPolicy struct{}

func (disabledLoginPolicy) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}
func (disabledLoginPolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, nil, "https://www.gravatar.com/avatar", nil
}

// disabledLoginEnv 聚合登录路由环境与真实用户仓储。
type disabledLoginEnv struct {
	router *gin.Engine
	svc    *identity.Service
	db     *gorm.DB
}

// newDisabledLoginEnv 装配带真实 SQLite 用户仓储的登录路由环境。
func newDisabledLoginEnv(t *testing.T) *disabledLoginEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "handler-disabled-login-test.db")
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
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer: "test", Key: []byte("test-key"), Lifetime: time.Hour,
	})
	svc := identity.NewService(identity.Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         repository.NewUserRepo(db),
		Prefs:         repository.NewPreferenceRepo(db),
		Cache:         disabledLoginStore{},
		Policy:        disabledLoginPolicy{},
		CaptchaPolicy: emailCodePolicy{},
		Signer:        signer,
	})
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	router.Use(middleware.JWTVerification(signer))
	RegisterAuth(router.Group("/api/v1"), svc)
	return &disabledLoginEnv{router: router, svc: svc, db: db}
}

// seedDisabledPasswordUser 创建带正确密码的用户并切换为停用状态，返回其 ID。
func (e *disabledLoginEnv) seedDisabledPasswordUser(t *testing.T) int64 {
	t.Helper()
	password := "correct-password-1"
	profile, err := e.svc.AdminCreateUser(context.Background(), identity.AdminCreateUserInput{
		Email: "disabled@example.com", Nickname: "disabled", Role: domain.RoleUser, Password: &password,
	})
	if err != nil {
		t.Fatalf("create disabled user: %v", err)
	}
	status := domain.UserStatusDisabled
	if err := repository.NewUserRepo(e.db).UpdateRoleStatus(context.Background(), profile.ID, domain.RoleUser, status); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	return profile.ID
}

// TestDisabledAccountPasswordLoginForbidden 验证停用账号用正确密码登录返回
// 403 forbidden 且消息为「账号已被禁用」，不泄露密码信息。
func TestDisabledAccountPasswordLoginForbidden(t *testing.T) {
	env := newDisabledLoginEnv(t)
	env.seedDisabledPasswordUser(t)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login",
		strings.NewReader(`{"email":"disabled@example.com","password":"correct-password-1"}`))
	request.Header.Set("Content-Type", "application/json")
	env.router.ServeHTTP(rec, request)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
		t.Fatalf("response must carry code forbidden; body=%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "账号已被禁用") {
		t.Fatalf("response must carry the disabled message; body=%s", rec.Body.String())
	}
}

// TestActiveAccountWrongPasswordStaysGeneric 验证活跃账号错误密码仍返回通用 401。
func TestActiveAccountWrongPasswordStaysGeneric(t *testing.T) {
	env := newDisabledLoginEnv(t)
	password := "correct-password-1"
	if _, err := env.svc.AdminCreateUser(context.Background(), identity.AdminCreateUserInput{
		Email: "active@example.com", Nickname: "active", Role: domain.RoleUser, Password: &password,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login",
		strings.NewReader(`{"email":"active@example.com","password":"wrong-password"}`))
	request.Header.Set("Content-Type", "application/json")
	env.router.ServeHTTP(rec, request)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"invalid_credentials"`) {
		t.Fatalf("response must carry code invalid_credentials; body=%s", rec.Body.String())
	}
}

// TestUnknownAccountLoginStaysGeneric 验证未知账号仍返回通用 401，不泄露账号存在性。
func TestUnknownAccountLoginStaysGeneric(t *testing.T) {
	env := newDisabledLoginEnv(t)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login",
		strings.NewReader(`{"email":"unknown@example.com","password":"whatever"}`))
	request.Header.Set("Content-Type", "application/json")
	env.router.ServeHTTP(rec, request)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"invalid_credentials"`) {
		t.Fatalf("response must carry code invalid_credentials; body=%s", rec.Body.String())
	}
}

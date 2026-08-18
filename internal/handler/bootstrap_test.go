package handler

import (
	"context"
	"io"
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
	"furtalk/internal/platform/logging"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/bootstrap"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// bootstrapHandlerPolicy 返回公开注册开启与认证评论模式的实例策略。
type bootstrapHandlerPolicy struct{}

func (bootstrapHandlerPolicy) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}

func (bootstrapHandlerPolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, nil, "https://www.gravatar.com/avatar", nil
}

// bootstrapHandlerSigner 签发固定 token 的第一方 signer 替身。
type bootstrapHandlerSigner struct {
	lifetime time.Duration
}

func (s bootstrapHandlerSigner) SignFirstParty(int64, int64) (string, error) {
	return "session-token", nil
}
func (s bootstrapHandlerSigner) Lifetime() time.Duration { return s.lifetime }

// bootstrapHandlerCaptchaPolicy 返回固定的空 CAPTCHA action 策略。
type bootstrapHandlerCaptchaPolicy struct {
	policy map[string]bool
}

func (p bootstrapHandlerCaptchaPolicy) CaptchaPolicy(context.Context) (map[string]bool, error) {
	return p.policy, nil
}

// bootstrapHandlerVerifier 是恒通过的 CAPTCHA 验证器替身。
type bootstrapHandlerVerifier struct{}

func (bootstrapHandlerVerifier) Verify(context.Context, string, string) error { return nil }

// newBootstrapHandlerDB 打开临时 SQLite 数据库并迁移引导所需表。
func newBootstrapHandlerDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "bootstrap-handler-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.BootstrapState{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// newBootstrapHandlerRouter 装配带错误翻译器、真实 JWT/principal 解析与
// bootstrap 子路由的测试引擎。
func newBootstrapHandlerRouter(t *testing.T, db *gorm.DB) (*gin.Engine, *bootstrap.Service) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	identitySvc := identity.NewService(identity.Dependencies{
		TxRunner:       gormtx.NewRunner(db),
		Users:          repository.NewUserRepo(db),
		Cache:          cache.NewMemory(10000),
		Policy:         bootstrapHandlerPolicy{},
		CaptchaPolicy:  bootstrapHandlerCaptchaPolicy{map[string]bool{}},
		Captcha:        bootstrapHandlerVerifier{},
		Signer:         bootstrapHandlerSigner{lifetime: 7 * 24 * time.Hour},
		PasskeyAdapter: nil,
	})
	bootstrapSvc, err := bootstrap.NewService(gormtx.NewRunner(db), identitySvc, repository.NewBootstrapRepo(db), logging.New(io.Discard))
	if err != nil {
		t.Fatalf("new bootstrap service: %v", err)
	}
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: 7 * 24 * time.Hour,
	})
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	router.Use(middleware.JWTVerification(signer))
	router.Use(middleware.PrincipalResolution(identitySvc))
	RegisterBootstrap(router.Group("/api/v1"), bootstrapSvc)
	return router, bootstrapSvc
}

// staleFirstPartyCookie 签发指向不存在用户的合法第一方会话 Cookie，模拟
// 开发库重建后残留的有效 JWT。
func staleFirstPartyCookie(t *testing.T) *http.Cookie {
	t.Helper()
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: 7 * 24 * time.Hour,
	})
	token, err := signer.SignFirstParty(999, 1)
	if err != nil {
		t.Fatalf("sign stale first-party token: %v", err)
	}
	return &http.Cookie{Name: middleware.FirstPartyCookieName, Value: token}
}

// TestBootstrapHandlerFullFlow 验证 bootstrap HTTP 契约：
// 未初始化时状态为 required，有效 token 创建管理员返回 204，之后状态翻转。
func TestBootstrapHandlerFullFlow(t *testing.T) {
	db := newBootstrapHandlerDB(t)
	router, bootstrapSvc := newBootstrapHandlerRouter(t, db)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"required":true`) {
		t.Fatalf("initial status = %d %s, want 200 with required:true", rec.Code, rec.Body.String())
	}

	body := `{"setup_token":"` + bootstrapSvc.SetupToken() + `","email":"admin@example.com","nickname":"Admin","password":"correct-horse-1"}`
	rec = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/admin", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create admin = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"required":false`) {
		t.Fatalf("post-init status = %d %s, want 200 with required:false", rec.Code, rec.Body.String())
	}
}

// TestBootstrapHandlerAdminUnavailable 验证无效 token 返回 410 bootstrap_unavailable。
func TestBootstrapHandlerAdminUnavailable(t *testing.T) {
	db := newBootstrapHandlerDB(t)
	router, _ := newBootstrapHandlerRouter(t, db)

	body := `{"setup_token":"wrong","email":"admin@example.com","nickname":"Admin","password":"correct-horse-1"}`
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/admin", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "bootstrap_unavailable") {
		t.Fatalf("body = %s, want bootstrap_unavailable code", rec.Body.String())
	}
}

// TestBootstrapStatusIgnoresStaleFirstPartyCookie 验证携带"JWT 有效但用户不存在"
// 的残留第一方 Cookie 时，公开状态接口仍返回 200 与正确的 required 值，并清除会话。
func TestBootstrapStatusIgnoresStaleFirstPartyCookie(t *testing.T) {
	db := newBootstrapHandlerDB(t)
	router, bootstrapSvc := newBootstrapHandlerRouter(t, db)
	stale := staleFirstPartyCookie(t)

	// 未初始化实例：返回 required:true，残留 Cookie 被清除。
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	request.AddCookie(stale)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"required":true`) {
		t.Fatalf("uninitialized status = %d %s, want 200 with required:true", rec.Code, rec.Body.String())
	}
	assertHandlerCookiesCleared(t, rec)

	// 初始化后同一残留 Cookie：仍返回 required:false。
	body := `{"setup_token":"` + bootstrapSvc.SetupToken() + `","email":"admin@example.com","nickname":"Admin","password":"correct-horse-1"}`
	rec = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/admin", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create admin = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	request.AddCookie(stale)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"required":false`) {
		t.Fatalf("post-init status = %d %s, want 200 with required:false", rec.Code, rec.Body.String())
	}
	assertHandlerCookiesCleared(t, rec)
}

// assertHandlerCookiesCleared 断言响应以 Max-Age=-1 清除了两枚第一方 Cookie。
func assertHandlerCookiesCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookie count = %d, want 2 cleared cookies", len(cookies))
	}
	names := map[string]bool{}
	for _, cookie := range cookies {
		names[cookie.Name] = true
		if cookie.MaxAge != -1 || cookie.Value != "" {
			t.Errorf("stale session cookie %s not cleared: %+v", cookie.Name, cookie)
		}
	}
	if !names[middleware.FirstPartyCookieName] || !names[middleware.CSRFCookieName] {
		t.Fatalf("cleared cookies = %v, want %s and %s", cookies, middleware.FirstPartyCookieName, middleware.CSRFCookieName)
	}
}

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
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/site"
	"github.com/gin-gonic/gin"
)

const testWidgetOrigin = "https://site.example"

// buildWidgetTestService 构建一套真实 repository + service 的 widget 测试装配。
func buildWidgetTestService(t *testing.T) (*comment.Service, comment.WidgetCredentialVerifier, comment.WidgetSettingsReader, middleware.PrincipalStore, middleware.UserGate, httpxOrigins) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "widget.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, model.All()...); err != nil {
		t.Fatal(err)
	}
	runner := gormtx.NewRunner(db)
	siteRepo := repository.NewSiteRepo(db)
	sitesService := site.NewService(siteRepo)
	siteRow, err := sitesService.Create(context.Background(), "Site", testWidgetOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sitesService.AddOrigin(context.Background(), siteRow.ID, testWidgetOrigin); err != nil {
		t.Fatal(err)
	}
	origins := httpxOrigins{svc: sitesService}

	svc := comment.NewService(comment.Dependencies{
		TxRunner: runner,
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    siteRepo,
		Users:    repository.NewUserRepo(db),
		Settings: testPolicyReader{},
		UserW:    testUserWriter{},
		Authz:    testPrincipalStore{},
		Signer:   &testSigner{},
		Verifier: testVerifier{},
		Logger:   nil,
	})
	return svc, testVerifier{}, testSettingsReader{}, testPrincipalStore{}, testUserGate{}, origins
}

type httpxOrigins struct{ svc *site.Service }

func (o httpxOrigins) AllowedOrigins(ctx context.Context, siteID int64) ([]string, error) {
	return o.svc.AllowedOrigins(ctx, siteID)
}

// TestWidgetCreateRejectsDisallowedOriginBeforeHandler 验证非白名单 Origin 在 handler 前被 CORS 拒绝。
func TestWidgetCreateRejectsDisallowedOriginBeforeHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins := buildWidgetTestService(t)

	tests := []struct {
		name    string
		path    string
		origins []string
	}{
		{name: "missing"},
		{name: "null", origins: []string{"null"}},
		{name: "wildcard", origins: []string{"*"}},
		{name: "suffix", origins: []string{"https://site.example.evil.example"}},
		{name: "path", origins: []string{"https://site.example/path"}},
		{name: "disallowed", origins: []string{"https://evil.example"}},
		{name: "multiple", origins: []string{testWidgetOrigin, "https://evil.example"}},
		{name: "wrong site", path: "/api/v1/widget/sites/2/comments", origins: []string{testWidgetOrigin}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			RegisterWidget(
				router.Group("/api/v1"),
				service, verifier, settings, principals, origins,
			)

			path := tt.path
			if path == "" {
				path = "/api/v1/widget/sites/1/comments"
			}
			req := httptest.NewRequest(
				http.MethodPost,
				path,
				strings.NewReader(`{"page_key":"post","body_markdown":"hello"}`),
			)
			req.Header.Set("Content-Type", "application/json")
			for _, origin := range tt.origins {
				req.Header.Add("Origin", origin)
			}
			req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestWidgetPreflightRegistersEveryPath 验证所有启用 CORS 的 widget 路径都注册了
// OPTIONS 预检路由，且对精确允许的 origin 返回 204 与完整的 CORS 响应头。
func TestWidgetPreflightRegistersEveryPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins := buildWidgetTestService(t)

	tests := []struct {
		name string
		path string
	}{
		{name: "runtime config", path: "/api/v1/widget/sites/1/runtime-config"},
		{name: "list comments", path: "/api/v1/widget/sites/1/comments"},
		{name: "create comment", path: "/api/v1/widget/sites/1/comments"},
		{name: "pin comment", path: "/api/v1/widget/sites/1/comments/1/pin"},
		{name: "delete comment", path: "/api/v1/widget/comments/1"},
		{name: "exchange", path: "/api/v1/widget/comment-authorizations/exchange"},
		{name: "session", path: "/api/v1/widget/session"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			RegisterWidget(
				router.Group("/api/v1"),
				service, verifier, settings, principals, origins,
			)

			req := httptest.NewRequest(http.MethodOptions, tt.path, nil)
			req.Header.Set("Origin", testWidgetOrigin)
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "Content-Type, X-Request-ID")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testWidgetOrigin {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, testWidgetOrigin)
			}
			if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
				t.Fatalf("Access-Control-Allow-Credentials = %q, want true", got)
			}
			if got := rec.Header().Get("Vary"); got != "Origin" {
				t.Fatalf("Vary = %q, want Origin", got)
			}
			if methods := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(methods, "OPTIONS") {
				t.Fatalf("Access-Control-Allow-Methods = %q, want to include OPTIONS", methods)
			}
			if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
				t.Fatal("Access-Control-Allow-Headers is empty, want echoed or default")
			}
		})
	}
}

// TestWidgetPreflightRejectsSiteParamDisallowed 验证站点参数策略的预检只放行
// 站点精确配置的 origin，未配置的 origin 一律 403 且不授予 allow-origin 头。
func TestWidgetPreflightRejectsSiteParamDisallowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins := buildWidgetTestService(t)

	tests := []struct {
		name   string
		path   string
		origin string
	}{
		{name: "unconfigured origin", path: "/api/v1/widget/sites/1/runtime-config", origin: "https://evil.example"},
		{name: "suffix origin", path: "/api/v1/widget/sites/1/comments", origin: "https://site.example.evil.example"},
		{name: "missing site", path: "/api/v1/widget/sites/999/comments", origin: testWidgetOrigin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			RegisterWidget(
				router.Group("/api/v1"),
				service, verifier, settings, principals, origins,
			)

			req := httptest.NewRequest(http.MethodOptions, tt.path, nil)
			req.Header.Set("Origin", tt.origin)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Fatalf("Access-Control-Allow-Origin = %q, want empty on rejection", got)
			}
		})
	}
}

// TestWidgetPreflightRejectsCredentialContextInvalid 验证凭据上下文策略的预检只做
// 结构性 Origin 校验，畸形、缺失、多个、通配符或 null Origin 一律 403 且不授予头。
func TestWidgetPreflightRejectsCredentialContextInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins := buildWidgetTestService(t)

	tests := []struct {
		name   string
		path   string
		origin string
	}{
		{name: "missing origin", path: "/api/v1/widget/comment-authorizations/exchange", origin: ""},
		{name: "null origin", path: "/api/v1/widget/comment-authorizations/exchange", origin: "null"},
		{name: "wildcard origin", path: "/api/v1/widget/session", origin: "*"},
		{name: "path origin", path: "/api/v1/widget/session", origin: "https://site.example/path"},
		{name: "non-https origin", path: "/api/v1/widget/comments/1", origin: "http://evil.example"},
		{name: "multiple origin headers", path: "/api/v1/widget/session", origin: testWidgetOrigin + ", https://evil.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			RegisterWidget(
				router.Group("/api/v1"),
				service, verifier, settings, principals, origins,
			)

			req := httptest.NewRequest(http.MethodOptions, tt.path, nil)
			if tt.origin == "" {
				req.Header.Del("Origin")
			} else if strings.Contains(tt.origin, ", ") {
				for _, part := range strings.Split(tt.origin, ", ") {
					req.Header.Add("Origin", part)
				}
			} else {
				req.Header.Set("Origin", tt.origin)
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Fatalf("Access-Control-Allow-Origin = %q, want empty on rejection", got)
			}
		})
	}
}

type testPolicyReader struct{}

func (testPolicyReader) CommentPolicy(context.Context) (domain.CommentPolicy, error) {
	return domain.CommentPolicy{
		Mode:           domain.CommentModeAnonymous,
		Epoch:          1,
		Moderation:     domain.ModerationDirect,
		UserDeleteMode: domain.UserDeleteModeSoft,
		MaxReplyDepth:  3,
		CaptchaPolicy:  map[string]bool{},
		Privacy:        domain.PrivacyPolicy{IPMode: "none", UAMode: "none"},
		CommentSort:    string(domain.CommentSortAsc),
	}, nil
}

type testSettingsReader struct{}

func (testSettingsReader) WidgetConfig(context.Context) (string, int64, error) {
	return domain.CommentModeAnonymous, 1, nil
}

type testPrincipalStore struct{}

func (testPrincipalStore) Resolve(context.Context, int64) (domain.Principal, error) {
	return domain.Principal{UserID: 1, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 1}, nil
}

type testUserGate struct{}

func (testUserGate) RequireUser(context.Context, domain.Principal) error { return nil }

type testUserWriter struct{}

func (testUserWriter) CreateUser(context.Context, *domain.User) error                  { return nil }
func (testUserWriter) UpdateUserProfile(context.Context, int64, string, *string) error { return nil }

type testSigner struct{}

func (testSigner) SignWidget(userID, siteID int64, kind, epoch string) (string, error) {
	return "token", nil
}
func (testSigner) Lifetime() time.Duration { return time.Hour }

type testVerifier struct{}

type testCredential struct{}

func (testCredential) UserID() int64        { return 1 }
func (testCredential) SiteID() int64        { return 1 }
func (testCredential) CommentMode() string  { return domain.CommentModeAnonymous }
func (testCredential) Epoch() int64         { return 1 }
func (testCredential) ExpiresAt() time.Time { return time.Now().Add(time.Hour) }

func (testVerifier) Verify(context.Context, string) (comment.WidgetCredential, error) {
	return testCredential{}, nil
}

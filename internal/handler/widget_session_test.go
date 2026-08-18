package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	jwt "furtalk/internal/platform/token"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/site"
	"github.com/gin-gonic/gin"
)

// sessionPolicyReader 返回给定模式与凭证代次的评论策略。
type sessionPolicyReader struct {
	mode  string
	epoch int64
}

func (r sessionPolicyReader) CommentPolicy(context.Context) (domain.CommentPolicy, error) {
	return domain.CommentPolicy{Mode: r.mode, Epoch: r.epoch}, nil
}

// sessionPrincipalStore 返回固定的当前主体。
type sessionPrincipalStore struct {
	principal domain.Principal
}

func (s sessionPrincipalStore) Resolve(context.Context, int64) (domain.Principal, error) {
	return s.principal, nil
}

// buildWidgetSessionRouter 装配真实 signer/verifier 与给定主体的已注册 widget 路由，
// 覆盖 CHIPS cookie、allowed Origin 与 session 探测的完整链路。
func buildWidgetSessionRouter(t *testing.T, mode string, role domain.Role, status domain.UserStatus) (*gin.Engine, *comment.WidgetSigner, int64) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "widget-session.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, model.All()...); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	siteRepo := repository.NewSiteRepo(db)
	sitesService := site.NewService(siteRepo)
	created, err := sitesService.Create(context.Background(), "Site", testWidgetOrigin)
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := sitesService.AddOrigin(context.Background(), created.ID, testWidgetOrigin); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	origins := httpxOrigins{svc: sitesService}

	signer := comment.NewWidgetSigner(comment.WidgetSignerConfig{
		Issuer:   "https://app.example",
		Key:      []byte("widget-session-test-key"),
		Lifetime: time.Hour,
	})
	verifier := comment.NewWidgetJWTVerifierFromSigner(signer)
	settings := comment.NewSettingsReader(sessionPolicyReader{mode: mode, epoch: 1})
	authz := sessionPrincipalStore{principal: domain.Principal{UserID: 2, Role: role, Status: status}}

	svc := comment.NewService(comment.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    siteRepo,
		Users:    repository.NewUserRepo(db),
		Settings: sessionPolicyReader{mode: mode, epoch: 1},
		UserW:    testUserWriter{},
		Authz:    authz,
		Signer:   signer,
		Verifier: verifier,
		Logger:   nil,
	})

	router := gin.New()
	RegisterWidget(router.Group("/api/v1"), svc, verifier, settings, authz, origins)
	return router, signer, created.ID
}

// TestWidgetSessionAdminAuthenticated 回归管理员经显式授权交换后的 WT 会话：
// 真实签名的 widget_authenticated 配合 CHIPS cookie 与允许的 Origin 立即返回 valid:true。
func TestWidgetSessionAdminAuthenticated(t *testing.T) {
	router, signer, siteID := buildWidgetSessionRouter(t, domain.CommentModeAuthenticated, domain.RoleAdmin, domain.UserStatusActive)
	token, err := signer.SignWidget(2, siteID, jwt.TokenKindWidgetAuthenticated, "1")
	if err != nil {
		t.Fatalf("sign widget token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/widget/session", nil)
	req.Header.Set("Origin", testWidgetOrigin)
	req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp WidgetSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("valid = false, want true; body=%s", rec.Body.String())
	}
	if resp.CredentialMode != domain.CommentModeAuthenticated {
		t.Fatalf("credential_mode = %q, want authenticated", resp.CredentialMode)
	}
	if resp.UserID != "2" || resp.SiteID != "1" {
		t.Fatalf("user_id/site_id = %q/%q, want 2/1", resp.UserID, resp.SiteID)
	}
}

// TestWidgetSessionAdminAnonymous 回归匿名模式下管理员的 widget_authenticated 会话：
// 真实签名的 WT 配合 CHIPS cookie 与允许的 Origin 在匿名模式下立即返回 valid:true。
func TestWidgetSessionAdminAnonymous(t *testing.T) {
	router, signer, siteID := buildWidgetSessionRouter(t, domain.CommentModeAnonymous, domain.RoleAdmin, domain.UserStatusActive)
	token, err := signer.SignWidget(2, siteID, jwt.TokenKindWidgetAuthenticated, "1")
	if err != nil {
		t.Fatalf("sign widget token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/widget/session", nil)
	req.Header.Set("Origin", testWidgetOrigin)
	req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp WidgetSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("valid = false, want true; body=%s", rec.Body.String())
	}
	if resp.CredentialMode != domain.CommentModeAuthenticated {
		t.Fatalf("credential_mode = %q, want authenticated", resp.CredentialMode)
	}
}

// TestWidgetSessionGenericInvalid 验证失败路径始终返回不敏感的 {"valid":false}：
// 匿名模式下普通用户持有凭据、模式匹配但代次不匹配、以及非活跃主体。
func TestWidgetSessionGenericInvalid(t *testing.T) {
	tests := []struct {
		name   string
		mode   string
		role   domain.Role
		status domain.UserStatus
		epoch  string
	}{
		{name: "anonymous ordinary user", mode: domain.CommentModeAnonymous, role: domain.RoleUser, status: domain.UserStatusActive, epoch: "1"},
		{name: "stale epoch", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, status: domain.UserStatusActive, epoch: "2"},
		{name: "disabled principal", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, status: domain.UserStatusDisabled, epoch: "1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, signer, siteID := buildWidgetSessionRouter(t, tt.mode, tt.role, tt.status)
			token, err := signer.SignWidget(2, siteID, jwt.TokenKindWidgetAuthenticated, tt.epoch)
			if err != nil {
				t.Fatalf("sign widget token: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/api/v1/widget/session", nil)
			req.Header.Set("Origin", testWidgetOrigin)
			req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: token})
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			var resp WidgetSessionResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Valid {
				t.Fatalf("valid = true, want false; body=%s", rec.Body.String())
			}
			if resp.CredentialMode != "" || resp.UserID != "" || resp.SiteID != "" {
				t.Fatalf("generic invalid response leaked fields: %s", rec.Body.String())
			}
		})
	}
}

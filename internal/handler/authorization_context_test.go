package handler

import (
	"context"
	"encoding/json"
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
	"furtalk/internal/platform/httpx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"furtalk/internal/service/site"
	"github.com/gin-gonic/gin"
)

// authenticatedPolicyReader 返回认证模式的评论策略，供授权上下文测试使用。
type authenticatedPolicyReader struct{}

func (authenticatedPolicyReader) CommentPolicy(context.Context) (domain.CommentPolicy, error) {
	return domain.CommentPolicy{
		Mode:           domain.CommentModeAuthenticated,
		Epoch:          1,
		Moderation:     domain.ModerationDirect,
		UserDeleteMode: domain.UserDeleteModeSoft,
		MaxReplyDepth:  5,
		CaptchaPolicy:  map[string]bool{},
		Privacy:        domain.PrivacyPolicy{IPMode: "none", UAMode: "none"},
		CommentSort:    string(domain.CommentSortAsc),
	}, nil
}

// newAuthorizationContextRouter 构建挂载授权上下文端点的认证模式测试引擎。
func newAuthorizationContextRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "authorization-context.db")
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
	created, err := sitesService.Create(context.Background(), "Site", "https://site.example")
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := sitesService.AddOrigin(context.Background(), created.ID, "https://site.example"); err != nil {
		t.Fatalf("add origin: %v", err)
	}

	svc := comment.NewService(comment.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    siteRepo,
		Users:    repository.NewUserRepo(db),
		Settings: authenticatedPolicyReader{},
		UserW:    testUserWriter{},
		Authz:    testPrincipalStore{},
		Signer:   &testSigner{},
		Verifier: testVerifier{},
		Logger:   nil,
	})
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: time.Hour,
	})
	router := gin.New()
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router.Use(httpx.ErrorWriter(translator))
	router.Use(middleware.JWTVerification(signer))
	router.Use(middleware.PrincipalResolution(testPrincipalStore{}))
	RegisterFirstPartyCommentAuthorizationWithAdmission(router.Group("/api/v1"), svc, testUserGate{}, nil)
	return router
}

// getAuthorizationContext 向授权上下文端点发起 GET。
func getAuthorizationContext(router *gin.Engine, login *http.Cookie, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if login != nil {
		request.AddCookie(login)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

// TestAuthorizationContextReturnsReadOnlyMetadata 验证授权上下文只返回
// {site_id, site_name, origin} 且不创建授权记录（响应后无法消费任何 code）。
func TestAuthorizationContextReturnsReadOnlyMetadata(t *testing.T) {
	router := newAuthorizationContextRouter(t)
	login := firstPartyCookie(t)

	rec := getAuthorizationContext(router, login, "/api/v1/comment-authorizations/context?site_id=1&origin=https://site.example")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp AuthorizationContextResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SiteID != "1" || resp.SiteName != "Site" || resp.Origin != "https://site.example" {
		t.Fatalf("response = %+v", resp)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

// TestAuthorizationContextRequiresLogin 验证未认证请求返回 401。
func TestAuthorizationContextRequiresLogin(t *testing.T) {
	router := newAuthorizationContextRouter(t)
	rec := getAuthorizationContext(router, nil, "/api/v1/comment-authorizations/context?site_id=1&origin=https://site.example")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAuthorizationContextRejectsUnlistedOrigin 验证结构合法但不在白名单的
// origin 返回 403；结构非法的 origin 在解析阶段返回 422。
func TestAuthorizationContextRejectsUnlistedOrigin(t *testing.T) {
	router := newAuthorizationContextRouter(t)
	login := firstPartyCookie(t)
	for _, origin := range []string{"https://evil.example", "https://site.example.evil.example"} {
		rec := getAuthorizationContext(router, login, "/api/v1/comment-authorizations/context?site_id=1&origin="+origin)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("origin=%q status = %d, want 403; body=%s", origin, rec.Code, rec.Body.String())
		}
	}
	for _, origin := range []string{"https://site.example/path", "null", "*"} {
		rec := getAuthorizationContext(router, login, "/api/v1/comment-authorizations/context?site_id=1&origin="+origin)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("origin=%q status = %d, want 422; body=%s", origin, rec.Code, rec.Body.String())
		}
	}
}

// TestAuthorizationContextRejectsInAnonymousMode 验证匿名模式下返回 403，
// 与签发端点保持相同的模式门禁。
func TestAuthorizationContextRejectsInAnonymousMode(t *testing.T) {
	service, _, _, principals, userGate, _ := buildWidgetTestService(t)
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: time.Hour,
	})
	router := gin.New()
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router.Use(httpx.ErrorWriter(translator))
	router.Use(middleware.JWTVerification(signer))
	router.Use(middleware.PrincipalResolution(principals))
	RegisterFirstPartyCommentAuthorizationWithAdmission(router.Group("/api/v1"), service, userGate, nil)
	login := firstPartyCookie(t)

	rec := getAuthorizationContext(router, login, "/api/v1/comment-authorizations/context?site_id=1&origin=https://site.example")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 in anonymous mode; body=%s", rec.Code, rec.Body.String())
	}
}

// TestRuntimeConfigResponseShape 验证运行时配置响应 DTO 的 JSON 结构与 omitempty 行为。
func TestRuntimeConfigResponseShape(t *testing.T) {
	resp := toRuntimeConfigResponse(&comment.RuntimeConfig{
		SiteID:          1,
		Name:            "Site",
		CommentMode:     domain.CommentModeAuthenticated,
		Moderation:      domain.ModerationDirect,
		UserDeleteMode:  domain.UserDeleteModeSoft,
		MaxReplyDepth:   5,
		CommentSort:     string(domain.CommentSortAsc),
		EmojiCatalogURL: "https://cdn.example/emoji.json?signature=abc",
		Captcha: &comment.RuntimeCaptcha{
			Comment: &comment.CaptchaProjection{
				Required:    true,
				Provider:    "cap",
				SiteKey:     "cap-site",
				APIEndpoint: "https://cap.example.com/cap-site/",
			},
		},
	})
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		`"required":true`,
		`"provider":"cap"`,
		`"site_key":"cap-site"`,
		`"api_endpoint":"https://cap.example.com/cap-site/"`,
		`"comment"`,
		`"comment_sort":"asc"`,
		`"emoji_catalog_url":"https://cdn.example/emoji.json?signature=abc"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "anonymous_session") {
		t.Fatalf("response leaked removed anonymous_session action: %s", body)
	}
	if strings.Contains(body, "secret") {
		t.Fatalf("response leaked a secret: %s", body)
	}
}

// TestRuntimeConfigResponseOmitsEmptyCatalog 验证未配置 emoji_catalog_url 时
// 公开响应通过 omitempty 省略该字段，保持与旧后端/旧 Widget 兼容。
func TestRuntimeConfigResponseOmitsEmptyCatalog(t *testing.T) {
	resp := toRuntimeConfigResponse(&comment.RuntimeConfig{
		SiteID:         1,
		Name:           "Site",
		CommentMode:    domain.CommentModeAnonymous,
		Moderation:     domain.ModerationDirect,
		UserDeleteMode: domain.UserDeleteModeSoft,
		MaxReplyDepth:  3,
		CommentSort:    string(domain.CommentSortAsc),
	})
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "emoji_catalog_url") {
		t.Fatalf("response leaked empty emoji_catalog_url: %s", raw)
	}
}

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
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
	"furtalk/internal/service/site"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// buildWidgetLikeService 构建认证模式的 widget 测试装配，使活跃用户凭证可通过角色矩阵。
func buildWidgetLikeService(t *testing.T) (*comment.Service, comment.WidgetCredentialVerifier, comment.WidgetSettingsReader, middleware.PrincipalStore, middleware.UserGate, httpxOrigins, *gorm.DB) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "widget-like.db")
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
		Settings: likePolicyReader{mode: domain.CommentModeAuthenticated},
		UserW:    testUserWriter{},
		Authz:    likePrincipalStore{},
		Signer:   &testSigner{},
		Verifier: testVerifier{},
		Logger:   nil,
	})
	return svc, testVerifier{}, likeSettingsReader{}, likePrincipalStore{}, testUserGate{}, origins, db
}

type likePolicyReader struct{ mode string }

func (r likePolicyReader) CommentPolicy(context.Context) (domain.CommentPolicy, error) {
	return domain.CommentPolicy{
		Mode:           r.mode,
		Epoch:          1,
		Moderation:     domain.ModerationDirect,
		UserDeleteMode: domain.UserDeleteModeSoft,
		MaxReplyDepth:  3,
		CaptchaPolicy:  map[string]bool{},
		Privacy:        domain.PrivacyPolicy{IPMode: "none", UAMode: "none"},
		CommentSort:    string(domain.CommentSortAsc),
	}, nil
}

type likeSettingsReader struct{}

func (likeSettingsReader) WidgetConfig(context.Context) (string, int64, error) {
	return domain.CommentModeAuthenticated, 1, nil
}

type likePrincipalStore struct{}

func (likePrincipalStore) Resolve(context.Context, int64) (domain.Principal, error) {
	return domain.Principal{UserID: 1, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 1}, nil
}

// seedWidgetPublishedComment 为 widget 测试装配插入一条已发布评论，返回 comment_id。
func seedWidgetPublishedComment(t *testing.T, db *gorm.DB, svc *comment.Service, siteID int64) (threadID, commentID int64) {
	t.Helper()
	user := &domain.User{Email: "w@example.com", EmailNormalized: "w@example.com", Nickname: "w", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := repository.NewUserRepo(db).Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	thread, err := repository.NewThreadRepo(db).ResolveOrCreate(context.Background(), siteID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	c := &domain.Comment{
		SiteID: siteID, ThreadID: thread.ID, UserID: user.ID, Depth: 0,
		BodyMarkdown: "hi", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now, PublishedAt: &now,
	}
	if err := repository.NewCommentRepo(db).Create(context.Background(), c); err != nil {
		t.Fatalf("create comment: %v", err)
	}
	return thread.ID, c.ID
}

// TestWidgetLikeRoutesIdempotent 验证 PUT/DELETE Like 路由返回权威 DTO 且幂等。
func TestWidgetLikeRoutesIdempotent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins, db := buildWidgetLikeService(t)
	_, commentID := seedWidgetPublishedComment(t, db, service, 1)
	router := likeRouter(service, verifier, settings, principals, origins)

	do := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Origin", testWidgetOrigin)
		req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	path := "/api/v1/widget/sites/1/comments/" + formatDecimal(commentID) + "/like"

	rec := do(http.MethodPut, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var res LikeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.CommentID != formatDecimal(commentID) || res.LikeCount != 1 || !res.Liked {
		t.Fatalf("like resp = %+v", res)
	}
	// 重复 PUT 幂等
	rec = do(http.MethodPut, path)
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.LikeCount != 1 || !res.Liked {
		t.Fatalf("repeat put resp = %+v", res)
	}
	// DELETE
	rec = do(http.MethodDelete, path)
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.LikeCount != 0 || res.Liked {
		t.Fatalf("delete resp = %+v", res)
	}
	// 重复 DELETE 幂等且不为负
	rec = do(http.MethodDelete, path)
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.LikeCount != 0 || res.Liked {
		t.Fatalf("repeat delete resp = %+v", res)
	}
}

// TestWidgetLikeRoutesRequireCredential 验证缺少凭证返回 401，未知评论返回 404。
func TestWidgetLikeRoutesRequireCredential(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins, db := buildWidgetLikeService(t)
	_, commentID := seedWidgetPublishedComment(t, db, service, 1)
	router := likeRouter(service, verifier, settings, principals, origins)

	path := "/api/v1/widget/sites/1/comments/" + formatDecimal(commentID) + "/like"
	// 无 cookie → 401
	req := httptest.NewRequest(http.MethodPut, path, nil)
	req.Header.Set("Origin", testWidgetOrigin)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-cookie status = %d, want 401", rec.Code)
	}
	// 未知评论 → 404
	req = httptest.NewRequest(http.MethodPut, "/api/v1/widget/sites/1/comments/99999/like", nil)
	req.Header.Set("Origin", testWidgetOrigin)
	req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown-comment status = %d, want 404", rec.Code)
	}
	// 跨站点凭证 → 403（凭证 site_id=1 但路径 site=2）
	req = httptest.NewRequest(http.MethodPut, "/api/v1/widget/sites/2/comments/"+formatDecimal(commentID)+"/like", nil)
	req.Header.Set("Origin", testWidgetOrigin)
	req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site status = %d, want 403", rec.Code)
	}
}

// TestWidgetListCommentsViewerState 验证公开列表携带查看者点赞状态，匿名恒 false。
func TestWidgetListCommentsViewerState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins, db := buildWidgetLikeService(t)
	_, commentID := seedWidgetPublishedComment(t, db, service, 1)
	router := likeRouter(service, verifier, settings, principals, origins)

	likePath := "/api/v1/widget/sites/1/comments/" + formatDecimal(commentID) + "/like"
	// 先以凭证点赞
	req := httptest.NewRequest(http.MethodPut, likePath, nil)
	req.Header.Set("Origin", testWidgetOrigin)
	req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("like status = %d", rec.Code)
	}
	// 匿名读取：liked_by_me false，like_count 1
	anon := httptest.NewRequest(http.MethodGet, "/api/v1/widget/sites/1/comments?page_key=page-key", nil)
	anon.Header.Set("Origin", testWidgetOrigin)
	recAnon := httptest.NewRecorder()
	router.ServeHTTP(recAnon, anon)
	if recAnon.Code != http.StatusOK {
		t.Fatalf("anon read status = %d", recAnon.Code)
	}
	assertCommentLikeState(t, recAnon.Body.String(), commentID, 1, false)
	// 带凭证读取：liked_by_me true
	authed := httptest.NewRequest(http.MethodGet, "/api/v1/widget/sites/1/comments?page_key=page-key", nil)
	authed.Header.Set("Origin", testWidgetOrigin)
	authed.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})
	recAuthed := httptest.NewRecorder()
	router.ServeHTTP(recAuthed, authed)
	if recAuthed.Code != http.StatusOK {
		t.Fatalf("authed read status = %d", recAuthed.Code)
	}
	assertCommentLikeState(t, recAuthed.Body.String(), commentID, 1, true)
}

// assertCommentLikeState 解析线程评论响应并断言指定评论的 Like 状态。
func assertCommentLikeState(t *testing.T, body string, commentID int64, count int64, liked bool) {
	t.Helper()
	var resp ThreadCommentsResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode thread response: %v", err)
	}
	target := formatDecimal(commentID)
	for _, c := range resp.Comments {
		if c.ID != target {
			continue
		}
		if c.LikeCount != count || c.LikedByMe != liked {
			t.Fatalf("comment like state = count %d liked %v, want count %d liked %v", c.LikeCount, c.LikedByMe, count, liked)
		}
		return
	}
	t.Fatalf("comment %s not found in response: %s", target, body)
}

// TestWidgetPreflightRegistersLikePaths 验证 Like 路由注册 OPTIONS 预检。
func TestWidgetPreflightRegistersLikePaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins, _ := buildWidgetLikeService(t)
	router := likeRouter(service, verifier, settings, principals, origins)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/widget/sites/1/comments/1/like", nil)
	req.Header.Set("Origin", testWidgetOrigin)
	req.Header.Set("Access-Control-Request-Method", "PUT")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, X-Request-ID")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
}

// TestWidgetLikeRoutesDisallowedOrigin 验证非白名单 Origin 在 handler 前被拒绝。
func TestWidgetLikeRoutesDisallowedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service, verifier, settings, principals, _, origins, _ := buildWidgetLikeService(t)
	router := likeRouter(service, verifier, settings, principals, origins)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/widget/sites/1/comments/1/like", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed origin status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// likeRouter 构建带错误翻译器的 widget 路由器。
func likeRouter(service *comment.Service, verifier comment.WidgetCredentialVerifier, settings comment.WidgetSettingsReader, principals middleware.PrincipalStore, origins httpxOrigins) *gin.Engine {
	translator, err := NewTranslator()
	if err != nil {
		panic(err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	RegisterWidget(router.Group("/api/v1"), service, verifier, settings, principals, origins)
	return router
}

// formatDecimal 把 int64 格式化为十进制字符串。
func formatDecimal(id int64) string {
	return strconv.FormatInt(id, 10)
}

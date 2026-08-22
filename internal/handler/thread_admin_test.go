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

// testAdminGate 校验主体是否为活跃管理员。
type testAdminGate struct{}

func (testAdminGate) RequireAdmin(_ context.Context, p domain.Principal) error {
	if p.Role != domain.RoleAdmin || p.Status != domain.UserStatusActive {
		return domain.ErrForbidden
	}
	return nil
}

// threadHandlerEnv 聚合线程管理与 widget 端点所需的服务与数据库。
type threadHandlerEnv struct {
	svc        *comment.Service
	db         *gorm.DB
	sites      *site.Service
	verifier   comment.WidgetCredentialVerifier
	settings   comment.WidgetSettingsReader
	principals middleware.PrincipalStore
	origins    httpxOrigins
}

// newThreadHandlerEnv 装配真实 SQLite 仓储的服务与站点服务。
func newThreadHandlerEnv(t *testing.T) *threadHandlerEnv {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "handler-thread-test.db")
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
	svc := comment.NewService(comment.Dependencies{
		TxRunner: gormtx.NewRunner(db),
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
	return &threadHandlerEnv{
		svc:        svc,
		db:         db,
		sites:      sitesService,
		verifier:   testVerifier{},
		settings:   testSettingsReader{},
		principals: testPrincipalStore{},
		origins:    httpxOrigins{svc: sitesService},
	}
}

// seedAdminThreadFixture 插入一个站点与若干线程，返回站点与线程 ID。
func seedAdminThreadFixture(t *testing.T, env *threadHandlerEnv) (siteID int64, threadID int64) {
	t.Helper()
	ctx := context.Background()
	s, err := env.sites.Create(ctx, "Site", "https://site.example")
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := env.sites.AddOrigin(ctx, s.ID, "https://site.example"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	repo := repository.NewThreadRepo(env.db)
	open, err := repo.ResolveOrCreate(ctx, s.ID, "open-page", nil, nil)
	if err != nil {
		t.Fatalf("create open thread: %v", err)
	}
	closed, err := repo.ResolveOrCreate(ctx, s.ID, "closed-page", nil, nil)
	if err != nil {
		t.Fatalf("create closed thread: %v", err)
	}
	if _, err := repo.UpdateCommentsEnabled(ctx, s.ID, closed.ID, false); err != nil {
		t.Fatalf("close thread: %v", err)
	}
	return s.ID, open.ID
}

// threadAdminRouter 装配含管理员门禁与 CSRF 的线程管理路由。
func threadAdminRouter(t *testing.T, svc *comment.Service) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	admin := router.Group("/api/v1/admin", adminPrincipal, middleware.RequireAdmin(testAdminGate{}), middleware.CSRFProtection())
	RegisterAdminThreads(admin, svc)
	return router
}

// widgetRouter 装配带错误翻译器的 widget 路由。
func widgetRouter(t *testing.T, env *threadHandlerEnv) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	RegisterWidget(router.Group("/api/v1"), env.svc, env.verifier, env.settings, env.principals, env.origins)
	return router
}

// TestAdminThreadsListReturnsSiteScopedView 验证列表返回站点名、十进制 ID、
// comments_enabled 与时间戳，且只含目标站点的线程。
func TestAdminThreadsListReturnsSiteScopedView(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites/"+itoa(siteID)+"/threads", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp AdminThreadListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Threads) != 2 {
		t.Fatalf("threads = %d, want 2", len(resp.Threads))
	}
	for _, tr := range resp.Threads {
		if tr.SiteName != "Site" {
			t.Fatalf("site_name = %q, want Site", tr.SiteName)
		}
		if tr.SiteID != itoa(siteID) {
			t.Fatalf("site_id = %q, want %q", tr.SiteID, itoa(siteID))
		}
		if tr.ID == "" {
			t.Fatalf("thread id is empty, want decimal string")
		}
	}
	closed := 0
	for _, tr := range resp.Threads {
		if tr.PageKey == "closed-page" && tr.CommentsEnabled {
			t.Fatal("closed-page must have comments_enabled=false")
		}
		if tr.PageKey == "closed-page" {
			closed++
		}
	}
	if closed != 1 {
		t.Fatalf("closed-page rows = %d, want 1", closed)
	}
}

// TestAdminThreadsListFiltersByEnabled 验证 comments_enabled 过滤生效。
func TestAdminThreadsListFiltersByEnabled(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites/"+itoa(siteID)+"/threads?comments_enabled=false", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp AdminThreadListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Threads) != 1 || resp.Threads[0].PageKey != "closed-page" {
		t.Fatalf("filtered threads = %+v, want only closed-page", resp.Threads)
	}
}

// TestAdminThreadsListRejectsBadBoolean 验证非法布尔查询参数返回 400。
func TestAdminThreadsListRejectsBadBoolean(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites/"+itoa(siteID)+"/threads?comments_enabled=banana", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminThreadsListAcceptsSortDirection 验证管理线程列表接受受控 sort
// 参数：asc/desc 均返回 200，缺省等价 desc，非法值返回 422。
func TestAdminThreadsListAcceptsSortDirection(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	for _, sort := range []string{"asc", "desc"} {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites/"+itoa(siteID)+"/threads?sort="+sort, nil)
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusOK {
			t.Fatalf("sort=%s status = %d, want 200; body=%s", sort, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites/"+itoa(siteID)+"/threads?sort=sideways", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid sort status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"invalid_input"`) {
		t.Fatalf("invalid sort body = %s, want code invalid_input", rec.Body.String())
	}
}

// TestAdminThreadsListPageAndTotal 验证页码分页生效、返回真实 total，且响应不含游标。
func TestAdminThreadsListPageAndTotal(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	repo := repository.NewThreadRepo(env.db)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := repo.ResolveOrCreate(ctx, siteID, "extra-"+strconv.Itoa(i), nil, nil); err != nil {
			t.Fatalf("create extra thread %d: %v", i, err)
		}
	}
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites/"+itoa(siteID)+"/threads?limit=3&page=2", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("page 2 status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"next_cursor"`) {
		t.Fatalf("response still exposes next_cursor: %s", rec.Body.String())
	}
	var resp AdminThreadListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if len(resp.Threads) != 2 || resp.Total != 5 {
		t.Fatalf("page 2 = %d threads total=%d, want 2 + total 5", len(resp.Threads), resp.Total)
	}
}

// TestAdminThreadsListRejectsInvalidPage 验证非正整数页码返回参数错误。
func TestAdminThreadsListRejectsInvalidPage(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)
	for _, page := range []string{"0", "-1", "abc", "1.5"} {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites/"+itoa(siteID)+"/threads?page="+page, nil)
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("page=%s status = %d, want 400; body=%s", page, rec.Code, rec.Body.String())
		}
	}
}

// TestAdminThreadsPatchTogglesState 验证 PATCH 可切换开关并返回完整视图。
func TestAdminThreadsPatchTogglesState(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	toggle := func(wantEnabled bool) {
		t.Helper()
		body := `{"comments_enabled":false}`
		if wantEnabled {
			body = `{"comments_enabled":true}`
		}
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
		request.Header.Set(middleware.CSRFHeaderName, csrf)
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		var resp AdminThreadResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.CommentsEnabled != wantEnabled {
			t.Fatalf("comments_enabled = %v, want %v", resp.CommentsEnabled, wantEnabled)
		}
		if resp.ID != itoa(threadID) {
			t.Fatalf("thread id = %q, want %q", resp.ID, itoa(threadID))
		}
	}

	toggle(false)
	toggle(true)
	toggle(false)
}

// TestAdminThreadsPatchRequiresCSRF 验证无 CSRF 的 PATCH 被拒绝。
func TestAdminThreadsPatchRequiresCSRF(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), strings.NewReader(`{"comments_enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"invalid_csrf_token"`) {
		t.Fatalf("status = %d %s, want 403 invalid_csrf_token", rec.Code, rec.Body.String())
	}
}

// TestAdminThreadsPatchRequiresField 验证省略全部更新字段返回 422。
func TestAdminThreadsPatchRequiresField(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminThreadsPatchEditsMetadata 验证 PATCH 可独立或组合编辑 page_key 与
// page_title，并稳定保留线程 ID。
func TestAdminThreadsPatchEditsMetadata(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	do := func(body string) AdminThreadResponse {
		t.Helper()
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
		request.Header.Set(middleware.CSRFHeaderName, csrf)
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		var resp AdminThreadResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.ID != itoa(threadID) {
			t.Fatalf("thread id = %q, want stable %q", resp.ID, itoa(threadID))
		}
		return resp
	}

	keyOnly := do(`{"page_key":"renamed-key"}`)
	if keyOnly.PageKey != "renamed-key" {
		t.Fatalf("page_key = %q, want renamed-key", keyOnly.PageKey)
	}

	titleOnly := do(`{"page_title":"New Title"}`)
	if titleOnly.PageTitle == nil || *titleOnly.PageTitle != "New Title" {
		t.Fatalf("page_title = %v, want New Title", titleOnly.PageTitle)
	}

	clearTitle := do(`{"page_title":null}`)
	if clearTitle.PageTitle != nil {
		t.Fatalf("page_title must be cleared, got %v", *clearTitle.PageTitle)
	}

	combo := do(`{"page_key":"combo","page_title":"Combo Title","comments_enabled":false}`)
	if combo.PageKey != "combo" || combo.PageTitle == nil || *combo.PageTitle != "Combo Title" || combo.CommentsEnabled {
		t.Fatalf("combo update = %+v", combo)
	}

	urlOnly := do(`{"page_url":"  https://site.example/renamed  "}`)
	if urlOnly.PageURL == nil || *urlOnly.PageURL != "https://site.example/renamed" {
		t.Fatalf("page_url = %v, want trimmed absolute url", urlOnly.PageURL)
	}

	clearURL := do(`{"page_url":null}`)
	if clearURL.PageURL != nil {
		t.Fatalf("page_url must be cleared, got %v", *clearURL.PageURL)
	}
}

// TestAdminThreadsPatchPageURLRejectsInvalid 验证非法 page_url 返回 422 且不落库。
func TestAdminThreadsPatchPageURLRejectsInvalid(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	for _, body := range []string{
		`{"page_url":"not-a-url"}`,
		`{"page_url":"ftp://example.com/x"}`,
		`{"page_url":"https://"}`,
		`{"page_url":"//example.com/x"}`,
	} {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
		request.Header.Set(middleware.CSRFHeaderName, csrf)
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("body %s status = %d, want 422; body=%s", body, rec.Code, rec.Body.String())
		}
	}
}

// TestAdminThreadsPatchDuplicateKeyConflict 验证 page_key 站点内重复返回 409。
func TestAdminThreadsPatchDuplicateKeyConflict(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), strings.NewReader(`{"page_key":"closed-page"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminThreadsPatchCrossSiteNotFound 验证跨站点 thread_id 返回 404。
func TestAdminThreadsPatchCrossSiteNotFound(t *testing.T) {
	env := newThreadHandlerEnv(t)
	_, threadID := seedAdminThreadFixture(t, env)
	other, err := env.sites.Create(context.Background(), "Other", "https://other.example")
	if err != nil {
		t.Fatalf("create other site: %v", err)
	}
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/sites/"+itoa(other.ID)+"/threads/"+itoa(threadID), strings.NewReader(`{"comments_enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminThreadsRejectNonAdmin 验证非管理员主体访问线程端点被拒绝。
func TestAdminThreadsRejectNonAdmin(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	gin.SetMode(gin.TestMode)
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	user := func(c *gin.Context) {
		c.Set("current_principal", domain.Principal{UserID: 1, Role: domain.RoleUser, Status: domain.UserStatusActive})
		c.Next()
	}
	admin := router.Group("/api/v1/admin", user, middleware.RequireAdmin(testAdminGate{}), middleware.CSRFProtection())
	RegisterAdminThreads(admin, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites/"+itoa(siteID)+"/threads", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), strings.NewReader(`{"comments_enabled":false}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	req2.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("patch status = %d, want 403; body=%s", rec2.Code, rec2.Body.String())
	}
}

// TestWidgetListCommentsReturnsCommentsEnabled 验证公开 widget 读取返回
// comments_enabled 状态且关闭线程历史仍可读。
func TestWidgetListCommentsReturnsCommentsEnabled(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	router := widgetRouter(t, env)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/widget/sites/"+itoa(siteID)+"/comments?page_key=closed-page", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp ThreadCommentsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Thread.CommentsEnabled {
		t.Fatal("comments_enabled = true, want false for closed thread")
	}
	if len(resp.Comments) != 0 {
		t.Fatalf("comments = %d, want 0", len(resp.Comments))
	}

	// 关闭线程不允许新增：验证码策略关闭时仍返回稳定错误 thread_closed。
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/widget/sites/"+itoa(siteID)+"/comments", strings.NewReader(`{"page_key":"closed-page","body_markdown":"x","email":"a@example.com","nickname":"a"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Origin", "https://site.example")
	req2.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("create status = %d, want 409; body=%s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), `"code":"thread_closed"`) {
		t.Fatalf("create body = %s, want code thread_closed", rec2.Body.String())
	}
}

// TestWidgetListCommentsRequiresPageKey 验证公开读取要求有效的 page_key。
func TestWidgetListCommentsRequiresPageKey(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	router := widgetRouter(t, env)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/widget/sites/"+itoa(siteID)+"/comments", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

// TestWidgetListCommentsAcceptsSortDirection 验证公开读取接受受控 sort 参数，
// asc/desc 均返回 200，非法值返回 422 且不创建线程。
func TestWidgetListCommentsAcceptsSortDirection(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, _ := seedAdminThreadFixture(t, env)
	router := widgetRouter(t, env)

	for _, sort := range []string{"asc", "desc"} {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/widget/sites/"+itoa(siteID)+"/comments?page_key=open-page&sort="+sort, nil)
		router.ServeHTTP(rec, request)
		if rec.Code != http.StatusOK {
			t.Fatalf("sort=%s status = %d, want 200; body=%s", sort, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/widget/sites/"+itoa(siteID)+"/comments?page_key=open-page&sort=sideways", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid sort status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"invalid_input"`) {
		t.Fatalf("invalid sort body = %s, want code invalid_input", rec.Body.String())
	}
}

// TestWidgetListCommentsNoModifyEndpoint 验证公开 widget 路由不暴露修改开关的端点。
func TestWidgetListCommentsNoModifyEndpoint(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := widgetRouter(t, env)

	// 公开路由下尝试切换开关的 PATCH 应 404（路由不存在）。
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/widget/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), strings.NewReader(`{"comments_enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no public modify endpoint); body=%s", rec.Code, rec.Body.String())
	}
}

// itoa 把 int64 转为十进制字符串。
func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

// seedAdminThreadCommentFixture 在种子线程下插入一条评论，供级联删除断言。
func seedAdminThreadCommentFixture(t *testing.T, env *threadHandlerEnv, siteID, threadID int64) int64 {
	t.Helper()
	ctx := context.Background()
	user := &domain.User{Email: "c@example.com", EmailNormalized: "c@example.com", Nickname: "c", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := repository.NewUserRepo(env.db).Create(ctx, user); err != nil {
		t.Fatalf("create comment user: %v", err)
	}
	comment := &domain.Comment{
		SiteID: siteID, ThreadID: threadID, UserID: user.ID, Depth: 0,
		BodyMarkdown: "body", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
	}
	if err := repository.NewCommentRepo(env.db).Create(ctx, comment); err != nil {
		t.Fatalf("create comment: %v", err)
	}
	return comment.ID
}

// TestAdminThreadsDeleteHardDeletesThread 验证 DELETE + confirm 删除线程，
// 且其下评论被级联删除，其他线程保留。
func TestAdminThreadsDeleteHardDeletesThread(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	seedAdminThreadCommentFixture(t, env, siteID, threadID)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID)+"?confirm=true", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	if _, err := repository.NewThreadRepo(env.db).GetBySiteAndID(context.Background(), siteID, threadID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("thread must be gone, got err=%v", err)
	}
	var comments int64
	if err := env.db.Model(&model.Comment{}).Where("site_id = ? AND thread_id = ?", siteID, threadID).Count(&comments).Error; err != nil {
		t.Fatalf("count comments: %v", err)
	}
	if comments != 0 {
		t.Fatalf("comments = %d, want 0 (cascade failed)", comments)
	}
	// 另一条线程（closed-page）保留。
	var remaining int64
	if err := env.db.Model(&model.Thread{}).Where("site_id = ?", siteID).Count(&remaining).Error; err != nil {
		t.Fatalf("count remaining threads: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining threads = %d, want 1", remaining)
	}
}

// TestAdminThreadsDeleteRequiresConfirm 验证缺 confirm 返回 422 且线程保留。
func TestAdminThreadsDeleteRequiresConfirm(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID), nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := repository.NewThreadRepo(env.db).GetBySiteAndID(context.Background(), siteID, threadID); err != nil {
		t.Fatalf("thread must survive without confirm: %v", err)
	}
}

// TestAdminThreadsDeleteCrossSiteNotFound 验证跨站点 thread_id 返回 404。
func TestAdminThreadsDeleteCrossSiteNotFound(t *testing.T) {
	env := newThreadHandlerEnv(t)
	_, threadID := seedAdminThreadFixture(t, env)
	other, err := env.sites.Create(context.Background(), "Other", "https://other.example")
	if err != nil {
		t.Fatalf("create other site: %v", err)
	}
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/sites/"+itoa(other.ID)+"/threads/"+itoa(threadID)+"?confirm=true", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := repository.NewThreadRepo(env.db).GetBySiteAndID(context.Background(), other.ID, threadID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("thread must stay missing: %v", err)
	}
}

// TestAdminThreadsDeleteRequiresCSRF 验证无 CSRF 的 DELETE 被拒绝。
func TestAdminThreadsDeleteRequiresCSRF(t *testing.T) {
	env := newThreadHandlerEnv(t)
	siteID, threadID := seedAdminThreadFixture(t, env)
	router := threadAdminRouter(t, env.svc)

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/sites/"+itoa(siteID)+"/threads/"+itoa(threadID)+"?confirm=true", nil)
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"invalid_csrf_token"`) {
		t.Fatalf("status = %d %s, want 403 invalid_csrf_token", rec.Code, rec.Body.String())
	}
}

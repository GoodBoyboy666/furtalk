package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/site"
	"github.com/gin-gonic/gin"
)

func setupLatestWidgetTest(t *testing.T) (*gin.Engine, *repository.CommentRepo, *repository.ThreadRepo, *repository.UserRepo, *domain.Site, *domain.Site) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dsn := filepath.Join(t.TempDir(), "widget-latest.db")
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
	threadRepo := repository.NewThreadRepo(db)
	commentRepo := repository.NewCommentRepo(db)
	userRepo := repository.NewUserRepo(db)

	sitesService := site.NewService(siteRepo)
	activeSite, err := sitesService.Create(context.Background(), "Active Site", testWidgetOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sitesService.AddOrigin(context.Background(), activeSite.ID, testWidgetOrigin); err != nil {
		t.Fatal(err)
	}

	disabledSite := &domain.Site{Name: "Disabled Site", CanonicalURL: "https://disabled.example", Status: domain.SiteStatusDisabled}
	if err := siteRepo.Create(context.Background(), disabledSite); err != nil {
		t.Fatal(err)
	}

	origins := httpxOrigins{svc: sitesService}

	svc := comment.NewService(comment.Dependencies{
		TxRunner: runner,
		Threads:  threadRepo,
		Comments: commentRepo,
		Sites:    siteRepo,
		Users:    userRepo,
		Settings: testPolicyReader{},
		UserW:    testUserWriter{},
		Authz:    testPrincipalStore{},
		Signer:   &testSigner{},
		Verifier: testVerifier{},
		Logger:   nil,
	})

	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}

	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	RegisterWidget(router.Group("/api/v1"), svc, testVerifier{}, testSettingsReader{}, testPrincipalStore{}, origins)

	return router, commentRepo, threadRepo, userRepo, activeSite, disabledSite
}

// TestWidgetListLatestComments_AnonymousNoAuthNoCSRF 验证无需登录、widget 凭据或 CSRF token，
// 即可获取按最新时间排序的公开评论列表及页面元数据。
func TestWidgetListLatestComments_AnonymousNoAuthNoCSRF(t *testing.T) {
	router, commentRepo, threadRepo, userRepo, activeSite, _ := setupLatestWidgetTest(t)
	ctx := context.Background()

	u1 := &domain.User{Email: "user1@example.com", EmailNormalized: "user1@example.com", Nickname: "Alice", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u1); err != nil {
		t.Fatal(err)
	}
	u2 := &domain.User{Email: "admin@example.com", EmailNormalized: "admin@example.com", Nickname: "AdminBob", Role: domain.RoleAdmin, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u2); err != nil {
		t.Fatal(err)
	}

	url1 := "https://site.example/posts/1"
	title1 := "Post 1"
	th1, err := threadRepo.ResolveOrCreate(ctx, activeSite.ID, "post-1", &url1, &title1)
	if err != nil {
		t.Fatal(err)
	}

	url2 := "https://site.example/posts/2"
	title2 := "Post 2"
	th2, err := threadRepo.ResolveOrCreate(ctx, activeSite.ID, "post-2", &url2, &title2)
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, time.August, 19, 10, 0, 0, 0, time.UTC)

	// c1: thread 1, Alice
	c1 := &domain.Comment{
		SiteID: activeSite.ID, ThreadID: th1.ID, UserID: u1.ID, Depth: 0,
		BodyMarkdown: "First comment", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: base, UpdatedAt: base, PublishedAt: &base,
	}
	if err := commentRepo.Create(ctx, c1); err != nil {
		t.Fatal(err)
	}

	// c2: thread 2, AdminBob replying to Alice
	t2 := base.Add(10 * time.Minute)
	c2 := &domain.Comment{
		SiteID: activeSite.ID, ThreadID: th2.ID, UserID: u2.ID, ReplyToUserID: &u1.ID, Depth: 1,
		BodyMarkdown: "Second comment", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: t2, UpdatedAt: t2, PublishedAt: &t2,
	}
	if err := commentRepo.Create(ctx, c2); err != nil {
		t.Fatal(err)
	}

	// Non-published comment should not appear
	tPending := base.Add(20 * time.Minute)
	cPending := &domain.Comment{
		SiteID: activeSite.ID, ThreadID: th1.ID, UserID: u1.ID, Depth: 0,
		BodyMarkdown: "Pending comment", Status: domain.CommentStatusPending,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: tPending, UpdatedAt: tPending,
	}
	if err := commentRepo.Create(ctx, cPending); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/widget/sites/%d/latest-comments", activeSite.ID), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp LatestCommentListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if len(resp.Comments) != 2 {
		t.Fatalf("expected 2 comments, got %d", len(resp.Comments))
	}

	// First is c2 (newest)
	if resp.Comments[0].ID != fmt.Sprintf("%d", c2.ID) {
		t.Errorf("expected resp.Comments[0].ID to be %d, got %s", c2.ID, resp.Comments[0].ID)
	}
	if resp.Comments[0].PageKey != "post-2" || *resp.Comments[0].PageURL != url2 || *resp.Comments[0].PageTitle != title2 {
		t.Errorf("resp.Comments[0] page metadata mismatch: %+v", resp.Comments[0])
	}
	if resp.Comments[0].AuthorNickname != "AdminBob" || resp.Comments[0].AuthorRole != "admin" {
		t.Errorf("resp.Comments[0] author mismatch: %+v", resp.Comments[0])
	}
	if resp.Comments[0].ReplyToNickname == nil || *resp.Comments[0].ReplyToNickname != "Alice" {
		t.Errorf("resp.Comments[0] reply_to_nickname mismatch: %+v", resp.Comments[0].ReplyToNickname)
	}

	// Second is c1
	if resp.Comments[1].ID != fmt.Sprintf("%d", c1.ID) {
		t.Errorf("expected resp.Comments[1].ID to be %d, got %s", c1.ID, resp.Comments[1].ID)
	}
	if resp.Comments[1].PageKey != "post-1" || *resp.Comments[1].PageURL != url1 || *resp.Comments[1].PageTitle != title1 {
		t.Errorf("resp.Comments[1] page metadata mismatch: %+v", resp.Comments[1])
	}
}

// TestWidgetListLatestComments_EmptyArray 验证没有评论时返回 {"comments": []} 而非 null。
func TestWidgetListLatestComments_EmptyArray(t *testing.T) {
	router, _, _, _, activeSite, _ := setupLatestWidgetTest(t)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/widget/sites/%d/latest-comments", activeSite.ID), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if body != `{"comments":[]}` {
		t.Fatalf("expected `{\"comments\":[]}`, got %s", body)
	}
}

// TestWidgetListLatestComments_LimitBoundaries 验证 limit 参数的默认值、上限收敛和异常值回落。
func TestWidgetListLatestComments_LimitBoundaries(t *testing.T) {
	router, commentRepo, threadRepo, userRepo, activeSite, _ := setupLatestWidgetTest(t)
	ctx := context.Background()

	u := &domain.User{Email: "u@example.com", EmailNormalized: "u@example.com", Nickname: "User", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	th, err := threadRepo.ResolveOrCreate(ctx, activeSite.ID, "p", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, time.August, 19, 10, 0, 0, 0, time.UTC)
	for i := 1; i <= 30; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		c := &domain.Comment{
			SiteID: activeSite.ID, ThreadID: th.ID, UserID: u.ID, Depth: 0,
			BodyMarkdown: fmt.Sprintf("comment %d", i), Status: domain.CommentStatusPublished,
			IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: ts, UpdatedAt: ts, PublishedAt: &ts,
		}
		if err := commentRepo.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name          string
		query         string
		expectedCount int
	}{
		{name: "default no limit", query: "", expectedCount: 25},
		{name: "over max limit 50", query: "?limit=50", expectedCount: 25},
		{name: "negative limit", query: "?limit=-10", expectedCount: 25},
		{name: "non-numeric limit", query: "?limit=abc", expectedCount: 25},
		{name: "zero limit", query: "?limit=0", expectedCount: 25},
		{name: "valid limit 5", query: "?limit=5", expectedCount: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/widget/sites/%d/latest-comments%s", activeSite.ID, tt.query), nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			var resp LatestCommentListResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(resp.Comments) != tt.expectedCount {
				t.Fatalf("expected %d comments, got %d", tt.expectedCount, len(resp.Comments))
			}
		})
	}
}

// TestWidgetListLatestComments_DTOAllowlistPrivacy 验证 JSON 响应严格遵循字段白名单，
// 绝不暴露邮箱、IP、UA、删除元数据或树结构字段。
func TestWidgetListLatestComments_DTOAllowlistPrivacy(t *testing.T) {
	router, commentRepo, threadRepo, userRepo, activeSite, _ := setupLatestWidgetTest(t)
	ctx := context.Background()

	u := &domain.User{Email: "secret@example.com", EmailNormalized: "secret@example.com", Nickname: "SecretUser", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	th, err := threadRepo.ResolveOrCreate(ctx, activeSite.ID, "p", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	base := time.Now().UTC()
	c := &domain.Comment{
		SiteID: activeSite.ID, ThreadID: th.ID, UserID: u.ID, Depth: 2,
		BodyMarkdown: "Public content", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeFull, IPValue: strPtr("1.2.3.4"),
		UAMode: domain.PrivacyModeFull, UARaw: strPtr("Mozilla/5.0"),
		CreatedAt: base, UpdatedAt: base, PublishedAt: &base,
	}
	if err := commentRepo.Create(ctx, c); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/widget/sites/%d/latest-comments", activeSite.ID), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	commentsList, ok := raw["comments"].([]any)
	if !ok || len(commentsList) == 0 {
		t.Fatalf("expected non-empty comments array")
	}

	firstItem, ok := commentsList[0].(map[string]any)
	if !ok {
		t.Fatalf("expected map for item")
	}

	forbiddenKeys := []string{
		"email", "author_email", "email_normalized", "author_email_normalized",
		"ip", "ip_mode", "ip_value",
		"ua", "ua_mode", "ua_raw", "ua_browser", "ua_os", "ua_device",
		"deleted_at", "status_before_delete",
		"parent_id", "root_id", "depth",
	}
	for _, key := range forbiddenKeys {
		if _, exists := firstItem[key]; exists {
			t.Errorf("forbidden key %q found in response JSON: %+v", key, firstItem)
		}
	}

	requiredKeys := []string{
		"id", "site_id", "thread_id", "page_key", "page_url", "page_title",
		"user_id", "body", "status", "author_nickname", "author_website",
		"author_role", "avatar_url", "reply_to_user_id", "reply_to_nickname",
		"created_at", "published_at",
	}
	for _, key := range requiredKeys {
		if _, exists := firstItem[key]; !exists {
			t.Errorf("required key %q missing in response JSON: %+v", key, firstItem)
		}
	}
}

// TestWidgetListLatestComments_CORS 验证 CORS 处理：精确配置的 Origin 获权，未配置 Origin 不获权，无 Origin 请求可正常读取。
func TestWidgetListLatestComments_CORS(t *testing.T) {
	router, _, _, _, activeSite, _ := setupLatestWidgetTest(t)

	// 1. Configured exact Origin -> returns CORS headers
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/widget/sites/%d/latest-comments", activeSite.ID), nil)
	req.Header.Set("Origin", testWidgetOrigin)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testWidgetOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, testWidgetOrigin)
	}

	// 2. Disallowed Origin -> does not return CORS header, but status is 200 (CORS is not auth for public GET)
	reqDisallowed := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/widget/sites/%d/latest-comments", activeSite.ID), nil)
	reqDisallowed.Header.Set("Origin", "https://disallowed.example")
	recDisallowed := httptest.NewRecorder()
	router.ServeHTTP(recDisallowed, reqDisallowed)

	if recDisallowed.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recDisallowed.Code)
	}
	if got := recDisallowed.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin for disallowed origin, got %q", got)
	}

	// 3. OPTIONS preflight
	reqOptions := httptest.NewRequest(http.MethodOptions, fmt.Sprintf("/api/v1/widget/sites/%d/latest-comments", activeSite.ID), nil)
	reqOptions.Header.Set("Origin", testWidgetOrigin)
	reqOptions.Header.Set("Access-Control-Request-Method", "GET")
	recOptions := httptest.NewRecorder()
	router.ServeHTTP(recOptions, reqOptions)

	if recOptions.Code != http.StatusNoContent && recOptions.Code != http.StatusOK {
		t.Fatalf("OPTIONS status = %d", recOptions.Code)
	}
	if got := recOptions.Header().Get("Access-Control-Allow-Origin"); got != testWidgetOrigin {
		t.Errorf("OPTIONS Access-Control-Allow-Origin = %q, want %q", got, testWidgetOrigin)
	}
}

// TestWidgetListLatestComments_Errors 验证无效站点、不存在站点与停用站点的错误语义。
func TestWidgetListLatestComments_Errors(t *testing.T) {
	router, _, _, _, _, disabledSite := setupLatestWidgetTest(t)

	// 1. Invalid site ID string -> 400 Bad Request
	reqInvalid := httptest.NewRequest(http.MethodGet, "/api/v1/widget/sites/invalid/latest-comments", nil)
	recInvalid := httptest.NewRecorder()
	router.ServeHTTP(recInvalid, reqInvalid)
	if recInvalid.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid site ID, got %d", recInvalid.Code)
	}

	// 2. Non-existent site -> 404 Not Found
	reqNotFound := httptest.NewRequest(http.MethodGet, "/api/v1/widget/sites/999999/latest-comments", nil)
	recNotFound := httptest.NewRecorder()
	router.ServeHTTP(recNotFound, reqNotFound)
	if recNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing site, got %d", recNotFound.Code)
	}

	// 3. Disabled site -> 403 Forbidden
	reqDisabled := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/widget/sites/%d/latest-comments", disabledSite.ID), nil)
	recDisabled := httptest.NewRecorder()
	router.ServeHTTP(recDisabled, reqDisabled)
	if recDisabled.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disabled site, got %d", recDisabled.Code)
	}
}

func strPtr(s string) *string {
	return &s
}

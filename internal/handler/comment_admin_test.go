package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/comment"
	"github.com/gin-gonic/gin"
)

// newAdminCommentsRouter 构建挂载 /api/v1/admin/comments 的测试引擎并
// 种子一个 pending 评论。返回 router、comment repo、评论 ID 与作者/站点 ID。
func newAdminCommentsRouter(t *testing.T) (*gin.Engine, *repository.CommentRepo, int64, int64, int64) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "admin-comments.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db,
		&model.User{}, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}, &model.Comment{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	runner := gormtx.NewRunner(db)
	svc := comment.NewService(comment.Dependencies{
		TxRunner: runner,
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    repository.NewSiteRepo(db),
		Users:    repository.NewUserRepo(db),
		Settings: testPolicyReader{},
		UserW:    testUserWriter{},
		Authz:    testPrincipalStore{},
		Signer:   &testSigner{},
		Verifier: testVerifier{},
		Logger:   nil,
	})

	router := gin.New()
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router.Use(httpx.ErrorWriter(translator))
	RegisterAdminComments(router.Group("/api/v1/admin"), svc)

	ctx := context.Background()
	userRepo := repository.NewUserRepo(db)
	user := &domain.User{
		Email: "admin@example.com", EmailNormalized: "admin@example.com",
		Nickname: "Admin", Role: domain.RoleAdmin, Status: domain.UserStatusActive,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	siteRepo := repository.NewSiteRepo(db)
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, site.ID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	commentRepo := repository.NewCommentRepo(db)
	row := &domain.Comment{
		SiteID: site.ID, ThreadID: thread.ID, UserID: user.ID, Depth: 0,
		BodyMarkdown: "hello", Status: domain.CommentStatusPending,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := commentRepo.Create(ctx, row); err != nil {
		t.Fatalf("create comment: %v", err)
	}
	return router, commentRepo, row.ID, user.ID, site.ID
}

// TestAdminCommentsPendingEndpoint 验证 POST /admin/comments/{id}/pending
// 把 pending 之外的评论移入 pending 并返回新状态；数据库同步更新。
func TestAdminCommentsPendingEndpoint(t *testing.T) {
	router, commentRepo, id, _, _ := newAdminCommentsRouter(t)

	// 评论经 publish 端点置为 published，随后移入 pending。
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodPost, "/api/v1/admin/comments/"+strconv.FormatInt(id, 10)+"/publish", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("publish = %d %s, want 200", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodPost, "/api/v1/admin/comments/"+strconv.FormatInt(id, 10)+"/pending", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("pending = %d %s, want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("pending response missing status: %s", rec.Body.String())
	}
	row, err := commentRepo.FindGlobalByID(context.Background(), id)
	if err != nil {
		t.Fatalf("re-find: %v", err)
	}
	if row.Status != domain.CommentStatusPending {
		t.Fatalf("db status = %s, want pending", row.Status)
	}
}

// TestAdminCommentsPendingSameStateConflict 验证对已 pending 评论再次 pending 返回 409。
func TestAdminCommentsPendingSameStateConflict(t *testing.T) {
	router, _, id, _, _ := newAdminCommentsRouter(t)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodPost, "/api/v1/admin/comments/"+strconv.FormatInt(id, 10)+"/pending", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("same-state pending = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"conflict"`) {
		t.Fatalf("conflict body missing code: %s", rec.Body.String())
	}
}

// TestAdminCommentsPendingMissingComment 验证不存在的评论返回 404。
func TestAdminCommentsPendingMissingComment(t *testing.T) {
	router, _, _, _, _ := newAdminCommentsRouter(t)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodPost, "/api/v1/admin/comments/999999/pending", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing pending = %d %s, want 404", rec.Code, rec.Body.String())
	}
}

// TestAdminCommentsListAcceptsSortDirection 验证管理评论列表接受受控 sort
// 参数：asc/desc 均返回 200，缺省等价 desc，非法值返回 422。
func TestAdminCommentsListAcceptsSortDirection(t *testing.T) {
	router, _, id, _, _ := newAdminCommentsRouter(t)

	for _, sort := range []string{"asc", "desc"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(
			http.MethodGet, "/api/v1/admin/comments?sort="+sort, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("sort=%s status = %d, want 200; body=%s", sort, rec.Code, rec.Body.String())
		}
	}

	// 缺省时不传 sort 也返回 200，且能读到种子评论。
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, "/api/v1/admin/comments", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("no-sort status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"id":"`+strconv.FormatInt(id, 10)+`"`) {
		t.Fatalf("no-sort body missing comment %d: %s", id, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, "/api/v1/admin/comments?sort=sideways", nil))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid sort status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"invalid_input"`) {
		t.Fatalf("invalid sort body = %s, want code invalid_input", rec.Body.String())
	}
}

// TestAdminCommentsListPageAndTotal 验证页码分页生效、返回真实 total，且响应不含游标。
func TestAdminCommentsListPageAndTotal(t *testing.T) {
	router, commentRepo, _, _, _ := newAdminCommentsRouter(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		row := &domain.Comment{
			SiteID: 1, ThreadID: 1, UserID: 1, Depth: 0,
			BodyMarkdown: "hello", Status: domain.CommentStatusPending,
			IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: time.Date(2026, time.August, 8+i, 12, 0, 0, 0, time.UTC),
			UpdatedAt: time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := commentRepo.Create(ctx, row); err != nil {
			t.Fatalf("create comment %d: %v", i, err)
		}
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, "/api/v1/admin/comments?limit=2&page=2", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("page 2 status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"next_cursor"`) {
		t.Fatalf("response still exposes next_cursor: %s", rec.Body.String())
	}
	var body struct {
		Comments []json.RawMessage `json:"comments"`
		Total    int64             `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Comments) != 2 || body.Total != 5 {
		t.Fatalf("page 2 = %d rows total=%d, want 2 rows + total 5", len(body.Comments), body.Total)
	}
	// 越界页返回空数组但总数不变。
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, "/api/v1/admin/comments?limit=2&page=99", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("out-of-range status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode out-of-range body: %v", err)
	}
	if len(body.Comments) != 0 || body.Total != 5 {
		t.Fatalf("out-of-range = %d rows total=%d, want 0 rows + total 5", len(body.Comments), body.Total)
	}
}

// TestAdminCommentsListRejectsInvalidPage 验证非正整数页码返回参数错误。
func TestAdminCommentsListRejectsInvalidPage(t *testing.T) {
	router, _, _, _, _ := newAdminCommentsRouter(t)
	for _, page := range []string{"0", "-1", "abc", "1.5"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(
			http.MethodGet, "/api/v1/admin/comments?page="+page, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("page=%s status = %d, want 400; body=%s", page, rec.Code, rec.Body.String())
		}
	}
}

// TestAdminCommentsListSearchByQ 验证 q 跨正文、作者邮箱与昵称做服务端搜索，
// 且分页总数与搜索结果一致。
func TestAdminCommentsListSearchByQ(t *testing.T) {
	router, _, id, _, _ := newAdminCommentsRouter(t)
	// 种子评论正文 hello、作者邮箱 admin@example.com、昵称 Admin。
	for _, q := range []string{"hello", "admin@example.com", "Admin"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(
			http.MethodGet, "/api/v1/admin/comments?q="+q, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("q=%s status = %d, want 200; body=%s", q, rec.Code, rec.Body.String())
		}
		var body struct {
			Comments []json.RawMessage `json:"comments"`
			Total    int64             `json:"total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode q=%s body: %v", q, err)
		}
		if len(body.Comments) != 1 || body.Total != 1 {
			t.Fatalf("q=%s = %d rows total=%d, want 1/1", q, len(body.Comments), body.Total)
		}
		if !strings.Contains(rec.Body.String(), `"id":"`+strconv.FormatInt(id, 10)+`"`) {
			t.Fatalf("q=%s result missing seed comment: %s", q, rec.Body.String())
		}
	}
	// 不匹配任何字段时返回空集与零总数。
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, "/api/v1/admin/comments?q=no-such-thing", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("no-match status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Comments []json.RawMessage `json:"comments"`
		Total    int64             `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode no-match body: %v", err)
	}
	if len(body.Comments) != 0 || body.Total != 0 {
		t.Fatalf("no-match = %d rows total=%d, want 0/0", len(body.Comments), body.Total)
	}
}

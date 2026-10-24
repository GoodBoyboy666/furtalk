package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// seedWidgetPageReply 插入用于独立分页接口验证的回复。
func seedWidgetPageReply(t *testing.T, db *gorm.DB, siteID, threadID, rootID int64, at time.Time, status domain.CommentStatus) int64 {
	t.Helper()
	root, err := repository.NewCommentRepo(db).FindBySiteAndID(context.Background(), siteID, rootID)
	if err != nil {
		t.Fatal(err)
	}
	row := &domain.Comment{SiteID: siteID, ThreadID: threadID, UserID: root.UserID, ParentID: &rootID, RootID: &rootID,
		ReplyToUserID: &root.UserID, Depth: 1, BodyMarkdown: "page reply", Status: status,
		IPMode: domain.PrivacyModeFull, IPValue: pageTestString("192.0.2.1"), UAMode: domain.PrivacyModeFull, UARaw: pageTestString("private-agent"),
		CreatedAt: at, UpdatedAt: at}
	if status == domain.CommentStatusPublished {
		row.PublishedAt = &at
	}
	if err := repository.NewCommentRepo(db).Create(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	return row.ID
}

// pageTestString 构造测试用可选字符串。
func pageTestString(value string) *string { return &value }

// TestWidgetPublicPagesHTTP 验证新增端点的分页、空根、隐私、查看者状态及旧接口兼容。
func TestWidgetPublicPagesHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, verifier, settings, principals, _, origins, db := buildWidgetLikeService(t)
	threadID, rootID := seedWidgetPublishedComment(t, db, svc, 1)
	root, err := repository.NewCommentRepo(db).FindBySiteAndID(context.Background(), 1, rootID)
	if err != nil {
		t.Fatal(err)
	}
	first := seedWidgetPageReply(t, db, 1, threadID, rootID, root.CreatedAt.Add(time.Second), domain.CommentStatusPublished)
	second := seedWidgetPageReply(t, db, 1, threadID, rootID, root.CreatedAt.Add(2*time.Second), domain.CommentStatusPublished)
	hidden := seedWidgetPageReply(t, db, 1, threadID, rootID, root.CreatedAt.Add(3*time.Second), domain.CommentStatusSpam)
	empty := &domain.Comment{SiteID: 1, ThreadID: threadID, UserID: root.UserID, BodyMarkdown: "empty root", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone, CreatedAt: root.CreatedAt, UpdatedAt: root.CreatedAt, PublishedAt: root.PublishedAt}
	if err := repository.NewCommentRepo(db).Create(context.Background(), empty); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{rootID, first} {
		if err := db.Create(&model.CommentLike{SiteID: 1, CommentID: id, UserID: root.UserID}).Error; err != nil {
			t.Fatal(err)
		}
	}
	router := likeRouter(svc, verifier, settings, principals, origins)
	do := func(path string, cookie bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Origin", testWidgetOrigin)
		if cookie {
			req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: "valid"})
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	rootPath := "/api/v1/widget/sites/1/root-comments"
	replyPath := "/api/v1/widget/sites/1/comments/" + formatDecimal(rootID) + "/replies"
	rec := do(rootPath+"?page_key=page-key&sort=asc&limit=1", false)
	if rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != testWidgetOrigin {
		t.Fatalf("root response status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	var roots ThreadRootCommentsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &roots); err != nil {
		t.Fatal(err)
	}
	if roots.Thread.ID != formatDecimal(threadID) || len(roots.Comments) != 1 || roots.Comments[0].ID != formatDecimal(rootID) || !roots.Comments[0].HasReplies || roots.Comments[0].LikedByMe || roots.NextCursor == nil {
		t.Fatalf("root DTO=%+v", roots)
	}
	rootCursor := *roots.NextCursor
	assertPublicPagePrivacy(t, rec.Body.Bytes(), true)
	rec = do(rootPath+"?page_key=page-key&sort=asc&limit=1", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer roots status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &roots); err != nil || !roots.Comments[0].LikedByMe {
		t.Fatalf("viewer root DTO=%+v err=%v", roots, err)
	}
	rec = do(rootPath+"?page_key=page-key&sort=asc&limit=1&cursor="+rootCursor, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("root append status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &roots); err != nil || len(roots.Comments) != 1 || roots.Comments[0].ID != formatDecimal(empty.ID) || roots.Comments[0].HasReplies || roots.NextCursor != nil {
		t.Fatalf("root append DTO=%+v err=%v", roots, err)
	}
	rec = do(replyPath+"?page_key=page-key&limit=1", true)
	var replies CommentRepliesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &replies); rec.Code != http.StatusOK || err != nil || replies.RootID != formatDecimal(rootID) || len(replies.Comments) != 1 || replies.Comments[0].ID != formatDecimal(first) || !replies.Comments[0].LikedByMe || replies.NextCursor == nil {
		t.Fatalf("reply DTO=%+v status=%d err=%v body=%s", replies, rec.Code, err, rec.Body.String())
	}
	replyCursor := *replies.NextCursor
	assertPublicPagePrivacy(t, rec.Body.Bytes(), false)
	rec = do(replyPath+"?page_key=page-key&limit=1&cursor="+replyCursor, false)
	if err := json.Unmarshal(rec.Body.Bytes(), &replies); rec.Code != http.StatusOK || err != nil || len(replies.Comments) != 1 || replies.Comments[0].ID != formatDecimal(second) || replies.Comments[0].LikedByMe || replies.NextCursor != nil {
		t.Fatalf("reply append DTO=%+v status=%d err=%v", replies, rec.Code, err)
	}
	// 没有回复的可见根必须返回空数组，而非不存在或 SQL 标记行。
	rec = do("/api/v1/widget/sites/1/comments/"+formatDecimal(empty.ID)+"/replies?page_key=page-key", false)
	if err := json.Unmarshal(rec.Body.Bytes(), &replies); rec.Code != http.StatusOK || err != nil || replies.Comments == nil || len(replies.Comments) != 0 || replies.NextCursor != nil {
		t.Fatalf("empty reply DTO=%+v status=%d err=%v", replies, rec.Code, err)
	}
	rec = do("/api/v1/widget/sites/1/comments?page_key=page-key&sort=desc&limit=1", false)
	var legacy ThreadCommentsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &legacy); rec.Code != http.StatusOK || err != nil || len(legacy.Comments) != 1 || legacy.Comments[0].ID != formatDecimal(second) || legacy.NextCursor == nil {
		t.Fatalf("legacy flat DTO=%+v status=%d err=%v", legacy, rec.Code, err)
	}
	if strings.Contains(rec.Body.String(), "has_replies") {
		t.Fatal("legacy comments gained a new field")
	}
	legacyCursor := *legacy.NextCursor
	// 构造其他线程与站点，以 HTTP 层证明游标绑定请求作用域。
	if _, err := repository.NewThreadRepo(db).ResolveOrCreate(context.Background(), 1, "other-page", nil, nil); err != nil {
		t.Fatal(err)
	}
	otherSite, err := origins.svc.Create(context.Background(), "Other", "https://other.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := origins.svc.AddOrigin(context.Background(), otherSite.ID, testWidgetOrigin); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.NewThreadRepo(db).ResolveOrCreate(context.Background(), otherSite.ID, "page-key", nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		status     int
	}{
		{"root-required-page", rootPath, 422},
		{"reply-required-page", replyPath, 422},
		{"root-invalid-sort", rootPath + "?page_key=page-key&sort=invalid", 422},
		{"root-sort-swap", rootPath + "?page_key=page-key&sort=desc&cursor=" + rootCursor, 422},
		{"root-thread-swap", rootPath + "?page_key=other-page&sort=asc&cursor=" + rootCursor, 422},
		{"root-site-swap", "/api/v1/widget/sites/" + formatDecimal(otherSite.ID) + "/root-comments?page_key=page-key&sort=asc&cursor=" + rootCursor, 422},
		{"reply-thread-swap", replyPath + "?page_key=other-page&cursor=" + replyCursor, 422},
		{"reply-site-swap", "/api/v1/widget/sites/" + formatDecimal(otherSite.ID) + "/comments/" + formatDecimal(rootID) + "/replies?page_key=page-key&cursor=" + replyCursor, 422},
		{"reply-root-swap", "/api/v1/widget/sites/1/comments/" + formatDecimal(empty.ID) + "/replies?page_key=page-key&cursor=" + replyCursor, 422},
		{"root-endpoint-swap", rootPath + "?page_key=page-key&cursor=" + replyCursor, 422},
		{"reply-endpoint-swap", replyPath + "?page_key=page-key&cursor=" + rootCursor, 422},
		{"root-legacy-cursor", rootPath + "?page_key=page-key&cursor=" + legacyCursor, 422},
		{"reply-legacy-cursor", replyPath + "?page_key=page-key&cursor=" + legacyCursor, 422},
		{"legacy-root-cursor", "/api/v1/widget/sites/1/comments?page_key=page-key&cursor=" + rootCursor, 422},
		{"root-malformed-cursor", rootPath + "?page_key=page-key&cursor=bad", 422},
		{"reply-malformed-cursor", replyPath + "?page_key=page-key&cursor=bad", 422},
		{"reply-missing", "/api/v1/widget/sites/1/comments/999999/replies?page_key=page-key", 404},
		{"reply-hidden", "/api/v1/widget/sites/1/comments/" + formatDecimal(hidden) + "/replies?page_key=page-key", 404},
		{"reply-nonroot", "/api/v1/widget/sites/1/comments/" + formatDecimal(first) + "/replies?page_key=page-key", 404},
		{"reply-wrong-thread", replyPath + "?page_key=other-page", 404},
		{"reply-wrong-site", "/api/v1/widget/sites/" + formatDecimal(otherSite.ID) + "/comments/" + formatDecimal(rootID) + "/replies?page_key=page-key", 404},
		{"root-invalid-id", "/api/v1/widget/sites/no/root-comments?page_key=page-key", 400},
		{"reply-invalid-id", "/api/v1/widget/sites/1/comments/no/replies?page_key=page-key", 400},
		{"reply-missing-thread", replyPath + "?page_key=missing-page", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(tc.path, false)
			if rec.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
	rec = do(rootPath+"?page_key=missing-page", false)
	if err := json.Unmarshal(rec.Body.Bytes(), &roots); rec.Code != http.StatusOK || err != nil || roots.Thread.ID != "0" || !roots.Thread.CommentsEnabled || roots.Comments == nil || len(roots.Comments) != 0 {
		t.Fatalf("synthetic root page=%+v status=%d err=%v", roots, rec.Code, err)
	}
	if err := db.Model(&model.Site{}).Where("id = ?", 1).Update("status", domain.SiteStatusDisabled).Error; err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{rootPath + "?page_key=page-key", replyPath + "?page_key=page-key"} {
		if rec := do(path, false); rec.Code != http.StatusForbidden {
			t.Fatalf("inactive site status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
}

// assertPublicPagePrivacy 验证分页响应没有隐私或 SQL 扫描标记字段。
func assertPublicPagePrivacy(t *testing.T, data []byte, root bool) {
	t.Helper()
	var response struct{ Comments []map[string]json.RawMessage }
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	for _, row := range response.Comments {
		for _, field := range []string{"email", "author_email", "author_email_normalized", "ip_mode", "ip_value", "ua_mode", "ua_raw", "requested_root_id", "deleted_at"} {
			if _, exists := row[field]; exists {
				t.Fatalf("public response exposed %s", field)
			}
		}
		if _, exists := row["has_replies"]; exists != root {
			t.Fatalf("has_replies exists=%v root=%v", exists, root)
		}
	}
}

// TestWidgetPublicPagesPreflight 验证两个新增路径显式注册 GET 的精确 Origin 预检。
func TestWidgetPublicPagesPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, verifier, settings, principals, _, origins, _ := buildWidgetLikeService(t)
	router := likeRouter(svc, verifier, settings, principals, origins)
	for _, path := range []string{"/api/v1/widget/sites/1/root-comments", "/api/v1/widget/sites/1/comments/1/replies"} {
		for _, origin := range []string{testWidgetOrigin, "https://evil.example"} {
			req := httptest.NewRequest(http.MethodOptions, path, nil)
			req.Header.Set("Origin", origin)
			req.Header.Set("Access-Control-Request-Method", http.MethodGet)
			req.Header.Set("Access-Control-Request-Headers", "Content-Type, X-Request-ID")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if origin == testWidgetOrigin {
				if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != origin || !strings.Contains(rec.Header().Get("Access-Control-Allow-Methods"), http.MethodGet) || rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Fatalf("allowed preflight status=%d headers=%v", rec.Code, rec.Header())
				}
			} else if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("disallowed preflight status=%d headers=%v", rec.Code, rec.Header())
			}
		}
	}
}

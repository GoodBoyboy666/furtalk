package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

// meCommentsRouter 装配真实仓储 + principal 注入的 /me/comments 读取路由。
func meCommentsRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	service, _, _, _, userGate, _ := buildWidgetTestService(t)
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	router.Use(func(c *gin.Context) {
		c.Set("current_principal", domain.Principal{UserID: 1, Role: domain.RoleUser, Status: domain.UserStatusActive})
		c.Next()
	})
	RegisterMeComments(router.Group("/api/v1"), service, userGate)
	return router
}

func meCommentsRequest(t *testing.T, router *gin.Engine, path string, login *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if login != nil {
		req.AddCookie(login)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestMeCommentsListReturnsOwnerCommentsOnly 验证 /me/comments 返回本人评论、
// 匹配总数，且响应不含游标字段。
func TestMeCommentsListReturnsOwnerCommentsOnly(t *testing.T) {
	router := meCommentsRouter(t)
	rec := meCommentsRequest(t, router, "/api/v1/me/comments", firstPartyCookie(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"next_cursor"`) {
		t.Fatalf("response still exposes next_cursor: %s", rec.Body.String())
	}
	var body struct {
		Comments       []json.RawMessage `json:"comments"`
		Total          int64             `json:"total"`
		UserDeleteMode string            `json:"user_delete_mode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.UserDeleteMode != domain.UserDeleteModeSoft {
		t.Fatalf("user_delete_mode = %q, want soft", body.UserDeleteMode)
	}
	if body.Total != int64(len(body.Comments)) {
		t.Fatalf("total = %d, want %d rows", body.Total, len(body.Comments))
	}
	for _, raw := range body.Comments {
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("decode comment: %v", err)
		}
		for _, leak := range []string{"author_email", "ip_value", "ua_raw", "ip_mode", "ua_mode"} {
			if _, ok := fields[leak]; ok {
				t.Fatalf("leaked field %q in response: %s", leak, raw)
			}
		}
	}
}

// TestMeCommentsListRejectsInvalidPage 验证非正整数页码返回参数错误。
func TestMeCommentsListRejectsInvalidPage(t *testing.T) {
	router := meCommentsRouter(t)
	for _, page := range []string{"0", "-1", "abc", "1.5"} {
		rec := meCommentsRequest(t, router, "/api/v1/me/comments?page="+page, firstPartyCookie(t))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("page=%s status = %d, want 400; body=%s", page, rec.Code, rec.Body.String())
		}
	}
}

// TestMeCommentsDetailScopesOwner 验证详情 owner 作用域生效，他人评论返回 404。
func TestMeCommentsDetailScopesOwner(t *testing.T) {
	router := meCommentsRouter(t)
	rec := meCommentsRequest(t, router, "/api/v1/me/comments/999999", firstPartyCookie(t))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestMeCommentsRejectsInvalidStatus 验证非法 status 筛选被拒绝。
func TestMeCommentsRejectsInvalidStatus(t *testing.T) {
	router := meCommentsRouter(t)
	rec := meCommentsRequest(t, router, "/api/v1/me/comments?status=bogus", firstPartyCookie(t))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

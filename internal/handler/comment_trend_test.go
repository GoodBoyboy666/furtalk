package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAdminCommentsTrendKeepsStaticRouteBeforeIDRoute 验证 trend 不会被
// /comments/:comment_id 当成非法评论 ID 处理，并且非法范围返回验证错误。
func TestAdminCommentsTrendKeepsStaticRouteBeforeIDRoute(t *testing.T) {
	router, _, _, _, _ := newAdminCommentsRouter(t)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/admin/comments/trend?days=6&timezone=UTC",
		nil,
	))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("trend invalid days = %d, body=%s; want 422", recorder.Code, recorder.Body.String())
	}
}

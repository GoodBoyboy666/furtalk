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

	"furtalk/internal/platform/database"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/site"

	"github.com/gin-gonic/gin"
)

// newSiteTestRouter 构建挂载站点路由的测试引擎（真实 repository + service）。
func newSiteTestRouter(t *testing.T) (*gin.Engine, *site.Service) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "handler-sites.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.Site{}, &model.SiteOrigin{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	svc := site.NewService(repository.NewSiteRepo(db))
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	RegisterAdminSites(router.Group("/api/v1/admin"), svc)
	return router, svc
}

// newSiteForHandler 创建站点并返回其 ID。
func newSiteForHandler(t *testing.T, svc *site.Service, name string) int64 {
	t.Helper()
	created, err := svc.Create(context.Background(), name, "https://example.com")
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	return created.ID
}

// performJSON 执行带 JSON body 的请求并返回 recorder。
func performJSON(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

// TestSitesListEmbedsOriginRecords 验证站点列表的 origins 是带稳定 ID 的对象数组。
func TestSitesListEmbedsOriginRecords(t *testing.T) {
	router, svc := newSiteTestRouter(t)
	siteID := newSiteForHandler(t, svc, "Site A")
	created, err := svc.AddOrigin(context.Background(), siteID, "https://app.example.com")
	if err != nil {
		t.Fatalf("add origin: %v", err)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/sites", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /admin/sites = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var resp SiteListResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Sites) != 1 {
		t.Fatalf("sites count = %d, want 1", len(resp.Sites))
	}
	origins := resp.Sites[0].Origins
	if len(origins) != 1 {
		t.Fatalf("origins count = %d, want 1", len(origins))
	}
	if origins[0].ID != formatSiteID(created.ID) || origins[0].Origin != "https://app.example.com" {
		t.Fatalf("origin record = %+v, want stable id %d with value", origins[0], created.ID)
	}
}

// TestOriginCreateUpdateDelete 验证 origin 的 POST/PATCH/DELETE 契约。
func TestOriginCreateUpdateDelete(t *testing.T) {
	router, svc := newSiteTestRouter(t)
	siteID := newSiteForHandler(t, svc, "Site A")

	created := performJSON(router, http.MethodPost,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins", `{"origin":" https://App.Example.COM "}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST origin = %d, body=%s", created.Code, created.Body.String())
	}
	var createdBody OriginResponse
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatalf("decode created origin: %v", err)
	}
	if createdBody.ID == "" || createdBody.Origin != "https://app.example.com" {
		t.Fatalf("created origin = %+v, want normalized value with id", createdBody)
	}

	updated := performJSON(router, http.MethodPatch,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins/"+createdBody.ID,
		`{"origin":"https://cdn.example.com"}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("PATCH origin = %d, body=%s", updated.Code, updated.Body.String())
	}
	var updatedBody OriginResponse
	if err := json.Unmarshal(updated.Body.Bytes(), &updatedBody); err != nil {
		t.Fatalf("decode updated origin: %v", err)
	}
	if updatedBody.ID != createdBody.ID || updatedBody.Origin != "https://cdn.example.com" {
		t.Fatalf("updated origin = %+v, want id %s with new value", updatedBody, createdBody.ID)
	}

	deleted := performJSON(router, http.MethodDelete,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins/"+createdBody.ID, "")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("DELETE origin = %d, body=%s", deleted.Code, deleted.Body.String())
	}

	missing := performJSON(router, http.MethodDelete,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins/"+createdBody.ID, "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("DELETE removed origin = %d, want 404", missing.Code)
	}
}

// TestOriginRejectsCrossSite 验证跨站点更新与删除被拒绝。
func TestOriginRejectsCrossSite(t *testing.T) {
	router, svc := newSiteTestRouter(t)
	siteA := newSiteForHandler(t, svc, "Site A")
	siteB := newSiteForHandler(t, svc, "Site B")
	created, err := svc.AddOrigin(context.Background(), siteA, "https://a.example.com")
	if err != nil {
		t.Fatalf("add origin: %v", err)
	}

	updated := performJSON(router, http.MethodPatch,
		"/api/v1/admin/sites/"+formatSiteID(siteB)+"/origins/"+formatSiteID(created.ID),
		`{"origin":"https://b.example.com"}`)
	if updated.Code != http.StatusNotFound {
		t.Fatalf("cross-site PATCH = %d, want 404; body=%s", updated.Code, updated.Body.String())
	}

	deleted := performJSON(router, http.MethodDelete,
		"/api/v1/admin/sites/"+formatSiteID(siteB)+"/origins/"+formatSiteID(created.ID), "")
	if deleted.Code != http.StatusNotFound {
		t.Fatalf("cross-site DELETE = %d, want 404", deleted.Code)
	}
}

// TestOriginErrors 验证重复与非法值分别映射为 409 与 422。
func TestOriginErrors(t *testing.T) {
	router, svc := newSiteTestRouter(t)
	siteID := newSiteForHandler(t, svc, "Site A")
	created, err := svc.AddOrigin(context.Background(), siteID, "https://app.example.com")
	if err != nil {
		t.Fatalf("add origin: %v", err)
	}

	duplicate := performJSON(router, http.MethodPost,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins", `{"origin":"https://app.example.com"}`)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate POST = %d, want 409; body=%s", duplicate.Code, duplicate.Body.String())
	}

	invalid := performJSON(router, http.MethodPost,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins", `{"origin":"not-a-url"}`)
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid POST = %d, want 422; body=%s", invalid.Code, invalid.Body.String())
	}

	if _, err := svc.AddOrigin(context.Background(), siteID, "https://other.example.com"); err != nil {
		t.Fatalf("add second origin: %v", err)
	}

	// 更新为其他 origin 行的值属于重复冲突，映射为 409。
	duplicateUpdate := performJSON(router, http.MethodPatch,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins/"+formatSiteID(created.ID),
		`{"origin":"https://other.example.com"}`)
	if duplicateUpdate.Code != http.StatusConflict {
		t.Fatalf("duplicate PATCH = %d, want 409; body=%s", duplicateUpdate.Code, duplicateUpdate.Body.String())
	}

	// 更新为自身当前值是幂等操作，必须保持 200（与仓储层语义一致）。
	idempotentUpdate := performJSON(router, http.MethodPatch,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins/"+formatSiteID(created.ID),
		`{"origin":"https://app.example.com"}`)
	if idempotentUpdate.Code != http.StatusOK {
		t.Fatalf("same-value PATCH = %d, want 200; body=%s", idempotentUpdate.Code, idempotentUpdate.Body.String())
	}

	missingUpdate := performJSON(router, http.MethodPatch,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins/99999", `{"origin":"https://x.example.com"}`)
	if missingUpdate.Code != http.StatusNotFound {
		t.Fatalf("missing PATCH = %d, want 404; body=%s", missingUpdate.Code, missingUpdate.Body.String())
	}

	badID := performJSON(router, http.MethodPatch,
		"/api/v1/admin/sites/"+formatSiteID(siteID)+"/origins/abc", `{"origin":"https://x.example.com"}`)
	if badID.Code != http.StatusBadRequest {
		t.Fatalf("bad origin id PATCH = %d, want 400; body=%s", badID.Code, badID.Body.String())
	}
}

// formatSiteID 将 int64 站点 ID 格式化为十进制字符串。
func formatSiteID(value int64) string {
	return strconv.FormatInt(value, 10)
}

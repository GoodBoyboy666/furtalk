package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"furtalk/internal/domain"
)

func TestAdminCommentPinRoutesAreIdempotentAndPublishedOnly(t *testing.T) {
	router, repo, id, _, _ := newAdminCommentsRouter(t)
	path := "/api/v1/admin/comments/" + strconv.FormatInt(id, 10) + "/pin"

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, path, nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("pin pending = %d %s, want 409", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/admin/comments/"+strconv.FormatInt(id, 10)+"/publish", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("publish = %d %s, want 200", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, path, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"is_pinned":true`) {
		t.Fatalf("pin = %d %s, want pinned admin view", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, path, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"is_pinned":true`) {
		t.Fatalf("repeat pin = %d %s, want pinned admin view", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, path, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"is_pinned":false`) {
		t.Fatalf("unpin = %d %s, want unpinned admin view", rec.Code, rec.Body.String())
	}
	row, err := repo.FindGlobalByID(context.Background(), id)
	if err != nil {
		t.Fatalf("reload comment: %v", err)
	}
	if row.IsPinned {
		t.Fatal("database comment remains pinned after DELETE")
	}
}

func TestAdminCommentPinRouteRejectsReply(t *testing.T) {
	router, repo, id, _, siteID := newAdminCommentsRouter(t)
	parentID := id
	reply := &domain.Comment{
		SiteID: siteID, ThreadID: 1, UserID: 1, ParentID: &parentID, RootID: &parentID,
		Depth: 1, BodyMarkdown: "reply", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
	}
	if err := repo.Create(context.Background(), reply); err != nil {
		t.Fatalf("create reply: %v", err)
	}
	path := "/api/v1/admin/comments/" + strconv.FormatInt(reply.ID, 10) + "/pin"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, path, nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("pin reply = %d %s, want 409", rec.Code, rec.Body.String())
	}
}

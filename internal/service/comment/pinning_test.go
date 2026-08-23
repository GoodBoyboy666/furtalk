package comment

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
)

func TestPinLifecyclePreservesStateAcrossModeration(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	if _, err := svc.AdminSetPinned(ctx, fx.IDs["pending"], true); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("pin pending = %v, want conflict", err)
	}
	view, err := svc.AdminSetPinned(ctx, fx.IDs["a"], true)
	if err != nil {
		t.Fatalf("pin published root: %v", err)
	}
	if !view.IsPinned {
		t.Fatal("pin published root returned false")
	}

	view, err = svc.AdminMarkSpam(ctx, fx.IDs["a"])
	if err != nil {
		t.Fatalf("mark spam: %v", err)
	}
	if !view.IsPinned {
		t.Fatal("spam transition cleared pin")
	}
	view, err = svc.AdminPublish(ctx, fx.IDs["a"])
	if err != nil {
		t.Fatalf("republish: %v", err)
	}
	if !view.IsPinned {
		t.Fatal("republish did not restore pin")
	}
	view, err = svc.AdminSetPinned(ctx, fx.IDs["a"], false)
	if err != nil {
		t.Fatalf("unpin hidden/published root: %v", err)
	}
	if view.IsPinned {
		t.Fatal("unpin returned true")
	}
}

func TestWidgetPinRequiresLiveAdministratorPrincipal(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	user := domain.Principal{UserID: 1, Role: domain.RoleUser, Status: domain.UserStatusActive}
	if _, err := svc.WidgetSetPinned(ctx, user, fx.SiteID, fx.IDs["a"], true); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("ordinary widget user pin = %v, want forbidden", err)
	}
	admin := domain.Principal{UserID: 1, Role: domain.RoleAdmin, Status: domain.UserStatusActive}
	result, err := svc.WidgetSetPinned(ctx, admin, fx.SiteID, fx.IDs["a"], true)
	if err != nil {
		t.Fatalf("admin widget pin: %v", err)
	}
	if result.CommentID != fx.IDs["a"] || !result.IsPinned {
		t.Fatalf("widget pin result = %+v", result)
	}
}

func TestPinRejectsDetachedReplyWithRootReferencesCleared(t *testing.T) {
	comment := &domain.Comment{Depth: 1}
	if err := validatePinTarget(comment, true); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("pin detached reply = %v, want conflict", err)
	}
}

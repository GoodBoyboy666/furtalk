package comment

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
)

func TestAdminBatchCountsNoopAndPublishesAfterCommit(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	bus := &recordingEventBus{}
	svc.bus = bus
	svc.settings = &staticCommentPolicyReader{policy: domain.CommentPolicy{
		Mode: domain.CommentModeAuthenticated, Moderation: domain.ModerationReview,
	}}

	result, err := svc.AdminBatch(context.Background(), AdminBatchInput{
		IDs: []int64{fx.Pending, fx.Published}, Action: AdminBatchPublish,
	})
	if err != nil {
		t.Fatalf("admin batch publish: %v", err)
	}
	if result.ChangedCount != 1 || result.UnchangedCount != 1 || bus.publishes != 1 {
		t.Fatalf("result = %+v, published events = %d", result, bus.publishes)
	}
	row, err := repository.NewCommentRepo(db).FindGlobalByID(context.Background(), fx.Pending)
	if err != nil || row.Status != domain.CommentStatusPublished {
		t.Fatalf("pending row = %+v, err=%v", row, err)
	}
}

func TestAdminBatchRollsBackWhenLaterTargetFails(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	reply, err := svc.CreateReplyFirstParty(context.Background(), fx.OwnerID, domain.RoleUser, fx.Published, "reply", "", nil, "ua")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}

	_, err = svc.AdminBatch(context.Background(), AdminBatchInput{
		IDs: []int64{fx.Published, reply.ID}, Action: AdminBatchPin,
	})
	var resourceErr *domain.ResourceError
	if !errors.As(err, &resourceErr) || resourceErr.ResourceID != reply.ID {
		t.Fatalf("error = %v, want failed reply %d", err, reply.ID)
	}
	row, findErr := repository.NewCommentRepo(db).FindGlobalByID(context.Background(), fx.Published)
	if findErr != nil {
		t.Fatalf("find root: %v", findErr)
	}
	if row.IsPinned {
		t.Fatal("root was pinned despite later batch failure")
	}
}

func TestAdminBatchHardDeletePreservesUnselectedReply(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	reply, err := svc.CreateReplyFirstParty(context.Background(), fx.OwnerID, domain.RoleUser, fx.Published, "reply", "", nil, "ua")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}
	result, err := svc.AdminBatch(context.Background(), AdminBatchInput{
		IDs: []int64{fx.Published}, Action: AdminBatchHardDelete, Confirm: true,
	})
	if err != nil || result.ChangedCount != 1 {
		t.Fatalf("hard delete result = %+v, err=%v", result, err)
	}
	row, err := repository.NewCommentRepo(db).FindGlobalByID(context.Background(), reply.ID)
	if err != nil {
		t.Fatalf("find retained reply: %v", err)
	}
	if row.ParentID != nil || row.RootID != nil {
		t.Fatalf("retained reply references deleted root: parent=%v root=%v", row.ParentID, row.RootID)
	}
}

func TestAdminBatchRequiresConfirmationAndRejectsDuplicates(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	if _, err := svc.AdminBatch(context.Background(), AdminBatchInput{
		IDs: []int64{fx.Published}, Action: AdminBatchSoftDelete,
	}); !errors.Is(err, domain.ErrConfirmationRequired) {
		t.Fatalf("missing soft-delete confirmation = %v", err)
	}
	if _, err := svc.AdminBatch(context.Background(), AdminBatchInput{
		IDs: []int64{fx.Published, fx.Published}, Action: AdminBatchPending,
	}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("duplicate ids = %v", err)
	}
}

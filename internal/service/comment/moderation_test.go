package comment

import (
	"context"
	"errors"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
	"gorm.io/gorm"
)

// seedAdminComment 插入一条指定状态的管理端测试评论。
func seedAdminComment(t *testing.T, db *gorm.DB, fx ownerFixture, status domain.CommentStatus, publishedAt *time.Time) int64 {
	t.Helper()
	thread, err := repository.NewThreadRepo(db).GetBySiteAndKey(context.Background(), fx.SiteID, "page-key")
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	c := &domain.Comment{
		SiteID: fx.SiteID, ThreadID: thread.ID, UserID: fx.OwnerID, Depth: 0,
		BodyMarkdown: "matrix-" + string(status), Status: status,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now,
		PublishedAt: publishedAt,
	}
	if err := repository.NewCommentRepo(db).Create(context.Background(), c); err != nil {
		t.Fatalf("create %s comment: %v", status, err)
	}
	return c.ID
}

// applyAdminTransition 应用目标状态对应的服务动作并返回更新后的评论。
func applyAdminTransition(t *testing.T, db *gorm.DB, svc *Service, id int64, to domain.CommentStatus) *domain.Comment {
	t.Helper()
	ctx := context.Background()
	var err error
	switch to {
	case domain.CommentStatusPending:
		_, err = svc.AdminPending(ctx, id)
	case domain.CommentStatusPublished:
		_, err = svc.AdminPublish(ctx, id)
	case domain.CommentStatusSpam:
		_, err = svc.AdminMarkSpam(ctx, id)
	case domain.CommentStatusDeleted:
		_, err = svc.AdminDelete(ctx, id, false, false)
	default:
		t.Fatalf("unknown target %q", to)
	}
	if err != nil {
		t.Fatalf("transition to %s: %v", to, err)
	}
	updated, findErr := repository.NewCommentRepo(db).FindGlobalByID(ctx, id)
	if findErr != nil {
		t.Fatalf("re-find %d: %v", id, findErr)
	}
	return updated
}

// TestAdminFourStateMatrix 验证四个状态之间的全部直接转换矩阵。
// 每个 (from, to) 单元使用独立评论，断言结果状态与目标一致。
func TestAdminFourStateMatrix(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	statuses := []domain.CommentStatus{
		domain.CommentStatusPending,
		domain.CommentStatusPublished,
		domain.CommentStatusSpam,
		domain.CommentStatusDeleted,
	}
	for _, from := range statuses {
		for _, to := range statuses {
			if from == to {
				continue
			}
			name := string(from) + "-to-" + string(to)
			t.Run(name, func(t *testing.T) {
				var publishedAt *time.Time
				if from == domain.CommentStatusPublished {
					now := time.Date(2026, time.August, 8, 11, 0, 0, 0, time.UTC)
					publishedAt = &now
				}
				id := seedAdminComment(t, db, fx, from, publishedAt)
				updated := applyAdminTransition(t, db, svc, id, to)
				if updated.Status != to {
					t.Fatalf("%s -> %s: status = %s, want %s", from, to, updated.Status, to)
				}
			})
		}
	}
}

// TestAdminSameStateConflicts 验证相同状态请求始终返回冲突，不会改写任何元数据。
func TestAdminSameStateConflicts(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	cases := []struct {
		id    int64
		apply func(context.Context, int64) error
		to    domain.CommentStatus
	}{
		{fx.Pending, func(ctx context.Context, id int64) error { _, err := svc.AdminPending(ctx, id); return err }, domain.CommentStatusPending},
		{fx.Published, func(ctx context.Context, id int64) error { _, err := svc.AdminPublish(ctx, id); return err }, domain.CommentStatusPublished},
		{fx.Spam, func(ctx context.Context, id int64) error { _, err := svc.AdminMarkSpam(ctx, id); return err }, domain.CommentStatusSpam},
	}
	for _, tc := range cases {
		if err := tc.apply(ctx, tc.id); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("%s same-state err = %v, want ErrConflict", tc.to, err)
		}
		after, _ := repository.NewCommentRepo(db).FindGlobalByID(ctx, tc.id)
		if after.Status != tc.to || after.DeletedAt != nil || after.StatusBeforeDelete != nil {
			t.Fatalf("same-state transition rewrote row: %+v", after)
		}
	}
}

// TestAdminPendingClearsPublicationMetadata 验证移到 pending 清除
// published_at、deleted_at 与 status_before_delete。
func TestAdminPendingClearsPublicationMetadata(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	id := fx.Published
	if _, err := svc.AdminPending(ctx, id); err != nil {
		t.Fatalf("published -> pending: %v", err)
	}
	row, err := repository.NewCommentRepo(db).FindGlobalByID(ctx, id)
	if err != nil {
		t.Fatalf("re-find: %v", err)
	}
	if row.Status != domain.CommentStatusPending || row.PublishedAt != nil || row.DeletedAt != nil || row.StatusBeforeDelete != nil {
		t.Fatalf("pending metadata not cleared: %+v", row)
	}
}

// TestAdminPublishFromDeletedRestoresOnlySelectedRow 验证 deleted -> published
// 只恢复目标单条、清除删除标记并设置 published_at；软删除只影响选中行，
// 回复本就不受影响。
func TestAdminPublishFromDeletedRestoresOnlySelectedRow(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	root, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Published, "root", "", nil, "ua")
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	reply, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, root.ID, "reply", "", nil, "ua")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}
	if _, err := svc.AdminDelete(ctx, root.ID, false, false); err != nil {
		t.Fatalf("soft delete root: %v", err)
	}

	if _, err := svc.AdminPublish(ctx, root.ID); err != nil {
		t.Fatalf("deleted -> published: %v", err)
	}
	repo := repository.NewCommentRepo(db)
	rootRow, _ := repo.FindGlobalByID(ctx, root.ID)
	replyRow, _ := repo.FindGlobalByID(ctx, reply.ID)
	if rootRow.Status != domain.CommentStatusPublished || rootRow.DeletedAt != nil || rootRow.StatusBeforeDelete != nil || rootRow.PublishedAt == nil {
		t.Fatalf("restored root = %+v", rootRow)
	}
	if replyRow.Status != domain.CommentStatusPublished {
		t.Fatalf("reply must stay published, got %+v", replyRow)
	}
}

// TestAdminSpamFromDeletedRetainsHistoricalPublishedAt 验证 deleted -> spam
// 清除删除标记但保留历史 published_at。
func TestAdminSpamFromDeletedRetainsHistoricalPublishedAt(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	if _, err := svc.AdminDelete(ctx, fx.Published, false, false); err != nil {
		t.Fatalf("soft delete published comment: %v", err)
	}
	if _, err := svc.AdminMarkSpam(ctx, fx.Published); err != nil {
		t.Fatalf("deleted -> spam: %v", err)
	}
	row, err := repository.NewCommentRepo(db).FindGlobalByID(ctx, fx.Published)
	if err != nil {
		t.Fatalf("re-find: %v", err)
	}
	if row.Status != domain.CommentStatusSpam || row.DeletedAt != nil || row.StatusBeforeDelete != nil {
		t.Fatalf("spam metadata wrong: %+v", row)
	}
	if row.PublishedAt == nil {
		t.Fatal("historical published_at lost after deleted -> spam")
	}
}

// TestAdminPublishEmitsPublishedEventOnlyUnderReview 验证只有审核策略为
// review 时，管理员发布评论才在持久化后发出 CommentPublished 事件；
// direct 策略下管理员发布不产生该事件。
func TestAdminPublishEmitsPublishedEventOnlyUnderReview(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	ctx := context.Background()

	t.Run("review emits published event", func(t *testing.T) {
		bus := &recordingEventBus{}
		svc := ownerService(db, domain.UserDeleteModeSoft)
		svc.bus = bus
		svc.settings = &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:          domain.CommentModeAuthenticated,
			Moderation:    domain.ModerationReview,
			MaxReplyDepth: 5,
			Privacy:       domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		}}

		if _, err := svc.AdminPublish(ctx, fx.Pending); err != nil {
			t.Fatalf("pending -> published: %v", err)
		}
		if bus.publishes != 1 {
			t.Fatalf("published events = %d, want 1", bus.publishes)
		}
	})

	t.Run("direct suppresses published event", func(t *testing.T) {
		bus := &recordingEventBus{}
		svc := ownerService(db, domain.UserDeleteModeSoft)
		svc.bus = bus

		if _, err := svc.AdminPublish(ctx, fx.Spam); err != nil {
			t.Fatalf("spam -> published: %v", err)
		}
		if bus.publishes != 0 {
			t.Fatalf("published events = %d, want 0 under direct", bus.publishes)
		}
	})
}

// TestAdminDeleteTargetsOnlySelectedRow 验证进入 deleted 只软删选中评论，
// 其回复后代保持原状态。
func TestAdminDeleteTargetsOnlySelectedRow(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	root, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Published, "root", "", nil, "ua")
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	reply, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, root.ID, "reply", "", nil, "ua")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}
	updated := applyAdminTransition(t, db, svc, root.ID, domain.CommentStatusDeleted)
	repo := repository.NewCommentRepo(db)
	replyRow, _ := repo.FindGlobalByID(ctx, reply.ID)
	if updated.Status != domain.CommentStatusDeleted {
		t.Fatalf("root status = %s, want deleted", updated.Status)
	}
	if replyRow.Status != domain.CommentStatusPublished {
		t.Fatalf("reply must stay published, got %+v", replyRow)
	}
}

// TestAdminTransitionConflictOnDeletedSameState 验证 deleted 上重复 delete 仍冲突。
func TestAdminTransitionConflictOnDeletedSameState(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	if _, err := svc.AdminDelete(ctx, fx.Deleted, false, false); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("deleted -> deleted err = %v, want ErrConflict", err)
	}
}

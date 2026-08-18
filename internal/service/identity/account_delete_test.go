package identity

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/comment"

	"gorm.io/gorm"
)

// newAccountDeleteTestDB 打开临时 SQLite 数据库并迁移用户/评论相关表。
func newAccountDeleteTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "account-delete-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.NotificationPreferences{}, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}, &model.Comment{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// accountDeleteFixture 是用户删除与评论关系测试的种子数据。
// owner 发表根评论；replier 回复该根评论。
type accountDeleteFixture struct {
	OwnerID   int64
	ReplierID int64
	RootID    int64
	ReplyID   int64
	SiteID    int64
}

func seedAccountDeleteFixture(t *testing.T, db *gorm.DB) accountDeleteFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	userRepo := repository.NewUserRepo(db)
	siteRepo := repository.NewSiteRepo(db)
	threadRepo := repository.NewThreadRepo(db)
	commentRepo := repository.NewCommentRepo(db)

	owner := &domain.User{Email: "owner@example.com", EmailNormalized: "owner@example.com", Nickname: "owner", Role: domain.RoleUser, Status: domain.UserStatusActive}
	replier := &domain.User{Email: "replier@example.com", EmailNormalized: "replier@example.com", Nickname: "replier", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := userRepo.Create(ctx, replier); err != nil {
		t.Fatalf("create replier: %v", err)
	}
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := threadRepo.ResolveOrCreate(ctx, site.ID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	publishedAt := &now
	root := &domain.Comment{
		SiteID: site.ID, ThreadID: thread.ID, UserID: owner.ID, Depth: 0,
		BodyMarkdown: "root", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now, PublishedAt: publishedAt,
	}
	if err := commentRepo.Create(ctx, root); err != nil {
		t.Fatalf("create root: %v", err)
	}
	reply := &domain.Comment{
		SiteID: site.ID, ThreadID: thread.ID, UserID: replier.ID, ParentID: &root.ID, RootID: &root.ID,
		ReplyToUserID: &owner.ID, Depth: 1,
		BodyMarkdown: "reply", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second), PublishedAt: publishedAt,
	}
	if err := commentRepo.Create(ctx, reply); err != nil {
		t.Fatalf("create reply: %v", err)
	}
	return accountDeleteFixture{
		OwnerID: owner.ID, ReplierID: replier.ID, RootID: root.ID, ReplyID: reply.ID, SiteID: site.ID,
	}
}

// newAccountDeleteService 装配身份服务，并把评论服务作为清理端口接线，
// 与组合根的 SetCommentDeleter 接线一致。
func newAccountDeleteService(t *testing.T, db *gorm.DB) *Service {
	t.Helper()
	store := &adminTestStore{}
	svc := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
		Prefs:    repository.NewPreferenceRepo(db),
		Cache:    &store.cache,
		Policy:   loginTestPolicy{},
	})
	commentService := comment.NewService(comment.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Comments: repository.NewCommentRepo(db),
	})
	svc.SetCommentDeleter(commentService)
	return svc
}

// TestAdminSoftDeleteUserKeepsOtherUsersReplies 验证软删除用户只软删其本人
// 评论，其他用户对这些评论的回复保持原状态。
func TestAdminSoftDeleteUserKeepsOtherUsersReplies(t *testing.T) {
	db := newAccountDeleteTestDB(t)
	fx := seedAccountDeleteFixture(t, db)
	svc := newAccountDeleteService(t, db)
	ctx := context.Background()

	if err := svc.AdminDeleteUser(ctx, fx.OwnerID+1000, fx.OwnerID, domain.UserDeleteModeSoft, false); err != nil {
		t.Fatalf("soft delete owner: %v", err)
	}
	repo := repository.NewCommentRepo(db)
	root, err := repo.FindGlobalByID(ctx, fx.RootID)
	if err != nil {
		t.Fatalf("find root: %v", err)
	}
	if root.Status != domain.CommentStatusDeleted {
		t.Fatalf("owner root must be soft-deleted, got %+v", root)
	}
	reply, err := repo.FindGlobalByID(ctx, fx.ReplyID)
	if err != nil {
		t.Fatalf("find reply: %v", err)
	}
	if reply.Status != domain.CommentStatusPublished {
		t.Fatalf("replier reply must stay published, got %+v", reply)
	}
	if reply.ParentID == nil || reply.RootID == nil {
		t.Fatalf("soft delete must keep reply tree refs, got parent=%v root=%v", reply.ParentID, reply.RootID)
	}
}

// TestAdminHardDeleteUserKeepsOtherUsersReplies 验证硬删除用户后，其本人评论
// 被级联删除，其他用户对这些评论的回复保留且 parent/root 引用被解除。
func TestAdminHardDeleteUserKeepsOtherUsersReplies(t *testing.T) {
	db := newAccountDeleteTestDB(t)
	fx := seedAccountDeleteFixture(t, db)
	svc := newAccountDeleteService(t, db)
	ctx := context.Background()

	if err := svc.AdminDeleteUser(ctx, fx.OwnerID+1000, fx.OwnerID, domain.UserDeleteModeHard, true); err != nil {
		t.Fatalf("hard delete owner: %v", err)
	}
	repo := repository.NewCommentRepo(db)
	if _, err := repo.FindGlobalByID(ctx, fx.RootID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("owner root must be cascade-deleted with the user: %v", err)
	}
	reply, err := repo.FindGlobalByID(ctx, fx.ReplyID)
	if err != nil {
		t.Fatalf("replier reply must survive: %v", err)
	}
	if reply.ParentID != nil || reply.RootID != nil {
		t.Fatalf("retained reply must have detached refs, got parent=%v root=%v", reply.ParentID, reply.RootID)
	}
	if reply.Status != domain.CommentStatusPublished || reply.BodyMarkdown != "reply" {
		t.Fatalf("retained reply changed: %+v", reply)
	}
	if reply.Depth != 1 {
		t.Fatalf("retained reply depth = %d, want retained 1", reply.Depth)
	}
	if reply.ReplyToUserID != nil {
		t.Fatalf("retained reply reply_to_user_id = %v, want SET NULL", *reply.ReplyToUserID)
	}
}

// TestAdminSoftDeleteUserDoesNotTouchOthersComments 验证软删除用户只处理
// 本人评论，完全不触碰其他用户的评论。
func TestAdminSoftDeleteUserDoesNotTouchOthersComments(t *testing.T) {
	db := newAccountDeleteTestDB(t)
	fx := seedAccountDeleteFixture(t, db)
	svc := newAccountDeleteService(t, db)
	ctx := context.Background()

	// 删除 replier（其回复是唯一归属），owner 的根评论保持原状。
	if err := svc.AdminDeleteUser(ctx, fx.OwnerID+1000, fx.ReplierID, domain.UserDeleteModeSoft, false); err != nil {
		t.Fatalf("soft delete replier: %v", err)
	}
	repo := repository.NewCommentRepo(db)
	root, err := repo.FindGlobalByID(ctx, fx.RootID)
	if err != nil {
		t.Fatalf("find root: %v", err)
	}
	if root.Status != domain.CommentStatusPublished {
		t.Fatalf("owner root must stay published, got %+v", root)
	}
	reply, err := repo.FindGlobalByID(ctx, fx.ReplyID)
	if err != nil {
		t.Fatalf("find reply: %v", err)
	}
	if reply.Status != domain.CommentStatusDeleted {
		t.Fatalf("replier reply must be soft-deleted, got %+v", reply)
	}
}

package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newCommentFKTestDB 打开临时 SQLite 数据库并迁移评论关系相关表。
func newCommentFKTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "comment-fk-repo-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}, &model.Comment{}, &model.CommentLike{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// seedReplyFixture 插入回复目标用户、作者、根评论所有者、站点与线程。
// root 由 rootOwner 发表；reply 由 author 回复 root，reply_to_user_id 指向
// target。target 仅作为被回复者，不拥有任何评论，便于验证 SET NULL。
func seedReplyFixture(t *testing.T, db *gorm.DB) (targetID, authorID, replyID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	userRepo := NewUserRepo(db)
	siteRepo := NewSiteRepo(db)
	threadRepo := NewThreadRepo(db)
	commentRepo := NewCommentRepo(db)

	target := &domain.User{Email: "target@example.com", EmailNormalized: "target@example.com", Nickname: "target", Role: domain.RoleUser, Status: domain.UserStatusActive}
	author := &domain.User{Email: "author@example.com", EmailNormalized: "author@example.com", Nickname: "author", Role: domain.RoleUser, Status: domain.UserStatusActive}
	rootOwner := &domain.User{Email: "root@example.com", EmailNormalized: "root@example.com", Nickname: "root", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, target); err != nil {
		t.Fatalf("create target user: %v", err)
	}
	if err := userRepo.Create(ctx, author); err != nil {
		t.Fatalf("create author user: %v", err)
	}
	if err := userRepo.Create(ctx, rootOwner); err != nil {
		t.Fatalf("create root owner user: %v", err)
	}

	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := threadRepo.ResolveOrCreate(ctx, site.ID, "page", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}

	publishedAt := &now
	root := &domain.Comment{
		SiteID: site.ID, ThreadID: thread.ID, UserID: rootOwner.ID, Depth: 0,
		BodyMarkdown: "root", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now, PublishedAt: publishedAt,
	}
	if err := commentRepo.Create(ctx, root); err != nil {
		t.Fatalf("create root comment: %v", err)
	}
	reply := &domain.Comment{
		SiteID: site.ID, ThreadID: thread.ID, UserID: author.ID, ParentID: &root.ID, RootID: &root.ID,
		ReplyToUserID: &target.ID, Depth: 1,
		BodyMarkdown: "reply", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second), PublishedAt: publishedAt,
	}
	if err := commentRepo.Create(ctx, reply); err != nil {
		t.Fatalf("create reply comment: %v", err)
	}
	return target.ID, author.ID, reply.ID
}

// TestCommentReplyToUserSetNullOnHardDelete 验证硬删除回复目标用户后，
// 回复的 reply_to_user_id 被外键 SET NULL 清空，回复本身保留。
func TestCommentReplyToUserSetNullOnHardDelete(t *testing.T) {
	db := newCommentFKTestDB(t)
	targetID, authorID, replyID := seedReplyFixture(t, db)
	ctx := context.Background()
	commentRepo := NewCommentRepo(db)

	before, err := commentRepo.FindGlobalByID(ctx, replyID)
	if err != nil {
		t.Fatalf("find reply before delete: %v", err)
	}
	if before.ReplyToUserID == nil || *before.ReplyToUserID != targetID {
		t.Fatalf("reply_to_user_id = %v, want target %d", before.ReplyToUserID, targetID)
	}

	if err := NewUserRepo(db).Delete(ctx, targetID); err != nil {
		t.Fatalf("hard delete target user: %v", err)
	}

	after, err := commentRepo.FindGlobalByID(ctx, replyID)
	if err != nil {
		t.Fatalf("find reply after delete: %v", err)
	}
	if after.ReplyToUserID != nil {
		t.Fatalf("reply_to_user_id = %v, want SET NULL", *after.ReplyToUserID)
	}
	if after.Status != domain.CommentStatusPublished {
		t.Fatalf("reply status = %s, want unchanged published", after.Status)
	}
	if after.UserID != authorID {
		// 防御性断言：author 未被删除，评论作者保持不变。
		t.Fatalf("reply user_id = %d, want author %d", after.UserID, authorID)
	}
}

// TestCommentSiteDeleteCascadesThreadAndComments 验证删除站点会硬删除其下
// 全部 thread 与 comment，且不影响其他站点的数据。
func TestCommentSiteDeleteCascadesThreadAndComments(t *testing.T) {
	db := newCommentFKTestDB(t)
	_, _, replyID := seedReplyFixture(t, db)
	ctx := context.Background()
	siteRepo := NewSiteRepo(db)
	threadRepo := NewThreadRepo(db)
	commentRepo := NewCommentRepo(db)

	reply, err := commentRepo.FindGlobalByID(ctx, replyID)
	if err != nil {
		t.Fatalf("find seeded reply: %v", err)
	}
	targetSiteID := reply.SiteID
	if targetSiteID == 0 {
		t.Fatal("fixture must seed a site")
	}

	// 另一个站点及其线程/评论必须保留。
	otherSite := &domain.Site{Name: "Other", CanonicalURL: "https://other.example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, otherSite); err != nil {
		t.Fatalf("create other site: %v", err)
	}
	otherThread, err := threadRepo.ResolveOrCreate(ctx, otherSite.ID, "other-page", nil, nil)
	if err != nil {
		t.Fatalf("resolve other thread: %v", err)
	}
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	publishedAt := &now
	otherComment := &domain.Comment{
		SiteID: otherSite.ID, ThreadID: otherThread.ID, UserID: reply.UserID, Depth: 0,
		BodyMarkdown: "other", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now, PublishedAt: publishedAt,
	}
	if err := commentRepo.Create(ctx, otherComment); err != nil {
		t.Fatalf("create other comment: %v", err)
	}

	if err := siteRepo.Delete(ctx, targetSiteID); err != nil {
		t.Fatalf("delete site: %v", err)
	}

	var deletedThreads int64
	if err := db.Model(&model.Thread{}).Where("site_id = ?", targetSiteID).Count(&deletedThreads).Error; err != nil {
		t.Fatalf("count deleted site threads: %v", err)
	}
	if deletedThreads != 0 {
		t.Fatalf("deleted site threads = %d, want 0", deletedThreads)
	}
	var deletedComments int64
	if err := db.Model(&model.Comment{}).Where("site_id = ?", targetSiteID).Count(&deletedComments).Error; err != nil {
		t.Fatalf("count deleted site comments: %v", err)
	}
	if deletedComments != 0 {
		t.Fatalf("deleted site comments = %d, want 0", deletedComments)
	}

	var otherThreads int64
	if err := db.Model(&model.Thread{}).Where("site_id = ?", otherSite.ID).Count(&otherThreads).Error; err != nil {
		t.Fatalf("count other threads: %v", err)
	}
	if otherThreads != 1 {
		t.Fatalf("other site threads = %d, want 1", otherThreads)
	}
	var otherComments int64
	if err := db.Model(&model.Comment{}).Where("site_id = ?", otherSite.ID).Count(&otherComments).Error; err != nil {
		t.Fatalf("count other comments: %v", err)
	}
	if otherComments != 1 {
		t.Fatalf("other site comments = %d, want 1", otherComments)
	}

	if _, err := threadRepo.GetBySiteAndID(ctx, otherSite.ID, otherThread.ID); err != nil {
		t.Fatalf("other thread must survive: %v", err)
	}
	if _, err := commentRepo.FindBySiteAndID(ctx, otherSite.ID, otherComment.ID); errors.Is(err, domain.ErrNotFound) {
		t.Fatal("other site comment must survive")
	}
}

// seedThreadDeleteFixture 插入站点、目标线程（含父子评论）与其他站点的
// 保留线程/评论，返回各 ID 以便断言级联删除的范围。
func seedThreadDeleteFixture(t *testing.T, db *gorm.DB) (targetSiteID, targetThreadID, targetRootID int64, otherSiteID int64, otherThreadID, otherCommentID int64) {
	t.Helper()
	ctx := context.Background()
	siteRepo := NewSiteRepo(db)
	threadRepo := NewThreadRepo(db)
	commentRepo := NewCommentRepo(db)
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	publishedAt := &now

	site := &domain.Site{Name: "Target", CanonicalURL: "https://target.example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := threadRepo.ResolveOrCreate(ctx, site.ID, "target-page", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	user := &domain.User{Email: "a@example.com", EmailNormalized: "a@example.com", Nickname: "a", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := NewUserRepo(db).Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	root := &domain.Comment{
		SiteID: site.ID, ThreadID: thread.ID, UserID: user.ID, Depth: 0,
		BodyMarkdown: "root", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now, PublishedAt: publishedAt,
	}
	if err := commentRepo.Create(ctx, root); err != nil {
		t.Fatalf("create root: %v", err)
	}
	reply := &domain.Comment{
		SiteID: site.ID, ThreadID: thread.ID, UserID: user.ID, ParentID: &root.ID, RootID: &root.ID, Depth: 1,
		BodyMarkdown: "reply", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second), PublishedAt: publishedAt,
	}
	if err := commentRepo.Create(ctx, reply); err != nil {
		t.Fatalf("create reply: %v", err)
	}

	otherSite := &domain.Site{Name: "Other", CanonicalURL: "https://other.example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, otherSite); err != nil {
		t.Fatalf("create other site: %v", err)
	}
	otherThread, err := threadRepo.ResolveOrCreate(ctx, otherSite.ID, "other-page", nil, nil)
	if err != nil {
		t.Fatalf("resolve other thread: %v", err)
	}
	otherComment := &domain.Comment{
		SiteID: otherSite.ID, ThreadID: otherThread.ID, UserID: user.ID, Depth: 0,
		BodyMarkdown: "other", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now, PublishedAt: publishedAt,
	}
	if err := commentRepo.Create(ctx, otherComment); err != nil {
		t.Fatalf("create other comment: %v", err)
	}
	return site.ID, thread.ID, root.ID, otherSite.ID, otherThread.ID, otherComment.ID
}

// TestThreadRepoDeleteThreadCascadesComments 验证删除 thread 会硬删除其下
// 全部父子评论（依赖复合外键 CASCADE），同时保留作者用户、其他站点与其他
// 线程的数据。
func TestThreadRepoDeleteThreadCascadesComments(t *testing.T) {
	db := newCommentFKTestDB(t)
	targetSiteID, targetThreadID, _, otherSiteID, otherThreadID, otherCommentID := seedThreadDeleteFixture(t, db)
	ctx := context.Background()
	threadRepo := NewThreadRepo(db)
	commentRepo := NewCommentRepo(db)

	if err := threadRepo.DeleteThread(ctx, targetSiteID, targetThreadID); err != nil {
		t.Fatalf("delete thread: %v", err)
	}

	if _, err := threadRepo.GetBySiteAndID(ctx, targetSiteID, targetThreadID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("target thread must be gone, got err=%v", err)
	}
	var targetComments int64
	if err := db.Model(&model.Comment{}).Where("site_id = ? AND thread_id = ?", targetSiteID, targetThreadID).Count(&targetComments).Error; err != nil {
		t.Fatalf("count target comments: %v", err)
	}
	if targetComments != 0 {
		t.Fatalf("target thread comments = %d, want 0 (cascade failed)", targetComments)
	}
	var targetAllComments int64
	if err := db.Model(&model.Comment{}).Where("site_id = ?", targetSiteID).Count(&targetAllComments).Error; err != nil {
		t.Fatalf("count target site comments: %v", err)
	}
	if targetAllComments != 0 {
		t.Fatalf("target site comments = %d, want 0", targetAllComments)
	}

	// 作者用户行保留：删除线程不得级联删除评论作者。
	var userCount int64
	if err := db.Model(&model.User{}).Count(&userCount).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("users = %d, want 1 preserved", userCount)
	}

	// 其他站点/线程数据保留。
	if _, err := threadRepo.GetBySiteAndID(ctx, otherSiteID, otherThreadID); err != nil {
		t.Fatalf("other thread must survive: %v", err)
	}
	if _, err := commentRepo.FindBySiteAndID(ctx, otherSiteID, otherCommentID); err != nil {
		t.Fatalf("other comment must survive: %v", err)
	}
	var otherComments int64
	if err := db.Model(&model.Comment{}).Where("site_id = ?", otherSiteID).Count(&otherComments).Error; err != nil {
		t.Fatalf("count other comments: %v", err)
	}
	if otherComments != 1 {
		t.Fatalf("other site comments = %d, want 1", otherComments)
	}
}

// TestThreadRepoDeleteThreadCrossSiteGuard 验证用错误站点删除线程返回
// domain.ErrNotFound，且不删除任何数据。
func TestThreadRepoDeleteThreadCrossSiteGuard(t *testing.T) {
	db := newCommentFKTestDB(t)
	targetSiteID, targetThreadID, rootID, otherSiteID, _, otherCommentID := seedThreadDeleteFixture(t, db)
	ctx := context.Background()
	threadRepo := NewThreadRepo(db)

	if err := threadRepo.DeleteThread(ctx, otherSiteID, targetThreadID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-site delete err = %v, want ErrNotFound", err)
	}
	if _, err := threadRepo.GetBySiteAndID(ctx, targetSiteID, targetThreadID); err != nil {
		t.Fatalf("target thread must survive: %v", err)
	}
	if _, err := NewCommentRepo(db).FindBySiteAndID(ctx, targetSiteID, rootID); err != nil {
		t.Fatalf("target root must survive: %v", err)
	}
	if _, err := NewCommentRepo(db).FindBySiteAndID(ctx, otherSiteID, otherCommentID); err != nil {
		t.Fatalf("other comment must survive: %v", err)
	}
}

// TestThreadRepoDeleteThreadMissing 验证删除不存在的 thread 返回
// domain.ErrNotFound。
func TestThreadRepoDeleteThreadMissing(t *testing.T) {
	db := newCommentFKTestDB(t)
	siteID, _, _, _, _, _ := seedThreadDeleteFixture(t, db)
	ctx := context.Background()
	if err := NewThreadRepo(db).DeleteThread(ctx, siteID, 999999); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing thread err = %v, want ErrNotFound", err)
	}
}

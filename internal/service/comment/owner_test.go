package comment

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

	"gorm.io/gorm"
)

// ownerTestDB 打开临时 SQLite 数据库并迁移评论相关表。
func ownerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "owner-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}, &model.Comment{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// ownerService 构建带固定策略与真实仓储的评论服务。
func ownerService(db *gorm.DB, deleteMode string) *Service {
	return &Service{
		txRunner: gormtx.NewRunner(db),
		threads:  repository.NewThreadRepo(db),
		comments: repository.NewCommentRepo(db),
		sites:    repository.NewSiteRepo(db),
		users:    repository.NewUserRepo(db),
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:            domain.CommentModeAuthenticated,
			Moderation:      domain.ModerationDirect,
			UserDeleteMode:  deleteMode,
			MaxReplyDepth:   5,
			CaptchaPolicy:   map[string]bool{},
			GravatarBaseURL: "https://www.gravatar.com/avatar",
			Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
			CommentSort:     string(domain.CommentSortAsc),
		}},
		captcha: &replyCaptchaVerifier{},
		bus:     &recordingEventBus{},
		now:     func() time.Time { return time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC) },
	}
}

// ownerFixture 是本人评论列表测试的种子数据。
type ownerFixture struct {
	OwnerID   int64
	OtherID   int64
	SiteID    int64
	Published int64
	Pending   int64
	Spam      int64
	Deleted   int64
	Other     int64
}

// seedOwnerComments 插入两位用户、一个站点与四个状态的本人评论。
func seedOwnerComments(t *testing.T, db *gorm.DB) ownerFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	userRepo := repository.NewUserRepo(db)
	siteRepo := repository.NewSiteRepo(db)
	threadRepo := repository.NewThreadRepo(db)
	commentRepo := repository.NewCommentRepo(db)

	owner := &domain.User{Email: "owner@example.com", EmailNormalized: "owner@example.com", Nickname: "owner", Role: domain.RoleUser, Status: domain.UserStatusActive}
	other := &domain.User{Email: "other@example.com", EmailNormalized: "other@example.com", Nickname: "other", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := userRepo.Create(ctx, other); err != nil {
		t.Fatalf("create other: %v", err)
	}
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := threadRepo.ResolveOrCreate(ctx, site.ID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}

	fx := ownerFixture{OwnerID: owner.ID, OtherID: other.ID, SiteID: site.ID}
	ids := make(map[string]int64)
	for _, sc := range []struct {
		key    string
		user   int64
		status domain.CommentStatus
	}{
		{"published", owner.ID, domain.CommentStatusPublished},
		{"pending", owner.ID, domain.CommentStatusPending},
		{"spam", owner.ID, domain.CommentStatusSpam},
		{"deleted", owner.ID, domain.CommentStatusDeleted},
		{"other", other.ID, domain.CommentStatusPublished},
	} {
		var publishedAt *time.Time
		if sc.status == domain.CommentStatusPublished {
			publishedAt = &now
		}
		c := &domain.Comment{
			SiteID: site.ID, ThreadID: thread.ID, UserID: sc.user, Depth: 0,
			BodyMarkdown: "body-" + sc.key, Status: sc.status,
			IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: now.Add(time.Duration(len(ids)) * time.Second), UpdatedAt: now,
			PublishedAt: publishedAt,
		}
		if err := commentRepo.Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", sc.key, err)
		}
		ids[sc.key] = c.ID
	}
	fx.Published, fx.Pending, fx.Spam, fx.Deleted = ids["published"], ids["pending"], ids["spam"], ids["deleted"]
	fx.Other = ids["other"]
	return fx
}

// TestListByOwnerScopesOwnerAndFilters 验证本人评论只返回当前用户，且站点/状态筛选可组合。
func TestListByOwnerScopesOwnerAndFilters(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	all, err := svc.ListByOwner(ctx, fx.OwnerID, nil, nil, 1, 50)
	if err != nil {
		t.Fatalf("list by owner: %v", err)
	}
	if len(all.Comments) != 4 {
		t.Fatalf("owner comments = %d, want 4 (other excluded)", len(all.Comments))
	}
	for _, c := range all.Comments {
		if c.UserID != fx.OwnerID {
			t.Fatalf("comment %d user = %d, want owner", c.ID, c.UserID)
		}
		if c.SiteName == "" || c.PageKey == "" {
			t.Fatalf("comment %d missing public metadata", c.ID)
		}
		if all.UserDeleteMode != domain.UserDeleteModeSoft {
			t.Fatalf("user_delete_mode = %q, want soft", all.UserDeleteMode)
		}
	}

	pending := domain.CommentStatusPending
	filtered, err := svc.ListByOwner(ctx, fx.OwnerID, &fx.SiteID, &pending, 1, 50)
	if err != nil {
		t.Fatalf("filtered list: %v", err)
	}
	if len(filtered.Comments) != 1 || filtered.Comments[0].ID != fx.Pending {
		t.Fatalf("pending rows = %+v, want only pending", filtered.Comments)
	}
}

// TestListByOwnerPagePagination 验证本人评论 (created_at,id) 偏移分页无重复、无缺口，
// 且每页携带与过滤条件一致的真实总数。
func TestListByOwnerPagePagination(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	page1, err := svc.ListByOwner(context.Background(), fx.OwnerID, nil, nil, 1, 2)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(page1.Comments) != 2 || page1.Total != 4 {
		t.Fatalf("page1 = %d rows total=%d, want 2 rows + total 4", len(page1.Comments), page1.Total)
	}
	page2, err := svc.ListByOwner(context.Background(), fx.OwnerID, nil, nil, 2, 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2.Comments) != 2 || page2.Total != 4 {
		t.Fatalf("page2 = %d rows total=%d, want 2 rows + total 4", len(page2.Comments), page2.Total)
	}
	outOfRange, err := svc.ListByOwner(context.Background(), fx.OwnerID, nil, nil, 9, 2)
	if err != nil {
		t.Fatalf("out-of-range page: %v", err)
	}
	if len(outOfRange.Comments) != 0 || outOfRange.Total != 4 {
		t.Fatalf("out-of-range = %d rows total=%d, want 0 rows + total 4", len(outOfRange.Comments), outOfRange.Total)
	}

	seen := map[int64]bool{}
	for _, page := range [][]OwnerCommentView{page1.Comments, page2.Comments} {
		for _, c := range page {
			if seen[c.ID] {
				t.Fatalf("duplicate comment %d across pages", c.ID)
			}
			seen[c.ID] = true
		}
	}
	if len(seen) != 4 {
		t.Fatalf("unique ids = %d, want 4 (no gaps)", len(seen))
	}
}

// TestGetByOwnerScopesOwner 验证详情只返回本人评论，他人评论为 404。
func TestGetByOwnerScopesOwner(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	got, err := svc.GetByOwner(ctx, fx.OwnerID, fx.Published)
	if err != nil {
		t.Fatalf("get own comment: %v", err)
	}
	if got.View.ID != fx.Published || got.View.AuthorAvatarURL == "" {
		t.Fatalf("got = %+v", got)
	}
	if got.UserDeleteMode != domain.UserDeleteModeSoft {
		t.Fatalf("delete mode = %q, want soft", got.UserDeleteMode)
	}

	if _, err := svc.GetByOwner(ctx, fx.OwnerID, fx.Published+99999); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing err = %v, want ErrNotFound", err)
	}
}

// TestGetByOwnerNeverExposesOtherUsers 验证跨用户详情始终 404，不泄露存在性。
func TestGetByOwnerNeverExposesOtherUsers(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	others, err := svc.ListByOwner(context.Background(), fx.OtherID, nil, nil, 1, 50)
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	for _, c := range others.Comments {
		if _, err := svc.GetByOwner(context.Background(), fx.OwnerID, c.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("cross-user get %d err = %v, want ErrNotFound", c.ID, err)
		}
	}
}

// TestListOwnerSites 验证站点选项按本人评论去重。
func TestListOwnerSites(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	sites, err := svc.ListOwnerSites(context.Background(), fx.OwnerID)
	if err != nil {
		t.Fatalf("list owner sites: %v", err)
	}
	if len(sites) != 1 || sites[0].ID != fx.SiteID || sites[0].Name != "Site" {
		t.Fatalf("sites = %+v", sites)
	}
}

// TestDeleteByOwnerStateMatrix 验证删除只允许 pending/published/spam，deleted 只读拒绝重复删除。
func TestDeleteByOwnerStateMatrix(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	cases := []struct {
		name    string
		id      int64
		wantErr error
	}{
		{name: "published deletable", id: fx.Published, wantErr: nil},
		{name: "pending deletable", id: fx.Pending, wantErr: nil},
		{name: "spam deletable", id: fx.Spam, wantErr: nil},
		{name: "deleted read-only", id: fx.Deleted, wantErr: domain.ErrConflict},
		{name: "other user forbidden", id: fx.Other, wantErr: domain.ErrForbidden},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.DeleteByOwner(ctx, fx.OwnerID, tt.id, nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestDeleteByOwnerSoftKeepsPlaceholder 验证 soft 模式保留状态前值与删除时间，正文占位由 DTO 层负责。
func TestDeleteByOwnerSoftKeepsPlaceholder(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	result, err := svc.DeleteByOwner(context.Background(), fx.OwnerID, fx.Published, nil)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if result.Hard {
		t.Fatal("soft delete reported hard=true")
	}
	row, err := repository.NewCommentRepo(db).FindGlobalByID(context.Background(), fx.Published)
	if err != nil {
		t.Fatalf("find deleted comment: %v", err)
	}
	if row.Status != domain.CommentStatusDeleted || row.StatusBeforeDelete == nil || *row.StatusBeforeDelete != domain.CommentStatusPublished || row.DeletedAt == nil {
		t.Fatalf("soft-deleted row = %+v", row)
	}
}

// TestDeleteByOwnerHardKeepsReplies 验证 hard 模式永久删除目标单条，
// 其回复保留原状态与正文，且解除的 parent/root 引用不产生悬空外键。
func TestDeleteByOwnerHardKeepsReplies(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeHard)
	ctx := context.Background()

	// 给 published 加一条回复，形成父子关系。
	reply, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Published, "a reply", "", nil, "test-agent")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}

	result, err := svc.DeleteByOwner(ctx, fx.OwnerID, fx.Published, nil)
	if err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if !result.Hard {
		t.Fatal("hard delete reported hard=false")
	}
	repo := repository.NewCommentRepo(db)
	if _, err := repo.FindGlobalByID(ctx, fx.Published); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("root still exists: %v", err)
	}
	kept, err := repo.FindGlobalByID(ctx, reply.ID)
	if err != nil {
		t.Fatalf("reply must survive hard delete: %v", err)
	}
	if kept.Status != domain.CommentStatusPublished || kept.BodyMarkdown != "a reply" {
		t.Fatalf("reply changed after parent hard delete: %+v", kept)
	}
	if kept.ParentID != nil || kept.RootID != nil {
		t.Fatalf("reply must have detached parent/root refs, got parent=%v root=%v", kept.ParentID, kept.RootID)
	}
	if kept.Depth != 1 {
		t.Fatalf("reply depth = %d, want retained 1", kept.Depth)
	}
}

// TestReplyOnlyPublished 验证第一方回复只允许 published 父评论。
func TestReplyOnlyPublished(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	if _, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Published, "ok", "", nil, "ua"); err != nil {
		t.Fatalf("reply to published: %v", err)
	}
	if _, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Pending, "no", "", nil, "ua"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("reply to pending err = %v, want ErrConflict", err)
	}
	if _, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Spam, "no", "", nil, "ua"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("reply to spam err = %v, want ErrConflict", err)
	}
	if _, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Deleted, "no", "", nil, "ua"); !errors.Is(err, domain.ErrParentDeleted) {
		t.Fatalf("reply to deleted err = %v, want ErrParentDeleted", err)
	}
}

// TestDeleteByOwnerSoftDeletesOnlySelected 验证 soft 模式只软删选中评论，
// 其回复保持原状态。
func TestDeleteByOwnerSoftDeletesOnlySelected(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	reply1, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Published, "reply 1", "", nil, "ua")
	if err != nil {
		t.Fatalf("create reply 1: %v", err)
	}

	result, err := svc.DeleteByOwner(ctx, fx.OwnerID, fx.Published, nil)
	if err != nil {
		t.Fatalf("soft delete root: %v", err)
	}
	if result.Hard {
		t.Fatal("soft delete reported hard=true")
	}

	repo := repository.NewCommentRepo(db)
	rootRow, err := repo.FindGlobalByID(ctx, fx.Published)
	if err != nil {
		t.Fatalf("find root: %v", err)
	}
	if rootRow.Status != domain.CommentStatusDeleted || rootRow.StatusBeforeDelete == nil || *rootRow.StatusBeforeDelete != domain.CommentStatusPublished || rootRow.DeletedAt == nil {
		t.Fatalf("soft-deleted root = %+v", rootRow)
	}

	keptReply, err := repo.FindGlobalByID(ctx, reply1.ID)
	if err != nil {
		t.Fatalf("reply must survive soft delete: %v", err)
	}
	if keptReply.Status != domain.CommentStatusPublished {
		t.Fatalf("reply must stay published, got %+v", keptReply)
	}

	// 管理员恢复根：只恢复目标单条。
	if _, err := svc.AdminRestore(ctx, fx.Published); err != nil {
		t.Fatalf("admin restore root: %v", err)
	}
	restoredRoot, _ := repo.FindGlobalByID(ctx, fx.Published)
	if restoredRoot.Status != domain.CommentStatusPublished || restoredRoot.DeletedAt != nil {
		t.Fatalf("root restore = %+v", restoredRoot)
	}
}

// TestAdminDeleteSoftDeletesOnlySelected 验证管理员 soft 删除只处理选中评论，
// 其回复保持原状态。
func TestAdminDeleteSoftDeletesOnlySelected(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	reply, err := svc.CreateReplyFirstParty(ctx, fx.OwnerID, domain.RoleUser, fx.Published, "reply", "", nil, "ua")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}

	result, err := svc.AdminDelete(ctx, fx.Published, false, false)
	if err != nil {
		t.Fatalf("admin soft delete: %v", err)
	}
	if result.Hard {
		t.Fatal("soft delete reported hard=true")
	}
	repo := repository.NewCommentRepo(db)
	rootRow, err := repo.FindGlobalByID(ctx, fx.Published)
	if err != nil {
		t.Fatalf("find root: %v", err)
	}
	if rootRow.Status != domain.CommentStatusDeleted {
		t.Fatalf("root not soft-deleted: %+v", rootRow)
	}
	keptReply, err := repo.FindGlobalByID(ctx, reply.ID)
	if err != nil {
		t.Fatalf("reply must survive: %v", err)
	}
	if keptReply.Status != domain.CommentStatusPublished {
		t.Fatalf("reply must stay published, got %+v", keptReply)
	}
}

// TestPublicListExcludesDeleted 验证公共列表完全排除已删除评论。
func TestPublicListExcludesDeleted(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	view, err := svc.ListPublic(ctx, fx.SiteID, "page-key", "", "", 50)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	for _, c := range view.Comments {
		if c.Status == domain.CommentStatusDeleted {
			t.Fatalf("public list contains deleted comment %d", c.ID)
		}
		if c.BodyMarkdown == "（该评论已被删除）" {
			t.Fatalf("public list contains placeholder body on comment %d", c.ID)
		}
	}
}

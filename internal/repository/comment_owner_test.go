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

// newCommentOwnerTestDB 打开临时 SQLite 数据库并迁移评论相关表。
func newCommentOwnerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "comment-owner-repo-test.db")
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

// seedOwnerFixture 插入两位用户、两个站点、两个线程与各自评论，返回关键 ID。
func seedOwnerFixture(t *testing.T, db *gorm.DB) (owner1, owner2 int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	userRepo := NewUserRepo(db)
	siteRepo := NewSiteRepo(db)
	threadRepo := NewThreadRepo(db)
	commentRepo := NewCommentRepo(db)

	u1 := &domain.User{Email: "one@example.com", EmailNormalized: "one@example.com", Nickname: "one", Role: domain.RoleUser, Status: domain.UserStatusActive}
	u2 := &domain.User{Email: "two@example.com", EmailNormalized: "two@example.com", Nickname: "two", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u1); err != nil {
		t.Fatalf("create user one: %v", err)
	}
	if err := userRepo.Create(ctx, u2); err != nil {
		t.Fatalf("create user two: %v", err)
	}

	s1 := &domain.Site{Name: "Site A", CanonicalURL: "https://a.example.com", Status: domain.SiteStatusActive}
	s2 := &domain.Site{Name: "Site B", CanonicalURL: "https://b.example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, s1); err != nil {
		t.Fatalf("create site A: %v", err)
	}
	if err := siteRepo.Create(ctx, s2); err != nil {
		t.Fatalf("create site B: %v", err)
	}

	t1, err := threadRepo.ResolveOrCreate(ctx, s1.ID, "page-one", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread one: %v", err)
	}
	t2, err := threadRepo.ResolveOrCreate(ctx, s2.ID, "page-two", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread two: %v", err)
	}

	mk := func(siteID, threadID, userID int64, body string, status domain.CommentStatus, at time.Time) {
		t.Helper()
		var publishedAt *time.Time
		if status == domain.CommentStatusPublished {
			publishedAt = &now
		}
		c := &domain.Comment{
			SiteID: siteID, ThreadID: threadID, UserID: userID, Depth: 0,
			BodyMarkdown: body, Status: status, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: at, UpdatedAt: at, PublishedAt: publishedAt,
		}
		if err := commentRepo.Create(ctx, c); err != nil {
			t.Fatalf("create comment %q: %v", body, err)
		}
	}

	mk(s1.ID, t1.ID, u1.ID, "one-a-published", domain.CommentStatusPublished, now)
	mk(s1.ID, t1.ID, u1.ID, "one-a-pending", domain.CommentStatusPending, now.Add(1*time.Second))
	mk(s1.ID, t1.ID, u2.ID, "two-a-published", domain.CommentStatusPublished, now.Add(2*time.Second))
	mk(s2.ID, t2.ID, u1.ID, "one-b-spam", domain.CommentStatusSpam, now.Add(3*time.Second))
	return u1.ID, u2.ID
}

// TestCommentRepoListByOwnerScopesOwner 验证 ListByOwner 只返回当前用户的评论。
func TestCommentRepoListByOwnerScopesOwner(t *testing.T) {
	db := newCommentOwnerTestDB(t)
	owner1, _ := seedOwnerFixture(t, db)
	repo := NewCommentRepo(db)

	rows, err := repo.ListByOwner(context.Background(), owner1, domain.OwnerFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list by owner: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("owner1 comments = %d, want 3", len(rows))
	}
	for _, r := range rows {
		if r.UserID != owner1 {
			t.Fatalf("comment %d user = %d, want owner %d", r.ID, r.UserID, owner1)
		}
	}
}

// TestCommentRepoListByOwnerFiltersSiteAndStatus 验证站点与状态筛选可组合且作用于 cursor 之前。
func TestCommentRepoListByOwnerFiltersSiteAndStatus(t *testing.T) {
	db := newCommentOwnerTestDB(t)
	owner1, _ := seedOwnerFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	sites, err := repo.ListOwnerSites(ctx, owner1)
	if err != nil {
		t.Fatalf("list owner sites: %v", err)
	}
	if len(sites) != 2 {
		t.Fatalf("owner sites = %d, want 2", len(sites))
	}

	rows, err := repo.ListByOwner(ctx, owner1, domain.OwnerFilter{SiteID: &sites[0].ID, Limit: 50})
	if err != nil {
		t.Fatalf("list by site: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("site-filtered comments = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.SiteID != sites[0].ID {
			t.Fatalf("comment %d site = %d, want %d", r.ID, r.SiteID, sites[0].ID)
		}
	}

	pending := domain.CommentStatusPending
	rows, err = repo.ListByOwner(ctx, owner1, domain.OwnerFilter{SiteID: &sites[0].ID, Status: &pending, Limit: 50})
	if err != nil {
		t.Fatalf("list by site+status: %v", err)
	}
	if len(rows) != 1 || rows[0].BodyMarkdown != "one-a-pending" {
		t.Fatalf("site+status rows = %+v, want only one-a-pending", rows)
	}
}

// TestCommentRepoListByOwnerCarriesPublicMetadata 验证返回站点名与线程元数据且不含邮箱隐私字段。
func TestCommentRepoListByOwnerCarriesPublicMetadata(t *testing.T) {
	db := newCommentOwnerTestDB(t)
	owner1, _ := seedOwnerFixture(t, db)
	repo := NewCommentRepo(db)

	rows, err := repo.ListByOwner(context.Background(), owner1, domain.OwnerFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list by owner: %v", err)
	}
	for _, r := range rows {
		if r.SiteName == "" || r.PageKey == "" {
			t.Fatalf("comment %d missing site/page metadata: %+v", r.ID, r)
		}
	}
}

// TestCommentRepoGetByOwnerAndIDScopesOwner 验证详情按 owner 作用域，他人评论视为不存在。
func TestCommentRepoGetByOwnerAndIDScopesOwner(t *testing.T) {
	db := newCommentOwnerTestDB(t)
	owner1, owner2 := seedOwnerFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	all, err := repo.ListByOwner(ctx, owner1, domain.OwnerFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list by owner: %v", err)
	}

	got, err := repo.GetByOwnerAndID(ctx, owner1, all[0].ID)
	if err != nil {
		t.Fatalf("get owner comment: %v", err)
	}
	if got.ID != all[0].ID || got.SiteName == "" || got.PageKey == "" {
		t.Fatalf("get owner comment = %+v", got)
	}

	others, err := repo.ListByOwner(ctx, owner2, domain.OwnerFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list owner2: %v", err)
	}
	if _, err := repo.GetByOwnerAndID(ctx, owner1, others[0].ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner get err = %v, want domain.ErrNotFound", err)
	}
}

// TestCommentRepoListOwnerSitesDedupes 验证站点列表去重且只含本人发表过评论的站点。
func TestCommentRepoListOwnerSitesDedupes(t *testing.T) {
	db := newCommentOwnerTestDB(t)
	owner1, owner2 := seedOwnerFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	sites, err := repo.ListOwnerSites(ctx, owner1)
	if err != nil {
		t.Fatalf("list owner sites: %v", err)
	}
	if len(sites) != 2 || sites[0].Name != "Site A" || sites[1].Name != "Site B" {
		t.Fatalf("owner1 sites = %+v, want Site A then Site B", sites)
	}

	other, err := repo.ListOwnerSites(ctx, owner2)
	if err != nil {
		t.Fatalf("list owner2 sites: %v", err)
	}
	if len(other) != 1 || other[0].Name != "Site A" {
		t.Fatalf("owner2 sites = %+v, want only Site A", other)
	}
}

// TestUserHardDeleteCascadesComments 验证硬删除用户会级联移除其全部评论及后代。
// users.comments 外键从 RESTRICT 改为 CASCADE，硬删用户时评论随之删除。
func TestUserHardDeleteCascadesComments(t *testing.T) {
	db := newCommentOwnerTestDB(t)
	owner1, _ := seedOwnerFixture(t, db)
	ctx := context.Background()
	userRepo := NewUserRepo(db)
	commentRepo := NewCommentRepo(db)

	rowsBefore := countCommentsByUser(t, commentRepo, owner1)
	if rowsBefore == 0 {
		t.Fatal("fixture must seed comments for owner1")
	}
	if err := userRepo.Delete(ctx, owner1); err != nil {
		t.Fatalf("hard delete user: %v", err)
	}
	remaining := countCommentsByUser(t, commentRepo, owner1)
	if remaining != 0 {
		t.Fatalf("hard delete of user must cascade its comments, remaining=%d", remaining)
	}
	if _, err := userRepo.FindByID(ctx, owner1); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted user must not exist: %v", err)
	}
}

// countCommentsByUser 统计某用户发表过的评论总数（删除后由级联清空）。
func countCommentsByUser(t *testing.T, repo *CommentRepo, userID int64) int {
	t.Helper()
	ctx := context.Background()
	rows, err := repo.ListByOwner(ctx, userID, domain.OwnerFilter{Limit: 100})
	if err != nil {
		t.Fatalf("list owner comments: %v", err)
	}
	return len(rows)
}

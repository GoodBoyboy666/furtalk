package repository

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

func newLatestTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "comment-latest-repo-test.db")
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

// TestCommentRepoListLatestPublic 验证 ListLatestPublic 的站点隔离、状态过滤、页面元数据、排序以及数量限制。
func TestCommentRepoListLatestPublic(t *testing.T) {
	db := newLatestTestDB(t)
	ctx := context.Background()
	userRepo := NewUserRepo(db)
	siteRepo := NewSiteRepo(db)
	threadRepo := NewThreadRepo(db)
	commentRepo := NewCommentRepo(db)

	u1 := &domain.User{Email: "u1@example.com", EmailNormalized: "u1@example.com", Nickname: "User1", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u1); err != nil {
		t.Fatalf("create user1: %v", err)
	}
	u2 := &domain.User{Email: "u2@example.com", EmailNormalized: "u2@example.com", Nickname: "User2", Role: domain.RoleAdmin, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u2); err != nil {
		t.Fatalf("create user2: %v", err)
	}

	site1 := &domain.Site{Name: "Site 1", CanonicalURL: "https://site1.example", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site1); err != nil {
		t.Fatalf("create site1: %v", err)
	}
	site2 := &domain.Site{Name: "Site 2", CanonicalURL: "https://site2.example", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site2); err != nil {
		t.Fatalf("create site2: %v", err)
	}

	url1 := "https://site1.example/page1"
	title1 := "Page 1 Title"
	t1p1, err := threadRepo.ResolveOrCreate(ctx, site1.ID, "p1", &url1, &title1)
	if err != nil {
		t.Fatalf("create thread1: %v", err)
	}
	url2 := "https://site1.example/page2"
	title2 := "Page 2 Title"
	t1p2, err := threadRepo.ResolveOrCreate(ctx, site1.ID, "p2", &url2, &title2)
	if err != nil {
		t.Fatalf("create thread2: %v", err)
	}
	t2p1, err := threadRepo.ResolveOrCreate(ctx, site2.ID, "p1", nil, nil)
	if err != nil {
		t.Fatalf("create thread3: %v", err)
	}

	base := time.Date(2026, time.August, 19, 10, 0, 0, 0, time.UTC)

	// Site 1 comments
	// c1: thread 1, created at base, published
	c1 := &domain.Comment{
		SiteID: site1.ID, ThreadID: t1p1.ID, UserID: u1.ID, Depth: 0,
		BodyMarkdown: "c1", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: base, UpdatedAt: base, PublishedAt: &base,
	}
	if err := commentRepo.Create(ctx, c1); err != nil {
		t.Fatalf("create c1: %v", err)
	}

	// c2: thread 2, created at base (same timestamp as c1, higher ID), published
	c2 := &domain.Comment{
		SiteID: site1.ID, ThreadID: t1p2.ID, UserID: u2.ID, ReplyToUserID: &u1.ID, Depth: 1,
		BodyMarkdown: "c2", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: base, UpdatedAt: base, PublishedAt: &base,
	}
	if err := commentRepo.Create(ctx, c2); err != nil {
		t.Fatalf("create c2: %v", err)
	}

	// c3: thread 1, created at base + 1h, published
	t3 := base.Add(time.Hour)
	c3 := &domain.Comment{
		SiteID: site1.ID, ThreadID: t1p1.ID, UserID: u1.ID, Depth: 0,
		BodyMarkdown: "c3", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: t3, UpdatedAt: t3, PublishedAt: &t3,
	}
	if err := commentRepo.Create(ctx, c3); err != nil {
		t.Fatalf("create c3: %v", err)
	}

	// cPending: thread 1, pending
	tPending := base.Add(2 * time.Hour)
	cPending := &domain.Comment{
		SiteID: site1.ID, ThreadID: t1p1.ID, UserID: u1.ID, Depth: 0,
		BodyMarkdown: "pending", Status: domain.CommentStatusPending,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: tPending, UpdatedAt: tPending,
	}
	if err := commentRepo.Create(ctx, cPending); err != nil {
		t.Fatalf("create cPending: %v", err)
	}

	// cSpam: thread 1, spam
	tSpam := base.Add(3 * time.Hour)
	cSpam := &domain.Comment{
		SiteID: site1.ID, ThreadID: t1p1.ID, UserID: u1.ID, Depth: 0,
		BodyMarkdown: "spam", Status: domain.CommentStatusSpam,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: tSpam, UpdatedAt: tSpam,
	}
	if err := commentRepo.Create(ctx, cSpam); err != nil {
		t.Fatalf("create cSpam: %v", err)
	}

	// cDeleted: thread 1, deleted
	tDeleted := base.Add(4 * time.Hour)
	cDeleted := &domain.Comment{
		SiteID: site1.ID, ThreadID: t1p1.ID, UserID: u1.ID, Depth: 0,
		BodyMarkdown: "deleted", Status: domain.CommentStatusDeleted,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: tDeleted, UpdatedAt: tDeleted,
	}
	if err := commentRepo.Create(ctx, cDeleted); err != nil {
		t.Fatalf("create cDeleted: %v", err)
	}

	// Site 2 comment
	tSite2 := base.Add(5 * time.Hour)
	cSite2 := &domain.Comment{
		SiteID: site2.ID, ThreadID: t2p1.ID, UserID: u1.ID, Depth: 0,
		BodyMarkdown: "site2 comment", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: tSite2, UpdatedAt: tSite2, PublishedAt: &tSite2,
	}
	if err := commentRepo.Create(ctx, cSite2); err != nil {
		t.Fatalf("create cSite2: %v", err)
	}

	// Query site 1
	results, err := commentRepo.ListLatestPublic(ctx, site1.ID, 10)
	if err != nil {
		t.Fatalf("ListLatestPublic site1: %v", err)
	}

	// Should have exactly 3 published comments: c3 (newest), c2 (base, higher ID), c1 (base, lower ID)
	if len(results) != 3 {
		t.Fatalf("expected 3 comments for site1, got %d", len(results))
	}

	if results[0].ID != c3.ID {
		t.Errorf("expected results[0] to be c3 (%d), got %d", c3.ID, results[0].ID)
	}
	if results[0].PageKey != "p1" || *results[0].PageURL != url1 || *results[0].PageTitle != title1 {
		t.Errorf("results[0] page metadata mismatch: %+v", results[0])
	}
	if results[0].AuthorNickname != "User1" || results[0].AuthorEmailNormalized != "u1@example.com" {
		t.Errorf("results[0] author info mismatch: %+v", results[0])
	}

	if results[1].ID != c2.ID {
		t.Errorf("expected results[1] to be c2 (%d), got %d", c2.ID, results[1].ID)
	}
	if results[1].PageKey != "p2" || *results[1].PageURL != url2 || *results[1].PageTitle != title2 {
		t.Errorf("results[1] page metadata mismatch: %+v", results[1])
	}
	if results[1].AuthorNickname != "User2" || results[1].AuthorRole != domain.RoleAdmin {
		t.Errorf("results[1] author info mismatch: %+v", results[1])
	}
	if results[1].ReplyToNickname == nil || *results[1].ReplyToNickname != "User1" {
		t.Errorf("results[1] reply_to_nickname mismatch: %+v", results[1].ReplyToNickname)
	}

	if results[2].ID != c1.ID {
		t.Errorf("expected results[2] to be c1 (%d), got %d", c1.ID, results[2].ID)
	}

	// Test limit
	limitResults, err := commentRepo.ListLatestPublic(ctx, site1.ID, 2)
	if err != nil {
		t.Fatalf("ListLatestPublic with limit 2: %v", err)
	}
	if len(limitResults) != 2 {
		t.Fatalf("expected 2 comments, got %d", len(limitResults))
	}
	if limitResults[0].ID != c3.ID || limitResults[1].ID != c2.ID {
		t.Errorf("limit results mismatch")
	}

	// Query site 2
	s2Results, err := commentRepo.ListLatestPublic(ctx, site2.ID, 10)
	if err != nil {
		t.Fatalf("ListLatestPublic site2: %v", err)
	}
	if len(s2Results) != 1 {
		t.Fatalf("expected 1 comment for site2, got %d", len(s2Results))
	}
	if s2Results[0].ID != cSite2.ID {
		t.Errorf("expected cSite2, got %d", s2Results[0].ID)
	}
}

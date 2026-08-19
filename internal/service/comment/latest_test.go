package comment

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
)

func TestServiceListLatestPublic(t *testing.T) {
	db := ownerTestDB(t)
	ctx := context.Background()

	userRepo := repository.NewUserRepo(db)
	siteRepo := repository.NewSiteRepo(db)
	threadRepo := repository.NewThreadRepo(db)
	commentRepo := repository.NewCommentRepo(db)

	u1 := &domain.User{Email: "u1@example.com", EmailNormalized: "u1@example.com", Nickname: "User1", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u1); err != nil {
		t.Fatalf("create user1: %v", err)
	}
	u2 := &domain.User{Email: "u2@example.com", EmailNormalized: "u2@example.com", Nickname: "User2", Role: domain.RoleAdmin, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, u2); err != nil {
		t.Fatalf("create user2: %v", err)
	}

	activeSite := &domain.Site{Name: "Active Site", CanonicalURL: "https://active.example", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, activeSite); err != nil {
		t.Fatalf("create active site: %v", err)
	}

	disabledSite := &domain.Site{Name: "Disabled Site", CanonicalURL: "https://disabled.example", Status: domain.SiteStatusDisabled}
	if err := siteRepo.Create(ctx, disabledSite); err != nil {
		t.Fatalf("create disabled site: %v", err)
	}

	url1 := "https://active.example/blog/1"
	title1 := "Blog 1"
	th1, err := threadRepo.ResolveOrCreate(ctx, activeSite.ID, "page1", &url1, &title1)
	if err != nil {
		t.Fatalf("create thread1: %v", err)
	}

	base := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)

	// Seed 30 published comments on activeSite
	for i := 1; i <= 30; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		c := &domain.Comment{
			SiteID: activeSite.ID, ThreadID: th1.ID, UserID: u1.ID, Depth: 0,
			BodyMarkdown: fmt.Sprintf("comment %d", i), Status: domain.CommentStatusPublished,
			IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: ts, UpdatedAt: ts, PublishedAt: &ts,
		}
		if err := commentRepo.Create(ctx, c); err != nil {
			t.Fatalf("create comment %d: %v", i, err)
		}
	}

	svc := &Service{
		txRunner: gormtx.NewRunner(db),
		threads:  threadRepo,
		comments: commentRepo,
		sites:    siteRepo,
		users:    userRepo,
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			GravatarBaseURL: "https://cravatar.cn/avatar",
		}},
	}

	// 1. Inactive site -> ErrSiteInactive
	_, err = svc.ListLatestPublic(ctx, disabledSite.ID, 25)
	if !errors.Is(err, domain.ErrSiteInactive) {
		t.Fatalf("expected ErrSiteInactive for disabled site, got %v", err)
	}

	// 2. Non-existent site -> ErrNotFound
	_, err = svc.ListLatestPublic(ctx, 999999, 25)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing site, got %v", err)
	}

	// 3. Default limit (<= 0) should return 25 items
	views, err := svc.ListLatestPublic(ctx, activeSite.ID, 0)
	if err != nil {
		t.Fatalf("ListLatestPublic default limit: %v", err)
	}
	if len(views) != 25 {
		t.Fatalf("expected 25 comments with limit=0, got %d", len(views))
	}
	// The first view should be the 30th comment (newest)
	if views[0].BodyMarkdown != "comment 30" {
		t.Errorf("expected views[0] to be comment 30, got %s", views[0].BodyMarkdown)
	}
	if views[0].PageKey != "page1" || *views[0].PageURL != url1 || *views[0].PageTitle != title1 {
		t.Errorf("views[0] page metadata mismatch: %+v", views[0])
	}
	if views[0].AuthorAvatarURL == "" {
		t.Errorf("expected avatar URL to be derived, got empty")
	}

	// 4. Negative limit should return 25 items
	viewsNeg, err := svc.ListLatestPublic(ctx, activeSite.ID, -5)
	if err != nil {
		t.Fatalf("ListLatestPublic negative limit: %v", err)
	}
	if len(viewsNeg) != 25 {
		t.Fatalf("expected 25 comments with limit=-5, got %d", len(viewsNeg))
	}

	// 5. Over-limit (e.g. 50) should be clamped to 25 items
	viewsOver, err := svc.ListLatestPublic(ctx, activeSite.ID, 50)
	if err != nil {
		t.Fatalf("ListLatestPublic over limit: %v", err)
	}
	if len(viewsOver) != 25 {
		t.Fatalf("expected 25 comments with limit=50, got %d", len(viewsOver))
	}

	// 6. Explicit limit within range (e.g. 10) should return exactly 10 items
	views10, err := svc.ListLatestPublic(ctx, activeSite.ID, 10)
	if err != nil {
		t.Fatalf("ListLatestPublic limit=10: %v", err)
	}
	if len(views10) != 10 {
		t.Fatalf("expected 10 comments with limit=10, got %d", len(views10))
	}
	if views10[0].BodyMarkdown != "comment 30" || views10[9].BodyMarkdown != "comment 21" {
		t.Errorf("views10 range unexpected: [0]=%s, [9]=%s", views10[0].BodyMarkdown, views10[9].BodyMarkdown)
	}
}

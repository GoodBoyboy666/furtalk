package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

type importFixture struct {
	db       *gorm.DB
	importer *Importer
	users    *repository.UserRepo
	sites    *repository.SiteRepo
	threads  *repository.ThreadRepo
	comments *repository.CommentRepo
}

func newImportFixture(t *testing.T) importFixture {
	t.Helper()
	db, err := database.Connect(database.Config{
		Dialect: "sqlite",
		Path:    filepath.Join(t.TempDir(), "artalk-import.db"),
	})
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, model.All()...); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	users := repository.NewUserRepo(db)
	sites := repository.NewSiteRepo(db)
	threads := repository.NewThreadRepo(db)
	comments := repository.NewCommentRepo(db)
	return importFixture{
		db:       db,
		importer: NewImporter(gormtx.NewRunner(db), users, sites, threads, comments),
		users:    users,
		sites:    sites,
		threads:  threads,
		comments: comments,
	}
}

func parseFixture(t *testing.T) []Artran {
	t.Helper()
	// Deliberately put the deepest reply first to verify topological ordering.
	input := `[
  {
    "id": "3", "rid": "2", "content": "pending grandchild",
    "ua": "Artalk/2.9", "ip": "not-an-ip",
    "created_at": "2026-01-03 12:00:00 +0800", "is_pending": "true",
    "nick": "Alice", "email": "alice@example.com", "link": "https://alice.example.com",
    "page_key": "/post", "page_title": "New title", "site_name": "Blog",
    "site_urls": "http://localhost:23366/demo/,https://blog.example.com/path/"
  },
  {
    "id": "2", "rid": "1", "content": "child",
    "ua": "Mozilla/5.0", "ip": "2001:db8::1234",
    "created_at": "2026-01-02 12:00:00 +0800", "updated_at": "2026-01-02T05:00:00Z",
    "is_collapsed": true, "is_pinned": true, "vote_up": 3,
    "nick": "Guest", "email": "", "link": "javascript:alert(1)",
    "page_key": "/post", "page_title": "Old title", "page_admin_only": true,
    "site_name": "Blog", "site_urls": "https://blog.example.com"
  },
  {
    "id": "1", "rid": "0", "content": "root",
    "ua": "Mozilla/5.0", "ip": "192.0.2.129",
    "created_at": "2026-01-01 12:00:00 +0800", "updated_at": "2026-01-01 12:30:00 +0800",
    "is_pending": false, "badge_name": "Admin",
    "nick": "Alice", "email": "Alice@Example.COM",
    "page_key": "/post", "page_title": "Old title", "site_name": "Blog",
    "site_urls": "https://blog.example.com"
  }
]`
	records, err := Parse(bytes.NewBufferString(input))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return records
}

func TestImporterDryRunRollsBackThenCommitPreservesTree(t *testing.T) {
	fixture := newImportFixture(t)
	ctx := context.Background()
	existing := &domain.User{
		Email: "alice@example.com", EmailNormalized: "alice@example.com", Nickname: "Existing Alice",
		Role: domain.RoleAdmin, Status: domain.UserStatusActive, SessionVersion: 1,
	}
	if err := fixture.users.Create(ctx, existing); err != nil {
		t.Fatalf("seed existing user: %v", err)
	}
	records := parseFixture(t)
	options := Options{
		IPMode: domain.PrivacyModeCoarse, UAMode: domain.PrivacyModeFull,
		SourceLocation: time.UTC, DryRun: true,
	}

	dryReport, err := fixture.importer.Import(ctx, records, options)
	if err != nil {
		t.Fatalf("dry-run Import() error = %v", err)
	}
	if dryReport.ImportedComments != 3 || dryReport.CreatedSites != 1 || dryReport.CreatedThreads != 1 {
		t.Fatalf("dry-run report = %+v", dryReport)
	}
	if dryReport.CreatedUsers != 1 || dryReport.ReusedUsers != 1 || dryReport.SyntheticEmails != 1 {
		t.Fatalf("dry-run user report = %+v", dryReport)
	}
	if dryReport.InvalidIPs != 1 || dryReport.InvalidWebsites != 1 {
		t.Fatalf("dry-run invalid report = %+v", dryReport)
	}
	if dryReport.IgnoredCollapsed != 1 || dryReport.IgnoredPinned != 1 || dryReport.IgnoredVotes != 1 || dryReport.IgnoredBadges != 1 || dryReport.IgnoredPagePolicies != 1 {
		t.Fatalf("dry-run ignored report = %+v", dryReport)
	}
	if sites, err := fixture.sites.List(ctx); err != nil || len(sites) != 0 {
		t.Fatalf("sites after dry-run = %+v, err = %v", sites, err)
	}
	if count, err := fixture.comments.CountAdmin(ctx, domain.AdminFilter{}); err != nil || count != 0 {
		t.Fatalf("comments after dry-run = %d, err = %v", count, err)
	}
	if count, err := fixture.users.Count(ctx, ""); err != nil || count != 1 {
		t.Fatalf("users after dry-run = %d, err = %v; want only seeded user", count, err)
	}

	options.DryRun = false
	report, err := fixture.importer.Import(ctx, records, options)
	if err != nil {
		t.Fatalf("commit Import() error = %v", err)
	}
	if report.ImportedComments != 3 || report.PublishedComments != 2 || report.PendingComments != 1 {
		t.Fatalf("commit report = %+v", report)
	}
	sites, err := fixture.sites.List(ctx)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites = %+v, err = %v", sites, err)
	}
	if sites[0].CanonicalURL != "https://blog.example.com" {
		t.Fatalf("canonical URL = %q", sites[0].CanonicalURL)
	}
	origins, err := fixture.sites.ListOrigins(ctx, sites[0].ID)
	if err != nil || len(origins) != 2 {
		t.Fatalf("origins = %+v, err = %v", origins, err)
	}
	thread, err := fixture.threads.GetBySiteAndKey(ctx, sites[0].ID, "/post")
	if err != nil {
		t.Fatalf("get thread: %v", err)
	}
	if thread.PageTitle == nil || *thread.PageTitle != "New title" {
		t.Fatalf("page title = %v", thread.PageTitle)
	}
	rows, err := fixture.comments.ListAdmin(ctx, domain.AdminFilter{SiteID: &sites[0].ID, Sort: domain.CommentSortAsc, Limit: 10})
	if err != nil {
		t.Fatalf("list comments: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("comments = %d, want 3", len(rows))
	}
	root, child, grandchild := rows[0], rows[1], rows[2]
	if root.ParentID != nil || root.RootID != nil || root.Depth != 0 || root.IPValue == nil || *root.IPValue != "192.0.2.0" {
		t.Fatalf("root = %+v", root.Comment)
	}
	if child.ParentID == nil || *child.ParentID != root.ID || child.RootID == nil || *child.RootID != root.ID || child.Depth != 1 {
		t.Fatalf("child = %+v", child.Comment)
	}
	if grandchild.ParentID == nil || *grandchild.ParentID != child.ID || grandchild.RootID == nil || *grandchild.RootID != root.ID || grandchild.Depth != 2 {
		t.Fatalf("grandchild = %+v", grandchild.Comment)
	}
	if child.ReplyToUserID == nil || *child.ReplyToUserID != existing.ID {
		t.Fatalf("child reply_to_user_id = %v, want %d", child.ReplyToUserID, existing.ID)
	}
	if grandchild.Status != domain.CommentStatusPending || grandchild.PublishedAt != nil {
		t.Fatalf("grandchild status/published = %s/%v", grandchild.Status, grandchild.PublishedAt)
	}
	if root.AuthorRole != domain.RoleAdmin || root.AuthorNickname != "Existing Alice" {
		t.Fatalf("existing user was not reused: role=%s nickname=%q", root.AuthorRole, root.AuthorNickname)
	}

	if _, err := fixture.importer.Import(ctx, records, options); err == nil || !strings.Contains(err.Error(), "already contains 3 comments") {
		t.Fatalf("repeat import error = %v", err)
	}
}

func TestPrepareRejectsBrokenReplyGraphs(t *testing.T) {
	base := func(id, rid string) Artran {
		return Artran{
			ID: flexibleString(id), RID: flexibleString(rid), CreatedAt: flexibleString("2026-01-01T00:00:00Z"),
			PageKey: flexibleString("/post"), SiteName: flexibleString("Blog"),
		}
	}
	for _, test := range []struct {
		name    string
		records []Artran
		want    string
	}{
		{name: "missing parent", records: []Artran{base("1", "99")}, want: "missing parent 99"},
		{name: "cycle", records: []Artran{base("1", "2"), base("2", "1")}, want: "contains a cycle"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := prepare(test.records, Options{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepare() error = %v, want %q", err, test.want)
			}
		})
	}
}

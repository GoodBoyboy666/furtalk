package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestCommentRepoFindBySiteAndIDLockedPostgresSQL verifies the parent read uses
// FOR UPDATE under PostgreSQL while retaining the site boundary.
func TestCommentRepoFindBySiteAndIDLockedPostgresSQL(t *testing.T) {
	sqliteDB := newCommentFKTestDB(t)
	sqlDB, err := sqliteDB.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}
	capture := &publicSQLCapture{Interface: logger.Default}
	postgresDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn:                 sqlDB,
		PreferSimpleProtocol: true,
	}), &gorm.Config{DryRun: true, Logger: capture})
	if err != nil {
		t.Fatalf("init postgres dry run db: %v", err)
	}

	_, _ = NewCommentRepo(postgresDB).FindBySiteAndIDLocked(context.Background(), 7, 11)
	if !strings.Contains(strings.ToUpper(capture.sql), "FOR UPDATE") {
		t.Fatalf("locked comment read SQL = %q, want FOR UPDATE", capture.sql)
	}
	if !strings.Contains(capture.sql, "site_id") || !strings.Contains(capture.sql, "id") {
		t.Fatalf("locked comment read SQL = %q, want site/id predicates", capture.sql)
	}
}

// TestCommentRepoFindBySiteAndIDLockedSQLite executes the same helper against
// pure-Go SQLite to ensure the dialect branch does not emit unsupported locking
// syntax and still returns the row inside a transaction.
func TestCommentRepoFindBySiteAndIDLockedSQLite(t *testing.T) {
	db := newCommentFKTestDB(t)
	ctx := context.Background()
	user := &domain.User{Email: "lock@example.com", EmailNormalized: "lock@example.com", Nickname: "lock", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := NewUserRepo(db).Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	site := &domain.Site{Name: "Lock", CanonicalURL: "https://lock.example", Status: domain.SiteStatusActive}
	if err := NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := NewThreadRepo(db).ResolveOrCreate(ctx, site.ID, "lock-page", nil, nil)
	if err != nil {
		t.Fatalf("create thread: %v", err)
	}
	now := time.Now().UTC()
	parent := &domain.Comment{SiteID: site.ID, ThreadID: thread.ID, UserID: user.ID, BodyMarkdown: "parent", Status: domain.CommentStatusPublished, CreatedAt: now, UpdatedAt: now, PublishedAt: &now}
	if err := NewCommentRepo(db).Create(ctx, parent); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	if err := gormtx.NewRunner(db).RunInTx(ctx, func(txCtx context.Context) error {
		got, findErr := NewCommentRepo(db).FindBySiteAndIDLocked(txCtx, site.ID, parent.ID)
		if findErr != nil {
			return findErr
		}
		if got.Status != domain.CommentStatusPublished {
			t.Fatalf("status = %s, want published", got.Status)
		}
		return nil
	}); err != nil {
		t.Fatalf("locked SQLite read: %v", err)
	}
}

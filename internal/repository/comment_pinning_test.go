package repository

import (
	"context"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
)

func TestCommentRepoSetPinnedIsIdempotentAndRootOnly(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	root, err := repo.SetPinned(ctx, siteID, ids["a"], true)
	if err != nil {
		t.Fatalf("pin root: %v", err)
	}
	if !root.IsPinned {
		t.Fatal("root is_pinned = false, want true")
	}
	repeat, err := repo.SetPinned(ctx, siteID, ids["a"], true)
	if err != nil {
		t.Fatalf("repeat pin root: %v", err)
	}
	if !repeat.IsPinned {
		t.Fatal("repeat pin cleared root")
	}

	parentID := ids["a"]
	reply := &domain.Comment{
		SiteID: siteID, ThreadID: threadID, UserID: root.UserID,
		ParentID: &parentID, RootID: &parentID, Depth: 1,
		BodyMarkdown: "reply", Status: domain.CommentStatusPublished,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
	}
	if err := repo.Create(ctx, reply); err != nil {
		t.Fatalf("create reply: %v", err)
	}
	if _, err := repo.SetPinned(ctx, siteID, reply.ID, true); err == nil {
		t.Fatal("pinning a reply succeeded")
	}
}

func TestCommentRepoListPublicPinnedFirstAcrossSortsAndPages(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()
	for _, id := range []int64{ids["a"], ids["c"]} {
		if _, err := repo.SetPinned(ctx, siteID, id, true); err != nil {
			t.Fatalf("pin %d: %v", id, err)
		}
	}

	asc, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, nil, 50, nil)
	if err != nil {
		t.Fatalf("list asc: %v", err)
	}
	assertOrder(t, asc, []int64{ids["a"], ids["c"], ids["b"], ids["d"]})
	if !asc[0].IsPinned || !asc[1].IsPinned || asc[2].IsPinned {
		t.Fatalf("asc pinned states = %v %v %v, want pinned,pinned,unpinned", asc[0].IsPinned, asc[1].IsPinned, asc[2].IsPinned)
	}

	desc, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortDesc, nil, 50, nil)
	if err != nil {
		t.Fatalf("list desc: %v", err)
	}
	assertOrder(t, desc, []int64{ids["c"], ids["a"], ids["d"], ids["b"]})

	var all []int64
	var cursor *domain.Cursor
	for len(all) < 4 {
		rows, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, cursor, 1, nil)
		if err != nil {
			t.Fatalf("page %d: %v", len(all), err)
		}
		if len(rows) == 0 {
			break
		}
		all = append(all, rows[0].ID)
		cursor = &domain.Cursor{Pinned: rows[0].IsPinned, CreatedAt: rows[0].CreatedAt, ID: rows[0].ID}
	}
	assertIDs(t, all, []int64{ids["a"], ids["c"], ids["b"], ids["d"]})
}

func TestSQLitePinnedRootConstraintDDL(t *testing.T) {
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: ":memory:"})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.Exec("CREATE TABLE pin_migration (id integer PRIMARY KEY, parent_id integer, depth integer NOT NULL DEFAULT 0)").Error; err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	if err := db.Exec("ALTER TABLE pin_migration ADD COLUMN is_pinned numeric NOT NULL DEFAULT false CONSTRAINT ck_pin_migration_root CHECK (NOT is_pinned OR (parent_id IS NULL AND depth = 0))").Error; err != nil {
		t.Fatalf("add pinned column: %v", err)
	}
	if err := db.Exec("INSERT INTO pin_migration (id, parent_id, depth, is_pinned) VALUES (1, 9, 1, true)").Error; err == nil {
		t.Fatal("SQLite accepted a pinned reply")
	}
}

func assertIDs(t *testing.T, got, want []int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
}

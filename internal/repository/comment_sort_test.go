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

// newSortTestDB 打开临时 SQLite 数据库并迁移评论相关表。
func newSortTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "comment-sort-repo-test.db")
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

// seedSortFixture 插入站点/线程与 5 条已发布评论：前两条共享同一 created_at
// （依赖 id 决胜），后三条时间递增，另有一条 pending 验证过滤。
// 返回各评论的 ID 与时间戳映射。
func seedSortFixture(t *testing.T, db *gorm.DB) (siteID, threadID int64, ids map[string]int64) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	userRepo := NewUserRepo(db)
	siteRepo := NewSiteRepo(db)
	threadRepo := NewThreadRepo(db)
	commentRepo := NewCommentRepo(db)

	user := &domain.User{Email: "u@example.com", EmailNormalized: "u@example.com", Nickname: "u", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := threadRepo.ResolveOrCreate(ctx, site.ID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}

	ids = map[string]int64{}
	times := map[string]time.Time{
		"a":       base,          // 与 b 同时间戳，id 更小
		"b":       base,          // 与 a 同时间戳，id 更大
		"c":       base.Add(1e9), // 1 秒后
		"d":       base.Add(2 * 1e9),
		"pending": base.Add(3 * 1e9), // 非 published，永不返回
	}
	for _, key := range []string{"a", "b", "c", "d", "pending"} {
		status := domain.CommentStatusPublished
		var publishedAt *time.Time
		if key == "pending" {
			status = domain.CommentStatusPending
		} else {
			ts := times[key]
			publishedAt = &ts
		}
		c := &domain.Comment{
			SiteID: site.ID, ThreadID: thread.ID, UserID: user.ID, Depth: 0,
			BodyMarkdown: "body-" + key, Status: status,
			IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: times[key], UpdatedAt: times[key], PublishedAt: publishedAt,
		}
		if err := commentRepo.Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", key, err)
		}
		ids[key] = c.ID
	}
	return site.ID, thread.ID, ids
}

// TestCommentRepoListPublicDirectionalOrdering 验证仓储按受控方向排序：
// asc 升序、desc 降序，且同时间戳由 id 决胜。
func TestCommentRepoListPublicDirectionalOrdering(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	asc, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, nil, 50)
	if err != nil {
		t.Fatalf("list asc: %v", err)
	}
	wantAsc := []int64{ids["a"], ids["b"], ids["c"], ids["d"]}
	assertOrder(t, asc, wantAsc)

	desc, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortDesc, nil, 50)
	if err != nil {
		t.Fatalf("list desc: %v", err)
	}
	wantDesc := []int64{ids["d"], ids["c"], ids["b"], ids["a"]}
	assertOrder(t, desc, wantDesc)
}

// TestCommentRepoListPublicDirectionalPagination 验证 asc/desc 方向游标分页
// 在相同时间戳边界与多页之间无重复、无遗漏。
func TestCommentRepoListPublicDirectionalPagination(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	for _, tt := range []struct {
		name  string
		sort  domain.CommentSort
		want  []int64
		limit int
	}{
		{name: "asc two-by-two", sort: domain.CommentSortAsc, want: []int64{ids["a"], ids["b"], ids["c"], ids["d"]}, limit: 2},
		{name: "desc two-by-two", sort: domain.CommentSortDesc, want: []int64{ids["d"], ids["c"], ids["b"], ids["a"]}, limit: 2},
		{name: "asc one-by-one", sort: domain.CommentSortAsc, want: []int64{ids["a"], ids["b"], ids["c"], ids["d"]}, limit: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var all []int64
			var cursor *domain.Cursor
			for page := 0; ; page++ {
				rows, err := repo.ListPublic(ctx, siteID, threadID, tt.sort, cursor, tt.limit)
				if err != nil {
					t.Fatalf("page %d: %v", page, err)
				}
				if len(rows) == 0 {
					break
				}
				for _, r := range rows {
					all = append(all, r.ID)
				}
				last := rows[len(rows)-1]
				next := &domain.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
				if len(rows) < tt.limit {
					break
				}
				cursor = next
				if page > 10 {
					t.Fatal("pagination did not terminate")
				}
			}
			if len(all) != len(tt.want) {
				t.Fatalf("ids = %v, want %v", all, tt.want)
			}
			seen := map[int64]bool{}
			for i, id := range all {
				if seen[id] {
					t.Fatalf("duplicate id %d across pages", id)
				}
				seen[id] = true
				if id != tt.want[i] {
					t.Fatalf("ids = %v, want %v", all, tt.want)
				}
			}
		})
	}
}

// assertOrder 断言仓储返回行的 ID 顺序。
func assertOrder(t *testing.T, rows []domain.PublicComment, want []int64) {
	t.Helper()
	if len(rows) != len(want) {
		t.Fatalf("rows = %d, want %d", len(rows), len(want))
	}
	for i, id := range want {
		if rows[i].ID != id {
			t.Fatalf("order mismatch at %d: got %d, want %d", i, rows[i].ID, id)
		}
	}
}

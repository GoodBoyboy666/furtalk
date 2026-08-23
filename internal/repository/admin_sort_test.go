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

// newAdminSortTestDB 打开临时 SQLite 数据库并迁移排序测试所需的表。
func newAdminSortTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "admin-sort-repo-test.db")
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

// seedAdminSortThreadFixture 插入站点与若干线程，前两条共享同一 created_at
// （依赖 id 决胜），后三条时间递增，用于验证线程排序方向与游标。
func seedAdminSortThreadFixture(t *testing.T, db *gorm.DB) (siteID int64, ids []int64) {
	t.Helper()
	ctx := context.Background()
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	repo := NewThreadRepo(db)
	base := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	times := []time.Time{base, base, base.Add(1e9), base.Add(2e9), base.Add(3e9)}
	for _, ts := range times {
		thread, err := repo.ResolveOrCreate(ctx, site.ID, "page-"+itoaT(len(ids)), nil, nil)
		if err != nil {
			t.Fatalf("create thread: %v", err)
		}
		ids = append(ids, thread.ID)
		// 回写时间戳使排序可预测。
		if err := db.Model(&model.Thread{}).Where("id = ?", thread.ID).Update("created_at", ts).Error; err != nil {
			t.Fatalf("update thread created_at: %v", err)
		}
	}
	return site.ID, ids
}

// itoaT 把 int 转为十进制字符串。
func itoaT(v int) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}

// TestThreadRepoListAdminDirectionalOrdering 验证管理线程列表按方向排序：
// asc 升序、desc 降序，且同时间戳由 id 决胜。
func TestThreadRepoListAdminDirectionalOrdering(t *testing.T) {
	db := newAdminSortTestDB(t)
	siteID, ids := seedAdminSortThreadFixture(t, db)
	repo := NewThreadRepo(db)
	ctx := context.Background()

	asc, err := repo.ListAdmin(ctx, domain.AdminThreadFilter{SiteID: &siteID, Sort: domain.CommentSortAsc, Limit: 50})
	if err != nil {
		t.Fatalf("list asc: %v", err)
	}
	wantAsc := []int64{ids[0], ids[1], ids[2], ids[3], ids[4]}
	if got := adminThreadIDs(asc); !equalInt64(got, wantAsc) {
		t.Fatalf("asc ids = %v, want %v", got, wantAsc)
	}

	desc, err := repo.ListAdmin(ctx, domain.AdminThreadFilter{SiteID: &siteID, Sort: domain.CommentSortDesc, Limit: 50})
	if err != nil {
		t.Fatalf("list desc: %v", err)
	}
	wantDesc := []int64{ids[4], ids[3], ids[2], ids[1], ids[0]}
	if got := adminThreadIDs(desc); !equalInt64(got, wantDesc) {
		t.Fatalf("desc ids = %v, want %v", got, wantDesc)
	}
}

// TestThreadRepoListAdminDirectionalPagination 验证管理线程 asc/desc 方向
// 偏移分页在相同时间戳边界与多页之间无重复、无遗漏。
func TestThreadRepoListAdminDirectionalPagination(t *testing.T) {
	db := newAdminSortTestDB(t)
	siteID, ids := seedAdminSortThreadFixture(t, db)
	repo := NewThreadRepo(db)
	ctx := context.Background()

	for _, tt := range []struct {
		name  string
		sort  domain.CommentSort
		want  []int64
		limit int
	}{
		{name: "asc two-by-two", sort: domain.CommentSortAsc, want: []int64{ids[0], ids[1], ids[2], ids[3], ids[4]}, limit: 2},
		{name: "desc two-by-two", sort: domain.CommentSortDesc, want: []int64{ids[4], ids[3], ids[2], ids[1], ids[0]}, limit: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var all []int64
			for page := 0; ; page++ {
				rows, err := repo.ListAdmin(ctx, domain.AdminThreadFilter{SiteID: &siteID, Sort: tt.sort, Offset: page * tt.limit, Limit: tt.limit})
				if err != nil {
					t.Fatalf("page %d: %v", page, err)
				}
				if len(rows) == 0 {
					break
				}
				for _, r := range rows {
					all = append(all, r.ID)
				}
				if len(rows) < tt.limit {
					break
				}
				if page > 10 {
					t.Fatal("pagination did not terminate")
				}
			}
			if !equalInt64(all, tt.want) {
				t.Fatalf("ids = %v, want %v", all, tt.want)
			}
		})
	}
}

// TestUserRepoListDirectionalOrdering 验证用户列表按 id 方向排序。
func TestUserRepoListDirectionalOrdering(t *testing.T) {
	db := newAdminSortTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		user := &domain.User{Email: email, EmailNormalized: email, Nickname: email, Role: domain.RoleUser, Status: domain.UserStatusActive}
		if err := repo.Create(ctx, user); err != nil {
			t.Fatalf("create user: %v", err)
		}
	}

	asc, err := repo.List(ctx, "", domain.CommentSortAsc, 50, 0)
	if err != nil {
		t.Fatalf("list asc: %v", err)
	}
	if len(asc) != 3 || asc[0].ID >= asc[1].ID || asc[1].ID >= asc[2].ID {
		t.Fatalf("asc users = %+v, want strictly ascending ids", asc)
	}

	desc, err := repo.List(ctx, "", domain.CommentSortDesc, 50, 0)
	if err != nil {
		t.Fatalf("list desc: %v", err)
	}
	if len(desc) != 3 || desc[0].ID <= desc[1].ID || desc[1].ID <= desc[2].ID {
		t.Fatalf("desc users = %+v, want strictly descending ids", desc)
	}
}

// TestCommentRepoListAdminDirectionalOrdering 验证管理评论列表按 (created_at, id)
// 方向排序，且同时间戳由 id 决胜。
func TestCommentRepoListAdminDirectionalOrdering(t *testing.T) {
	db := newAdminSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	asc, err := repo.ListAdmin(ctx, domain.AdminFilter{SiteID: &siteID, ThreadID: &threadID, Sort: domain.CommentSortAsc, Limit: 50})
	if err != nil {
		t.Fatalf("list asc: %v", err)
	}
	wantAsc := []int64{ids["a"], ids["b"], ids["c"], ids["d"], ids["pending"]}
	if got := adminCommentIDs(asc); !equalInt64(got, wantAsc) {
		t.Fatalf("asc ids = %v, want %v", got, wantAsc)
	}

	desc, err := repo.ListAdmin(ctx, domain.AdminFilter{SiteID: &siteID, ThreadID: &threadID, Sort: domain.CommentSortDesc, Limit: 50})
	if err != nil {
		t.Fatalf("list desc: %v", err)
	}
	wantDesc := []int64{ids["pending"], ids["d"], ids["c"], ids["b"], ids["a"]}
	if got := adminCommentIDs(desc); !equalInt64(got, wantDesc) {
		t.Fatalf("desc ids = %v, want %v", got, wantDesc)
	}
}

// TestCommentRepoListAdminDirectionalPagination 验证管理评论 asc/desc 方向
// 偏移分页无重复、无遗漏。
func TestCommentRepoListAdminDirectionalPagination(t *testing.T) {
	db := newAdminSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	for _, tt := range []struct {
		name  string
		sort  domain.CommentSort
		want  []int64
		limit int
	}{
		{name: "asc two-by-two", sort: domain.CommentSortAsc, want: []int64{ids["a"], ids["b"], ids["c"], ids["d"], ids["pending"]}, limit: 2},
		{name: "desc two-by-two", sort: domain.CommentSortDesc, want: []int64{ids["pending"], ids["d"], ids["c"], ids["b"], ids["a"]}, limit: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var all []int64
			for page := 0; ; page++ {
				rows, err := repo.ListAdmin(ctx, domain.AdminFilter{SiteID: &siteID, ThreadID: &threadID, Sort: tt.sort, Offset: page * tt.limit, Limit: tt.limit})
				if err != nil {
					t.Fatalf("page %d: %v", page, err)
				}
				if len(rows) == 0 {
					break
				}
				for _, r := range rows {
					all = append(all, r.ID)
				}
				if len(rows) < tt.limit {
					break
				}
				if page > 10 {
					t.Fatal("pagination did not terminate")
				}
			}
			if !equalInt64(all, tt.want) {
				t.Fatalf("ids = %v, want %v", all, tt.want)
			}
		})
	}
}

// adminThreadIDs 提取管理线程行的 ID。
func adminThreadIDs(rows []domain.AdminThread) []int64 {
	out := make([]int64, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}

// adminCommentIDs 提取管理评论行的 ID。
func adminCommentIDs(rows []domain.AdminComment) []int64 {
	out := make([]int64, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}

// equalInt64 报告两个 int64 切片逐元素相等。
func equalInt64(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

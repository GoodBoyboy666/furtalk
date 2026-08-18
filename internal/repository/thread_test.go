package repository

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newThreadTestDB 打开临时 SQLite 数据库并迁移线程相关表。
func newThreadTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "thread-repo-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// seedThreadSite 插入一个活跃站点。
func seedThreadSite(t *testing.T, db *gorm.DB) *domain.Site {
	t.Helper()
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := NewSiteRepo(db).Create(context.Background(), site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	return site
}

// TestThreadRepoLazyCreateConcurrentUnique 验证并发惰性创建只产生一条记录。
func TestThreadRepoLazyCreateConcurrentUnique(t *testing.T) {
	db := newThreadTestDB(t)
	site := seedThreadSite(t, db)
	repo := NewThreadRepo(db)

	const workers = 10
	start := make(chan struct{})
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			_, errs[idx] = repo.ResolveOrCreateLazy(context.Background(), site.ID, "same-page")
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}

	var count int64
	if err := db.Model(&model.Thread{}).Where("site_id = ?", site.ID).Count(&count).Error; err != nil {
		t.Fatalf("count threads: %v", err)
	}
	if count != 1 {
		t.Fatalf("thread rows = %d, want 1", count)
	}
}

// TestThreadRepoLazyCreateReusesWithoutTimestampWrite 验证重复惰性读取复用同一
// 记录且不刷新 updated_at。
func TestThreadRepoLazyCreateReusesWithoutTimestampWrite(t *testing.T) {
	db := newThreadTestDB(t)
	site := seedThreadSite(t, db)
	repo := NewThreadRepo(db)
	ctx := context.Background()

	first, err := repo.ResolveOrCreateLazy(ctx, site.ID, "page")
	if err != nil {
		t.Fatalf("first lazy create: %v", err)
	}
	before, err := repo.GetBySiteAndKey(ctx, site.ID, "page")
	if err != nil {
		t.Fatalf("get thread: %v", err)
	}

	time.Sleep(20 * time.Millisecond)
	second, err := repo.ResolveOrCreateLazy(ctx, site.ID, "page")
	if err != nil {
		t.Fatalf("second lazy create: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("thread id changed: first=%d second=%d", first.ID, second.ID)
	}
	after, err := repo.GetBySiteAndKey(ctx, site.ID, "page")
	if err != nil {
		t.Fatalf("get thread after reuse: %v", err)
	}
	if !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("updated_at changed on lazy reuse: before=%v after=%v", before.UpdatedAt, after.UpdatedAt)
	}
}

// TestThreadRepoNewThreadDefaultsEnabled 验证新建线程默认开启。
func TestThreadRepoNewThreadDefaultsEnabled(t *testing.T) {
	db := newThreadTestDB(t)
	site := seedThreadSite(t, db)
	repo := NewThreadRepo(db)

	thread, err := repo.ResolveOrCreateLazy(context.Background(), site.ID, "new-page")
	if err != nil {
		t.Fatalf("lazy create: %v", err)
	}
	if !thread.CommentsEnabled {
		t.Fatal("comments_enabled = false, want default true")
	}
}

// TestThreadRepoUpdateCommentsEnabledRoundTrip 验证显式 false 持久化、同值更新
// 成功，且跨站点 thread_id 返回 ErrNotFound。
func TestThreadRepoUpdateCommentsEnabledRoundTrip(t *testing.T) {
	db := newThreadTestDB(t)
	site := seedThreadSite(t, db)
	repo := NewThreadRepo(db)
	ctx := context.Background()

	thread, err := repo.ResolveOrCreate(ctx, site.ID, "page", nil, nil)
	if err != nil {
		t.Fatalf("create thread: %v", err)
	}

	updated, err := repo.UpdateCommentsEnabled(ctx, site.ID, thread.ID, false)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if updated.CommentsEnabled {
		t.Fatal("comments_enabled = true, want literal false persisted")
	}
	got, err := repo.GetBySiteAndKey(ctx, site.ID, "page")
	if err != nil {
		t.Fatalf("get thread: %v", err)
	}
	if got.CommentsEnabled {
		t.Fatal("comments_enabled = true after read, want false")
	}

	again, err := repo.UpdateCommentsEnabled(ctx, site.ID, thread.ID, false)
	if err != nil {
		t.Fatalf("same-value update must succeed: %v", err)
	}
	if again.CommentsEnabled {
		t.Fatal("comments_enabled = true after same-value update, want false")
	}

	reopened, err := repo.UpdateCommentsEnabled(ctx, site.ID, thread.ID, true)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened.CommentsEnabled {
		t.Fatal("comments_enabled = false after reopen, want true")
	}

	if _, err := repo.UpdateCommentsEnabled(ctx, site.ID+999, thread.ID, false); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-site update error = %v, want ErrNotFound", err)
	}
}

// TestThreadRepoListAdminScoped 验证站点作用域、开启状态过滤、文本搜索与游标分页。
func TestThreadRepoListAdminScoped(t *testing.T) {
	db := newThreadTestDB(t)
	site := seedThreadSite(t, db)
	repo := NewThreadRepo(db)
	ctx := context.Background()

	title1 := "Alpha Page"
	url1 := "https://example.com/alpha"
	t1, err := repo.ResolveOrCreate(ctx, site.ID, "alpha-key", &url1, &title1)
	if err != nil {
		t.Fatalf("create alpha: %v", err)
	}
	t2, err := repo.ResolveOrCreate(ctx, site.ID, "beta-key", nil, nil)
	if err != nil {
		t.Fatalf("create beta: %v", err)
	}
	if _, err := repo.UpdateCommentsEnabled(ctx, site.ID, t2.ID, false); err != nil {
		t.Fatalf("close beta: %v", err)
	}
	_ = t1

	rows, err := repo.ListAdmin(ctx, domain.AdminThreadFilter{SiteID: &site.ID, Limit: 50})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.SiteName != "Site" {
			t.Fatalf("site name = %q, want Site", r.SiteName)
		}
		if r.SiteID != site.ID {
			t.Fatalf("site id = %d, want %d", r.SiteID, site.ID)
		}
	}

	falseVal := false
	closed, err := repo.ListAdmin(ctx, domain.AdminThreadFilter{SiteID: &site.ID, CommentsEnabled: &falseVal, Limit: 50})
	if err != nil {
		t.Fatalf("list closed: %v", err)
	}
	if len(closed) != 1 || closed[0].PageKey != "beta-key" {
		t.Fatalf("closed rows = %+v, want only beta-key", closed)
	}

	searched, err := repo.ListAdmin(ctx, domain.AdminThreadFilter{SiteID: &site.ID, Q: "alpha", Limit: 50})
	if err != nil {
		t.Fatalf("list search: %v", err)
	}
	if len(searched) != 1 || searched[0].PageKey != "alpha-key" {
		t.Fatalf("search rows = %+v, want only alpha-key", searched)
	}

	other := seedThreadSite(t, db)
	otherThread, err := repo.ResolveOrCreate(ctx, other.ID, "other-key", nil, nil)
	if err != nil {
		t.Fatalf("create other-site thread: %v", err)
	}
	_ = otherThread
	siteOnly, err := repo.ListAdmin(ctx, domain.AdminThreadFilter{SiteID: &site.ID, Limit: 50})
	if err != nil {
		t.Fatalf("list site-scoped: %v", err)
	}
	if len(siteOnly) != 2 {
		t.Fatalf("site rows = %d, want 2 (other site must be excluded)", len(siteOnly))
	}
}

// TestThreadRepoListAdminOffsetPagination 验证 (created_at, id) 偏移分页无重复无缺口。
func TestThreadRepoListAdminOffsetPagination(t *testing.T) {
	db := newThreadTestDB(t)
	site := seedThreadSite(t, db)
	repo := NewThreadRepo(db)
	ctx := context.Background()

	base := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		row := &model.Thread{
			SiteID:    site.ID,
			PageKey:   "cursor-page-" + string(rune('a'+i)),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
			UpdatedAt: base.Add(time.Duration(i) * time.Second),
		}
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("create row %d: %v", i, err)
		}
	}

	var seen []string
	for offset := 0; ; offset += 2 {
		page, err := repo.ListAdmin(ctx, domain.AdminThreadFilter{SiteID: &site.ID, Offset: offset, Limit: 2})
		if err != nil {
			t.Fatalf("list page: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, r := range page {
			seen = append(seen, r.PageKey)
		}
		if len(page) < 2 {
			break
		}
	}
	if len(seen) != 5 {
		t.Fatalf("total rows = %d, want 5", len(seen))
	}
	unique := map[string]bool{}
	for _, k := range seen {
		if unique[k] {
			t.Fatalf("duplicate row %q across offset pages", k)
		}
		unique[k] = true
	}
}

// legacyThread 是旧的 threads 表形状（无 comments_enabled 列），用于迁移测试。
type legacyThread struct {
	ID        int64     `gorm:"primaryKey;autoIncrement;generated:identity;uniqueIndex:uq_threads_site_id,priority:2"`
	SiteID    int64     `gorm:"column:site_id;not null;uniqueIndex:uq_threads_site_id,priority:1;uniqueIndex:uq_threads_site_page,priority:1"`
	PageKey   string    `gorm:"column:page_key;type:text;not null;uniqueIndex:uq_threads_site_page,priority:2"`
	PageURL   *string   `gorm:"column:page_url;type:text"`
	PageTitle *string   `gorm:"column:page_title;type:text"`
	CreatedAt time.Time `gorm:"column:created_at;precision:6;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;precision:6;autoUpdateTime"`
}

func (legacyThread) TableName() string { return "threads" }

// TestThreadSchemaColumnDefaultAndMigration 验证 comments_enabled 列 NOT NULL 且
// 默认 true；旧表结构经 AutoMigrate 后既有行保持开启。
func TestThreadSchemaColumnDefaultAndMigration(t *testing.T) {
	t.Run("column is not null with default true", func(t *testing.T) {
		db := newThreadTestDB(t)
		seedThreadSite(t, db)
		var cols []struct {
			CID     int            `gorm:"column:cid"`
			Name    string         `gorm:"column:name"`
			Type    string         `gorm:"column:type"`
			NotNull int            `gorm:"column:notnull"`
			Default sql.NullString `gorm:"column:dflt_value"`
			PK      int            `gorm:"column:pk"`
		}
		if err := db.Raw("PRAGMA table_info(threads)").Scan(&cols).Error; err != nil {
			t.Fatalf("pragma table_info: %v", err)
		}
		found := false
		for _, c := range cols {
			if c.Name == "comments_enabled" {
				found = true
				if c.NotNull != 1 {
					t.Fatalf("comments_enabled notnull = %d, want 1", c.NotNull)
				}
				if !c.Default.Valid || (c.Default.String != "1" && c.Default.String != "true") {
					t.Fatalf("comments_enabled default = %q, want 1/true", c.Default.String)
				}
			}
		}
		if !found {
			t.Fatal("comments_enabled column missing from threads table")
		}
	})

	t.Run("existing rows stay enabled after migration", func(t *testing.T) {
		dsn := filepath.Join(t.TempDir(), "thread-migration-test.db")
		db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
		if err != nil {
			t.Fatalf("connect sqlite: %v", err)
		}
		t.Cleanup(func() {
			if sqlDB, cerr := db.DB(); cerr == nil {
				_ = sqlDB.Close()
			}
		})
		ctx := context.Background()

		if err := database.AutoMigrate(db, &model.Site{}, &legacyThread{}); err != nil {
			t.Fatalf("migrate legacy schema: %v", err)
		}
		site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
		if err := NewSiteRepo(db).Create(ctx, site); err != nil {
			t.Fatalf("create site: %v", err)
		}
		legacy := &legacyThread{SiteID: site.ID, PageKey: "legacy-page"}
		if err := db.Create(legacy).Error; err != nil {
			t.Fatalf("create legacy thread: %v", err)
		}

		if err := database.AutoMigrate(db, &model.Site{}, &model.Thread{}); err != nil {
			t.Fatalf("migrate to current schema: %v", err)
		}
		thread, err := NewThreadRepo(db).GetBySiteAndKey(ctx, site.ID, "legacy-page")
		if err != nil {
			t.Fatalf("read migrated thread: %v", err)
		}
		if !thread.CommentsEnabled {
			t.Fatal("migrated legacy thread comments_enabled = false, want default true")
		}
	})
}

package comment

import (
	"context"
	"errors"
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

// newThreadAdminTestDB 打开临时 SQLite 数据库并迁移线程相关表。
func newThreadAdminTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "thread-admin-test.db")
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

// threadAdminService 装配带真实仓储的评论服务（仅线程管理用例需要）。
func threadAdminService(db *gorm.DB) *Service {
	return &Service{
		txRunner: gormtx.NewRunner(db),
		threads:  repository.NewThreadRepo(db),
		sites:    repository.NewSiteRepo(db),
		now:      func() time.Time { return time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC) },
	}
}

// seedThreadAdminFixture 插入一个站点与两个线程。
func seedThreadAdminFixture(t *testing.T, db *gorm.DB) (siteID, threadA, threadB int64) {
	t.Helper()
	ctx := context.Background()
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := repository.NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	titleA := "Alpha"
	urlA := "https://example.com/alpha"
	a, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, site.ID, "alpha", &urlA, &titleA)
	if err != nil {
		t.Fatalf("create alpha: %v", err)
	}
	b, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, site.ID, "beta", nil, nil)
	if err != nil {
		t.Fatalf("create beta: %v", err)
	}
	return site.ID, a.ID, b.ID
}

// TestAdminUpdateThreadKeyTitleEnabled 验证在同一线程上独立或组合更新
// page_key、page_title、comments_enabled，ID 与既有数据归属不变。
func TestAdminUpdateThreadKeyTitleEnabled(t *testing.T) {
	db := newThreadAdminTestDB(t)
	siteID, threadA, _ := seedThreadAdminFixture(t, db)
	svc := threadAdminService(db)
	ctx := context.Background()

	updated, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{
		PageKey: strPtr("renamed"),
	})
	if err != nil {
		t.Fatalf("update key: %v", err)
	}
	if updated.PageKey != "renamed" || updated.ID != threadA {
		t.Fatalf("key update = %+v", updated)
	}

	newTitle := "Beta Title"
	updated, err = svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{
		PageTitle: OptionalNullableString{Set: true, Value: &newTitle},
	})
	if err != nil {
		t.Fatalf("update title: %v", err)
	}
	if updated.PageTitle == nil || *updated.PageTitle != newTitle {
		t.Fatalf("title update = %+v", updated)
	}

	enabled := false
	updated, err = svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{
		CommentsEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("update enabled: %v", err)
	}
	if updated.CommentsEnabled {
		t.Fatal("comments_enabled = true, want literal false")
	}

	// 组合更新：key + title + enabled 一次提交。
	enabled = true
	comboTitle := "Combo"
	updated, err = svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{
		PageKey:         strPtr("combo"),
		PageTitle:       OptionalNullableString{Set: true, Value: &comboTitle},
		CommentsEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("combo update: %v", err)
	}
	if updated.PageKey != "combo" || *updated.PageTitle != "Combo" || !updated.CommentsEnabled || updated.ID != threadA {
		t.Fatalf("combo update = %+v", updated)
	}

	// 稳定 ID 与线程归属不变。
	got, err := repository.NewThreadRepo(db).GetBySiteAndID(ctx, siteID, threadA)
	if err != nil {
		t.Fatalf("read thread: %v", err)
	}
	if got.ID != threadA || got.PageKey != "combo" {
		t.Fatalf("persisted thread = %+v", got)
	}
}

// TestAdminUpdateThreadTitleClear 验证 page_title 显式 null/空白清空，缺省保持不变。
func TestAdminUpdateThreadTitleClear(t *testing.T) {
	db := newThreadAdminTestDB(t)
	siteID, threadA, _ := seedThreadAdminFixture(t, db)
	svc := threadAdminService(db)
	ctx := context.Background()

	// 缺省 page_title：保持不变。
	if _, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{
		PageKey: strPtr("key-only"),
	}); err != nil {
		t.Fatalf("key-only update: %v", err)
	}
	got, err := repository.NewThreadRepo(db).GetBySiteAndID(ctx, siteID, threadA)
	if err != nil {
		t.Fatalf("read thread: %v", err)
	}
	if got.PageTitle == nil || *got.PageTitle != "Alpha" {
		t.Fatalf("page_title must stay unchanged, got %v", got.PageTitle)
	}

	// 显式 null：清空。
	if _, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{
		PageTitle: OptionalNullableString{Set: true, Value: nil},
	}); err != nil {
		t.Fatalf("clear title via null: %v", err)
	}
	got, _ = repository.NewThreadRepo(db).GetBySiteAndID(ctx, siteID, threadA)
	if got.PageTitle != nil {
		t.Fatalf("page_title must be cleared, got %v", *got.PageTitle)
	}

	// 显式空白字符串：清空。
	if _, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{
		PageTitle: OptionalNullableString{Set: true, Value: strPtr("   ")},
	}); err != nil {
		t.Fatalf("clear title via blank: %v", err)
	}
	got, _ = repository.NewThreadRepo(db).GetBySiteAndID(ctx, siteID, threadA)
	if got.PageTitle != nil {
		t.Fatalf("page_title must stay cleared, got %v", *got.PageTitle)
	}
}

// TestAdminUpdateThreadValidation 验证空输入、空白 key、超长字段与跨站点返回错误。
func TestAdminUpdateThreadValidation(t *testing.T) {
	db := newThreadAdminTestDB(t)
	siteID, threadA, threadB := seedThreadAdminFixture(t, db)
	svc := threadAdminService(db)
	ctx := context.Background()

	if _, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("empty input err = %v, want ErrValidation", err)
	}
	if _, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{PageKey: strPtr("  ")}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("blank key err = %v, want ErrValidation", err)
	}
	longKey := strings.Repeat("a", maxPageKeyLength+1)
	if _, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{PageKey: &longKey}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("long key err = %v, want ErrValidation", err)
	}
	longTitle := strings.Repeat("b", maxPageTitleLength+1)
	if _, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{
		PageTitle: OptionalNullableString{Set: true, Value: &longTitle},
	}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("long title err = %v, want ErrValidation", err)
	}
	// 跨站点 thread_id 视为不存在。
	if _, err := svc.AdminUpdateThread(ctx, siteID+999, threadA, AdminThreadUpdateInput{PageKey: strPtr("x")}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-site err = %v, want ErrNotFound", err)
	}
	// 同站点另一线程的 key 冲突。
	if _, err := svc.AdminUpdateThread(ctx, siteID, threadA, AdminThreadUpdateInput{PageKey: strPtr("beta")}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate key err = %v, want ErrConflict", err)
	}
	// 跨站点隔离：另一站点可自由使用与站点 1 相同的 key。
	otherSite := &domain.Site{Name: "Other", CanonicalURL: "https://other.example.com", Status: domain.SiteStatusActive}
	if err := repository.NewSiteRepo(db).Create(ctx, otherSite); err != nil {
		t.Fatalf("create other site: %v", err)
	}
	// 站点 2 与站点 1 都持有 beta：证明唯一性按站点隔离。
	if _, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, otherSite.ID, "beta", nil, nil); err != nil {
		t.Fatalf("create other beta: %v", err)
	}
	// 其他站点内更新到已占用 key 仍冲突。
	otherAlpha, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, otherSite.ID, "alpha", nil, nil)
	if err != nil {
		t.Fatalf("create other alpha: %v", err)
	}
	_ = threadB
	if _, err := svc.AdminUpdateThread(ctx, otherSite.ID, otherAlpha.ID, AdminThreadUpdateInput{PageKey: strPtr("beta")}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("same-site duplicate key err = %v, want ErrConflict", err)
	}
}

// strPtr 返回字符串指针。
func strPtr(s string) *string {
	return &s
}

// TestAdminDeleteThreadRequiresConfirm 验证硬删除缺确认返回
// ErrConfirmationRequired 且线程保留。
func TestAdminDeleteThreadRequiresConfirm(t *testing.T) {
	db := newThreadAdminTestDB(t)
	siteID, threadA, _ := seedThreadAdminFixture(t, db)
	svc := threadAdminService(db)
	ctx := context.Background()

	if err := svc.AdminDeleteThread(ctx, siteID, threadA, false); !errors.Is(err, domain.ErrConfirmationRequired) {
		t.Fatalf("err = %v, want ErrConfirmationRequired", err)
	}
	if _, err := repository.NewThreadRepo(db).GetBySiteAndID(ctx, siteID, threadA); err != nil {
		t.Fatalf("thread must survive without confirm: %v", err)
	}
}

// TestAdminDeleteThreadSuccess 验证确认后删除成功，其他线程保留。
func TestAdminDeleteThreadSuccess(t *testing.T) {
	db := newThreadAdminTestDB(t)
	siteID, threadA, threadB := seedThreadAdminFixture(t, db)
	svc := threadAdminService(db)
	ctx := context.Background()

	if err := svc.AdminDeleteThread(ctx, siteID, threadA, true); err != nil {
		t.Fatalf("delete thread: %v", err)
	}
	if _, err := repository.NewThreadRepo(db).GetBySiteAndID(ctx, siteID, threadA); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted thread must be gone, got err=%v", err)
	}
	if _, err := repository.NewThreadRepo(db).GetBySiteAndID(ctx, siteID, threadB); err != nil {
		t.Fatalf("sibling thread must survive: %v", err)
	}
}

// TestAdminDeleteThreadCrossSite 验证跨站点删除视为不存在。
func TestAdminDeleteThreadCrossSite(t *testing.T) {
	db := newThreadAdminTestDB(t)
	siteID, threadA, _ := seedThreadAdminFixture(t, db)
	svc := threadAdminService(db)
	ctx := context.Background()

	if err := svc.AdminDeleteThread(ctx, siteID+999, threadA, true); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-site err = %v, want ErrNotFound", err)
	}
	if _, err := repository.NewThreadRepo(db).GetBySiteAndID(ctx, siteID, threadA); err != nil {
		t.Fatalf("thread must survive: %v", err)
	}
}

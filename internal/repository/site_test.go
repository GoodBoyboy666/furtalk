package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newSiteTestDB 打开临时 SQLite 数据库并迁移站点与 origin 表。
func newSiteTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "site-repo-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.Site{}, &model.SiteOrigin{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// createSiteRow 直接插入一个站点行并返回其 ID。
func createSiteRow(t *testing.T, db *gorm.DB, name string) int64 {
	t.Helper()
	row := model.Site{Name: name, CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create site row: %v", err)
	}
	return row.ID
}

// TestSiteRepoOriginCRUD 验证 origin 记录携带稳定 ID 的完整 CRUD 生命周期。
func TestSiteRepoOriginCRUD(t *testing.T) {
	db := newSiteTestDB(t)
	repo := NewSiteRepo(db)
	ctx := context.Background()
	siteID := createSiteRow(t, db, "Site A")

	created, err := repo.AddOrigin(ctx, siteID, "https://app.example.com")
	if err != nil {
		t.Fatalf("add origin: %v", err)
	}
	if created.ID <= 0 || created.Origin != "https://app.example.com" {
		t.Fatalf("created origin = %+v, want generated id and exact origin", created)
	}

	got, err := repo.GetOrigin(ctx, siteID, created.ID)
	if err != nil {
		t.Fatalf("get origin: %v", err)
	}
	if got.ID != created.ID || got.Origin != created.Origin {
		t.Fatalf("get origin = %+v, want %+v", got, created)
	}

	listed, err := repo.ListOrigins(ctx, siteID)
	if err != nil {
		t.Fatalf("list origins: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID || listed[0].Origin != created.Origin {
		t.Fatalf("list origins = %+v, want one record with stable id", listed)
	}

	updated, err := repo.UpdateOrigin(ctx, siteID, created.ID, "https://cdn.example.com")
	if err != nil {
		t.Fatalf("update origin: %v", err)
	}
	if updated.ID != created.ID || updated.Origin != "https://cdn.example.com" {
		t.Fatalf("updated origin = %+v, want same id with new value", updated)
	}

	// SQLite 的 RowsAffected 只统计实际变更的行：更新为相同值也必须成功，
	// 不能误报 ErrNotFound（PostgreSQL 返回匹配行数，方言语义必须对齐）。
	same, err := repo.UpdateOrigin(ctx, siteID, created.ID, "https://cdn.example.com")
	if err != nil {
		t.Fatalf("update origin to same value: %v", err)
	}
	if same.ID != created.ID || same.Origin != "https://cdn.example.com" {
		t.Fatalf("same-value update = %+v, want unchanged record", same)
	}

	if err := repo.RemoveOrigin(ctx, siteID, created.ID); err != nil {
		t.Fatalf("remove origin: %v", err)
	}
	if _, err := repo.GetOrigin(ctx, siteID, created.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get removed origin err = %v, want domain.ErrNotFound", err)
	}
}

// TestSiteRepoOriginRejectsCrossSite 验证 origin 读写都限定在 site_id 作用域内。
func TestSiteRepoOriginRejectsCrossSite(t *testing.T) {
	db := newSiteTestDB(t)
	repo := NewSiteRepo(db)
	ctx := context.Background()
	siteA := createSiteRow(t, db, "Site A")
	siteB := createSiteRow(t, db, "Site B")

	created, err := repo.AddOrigin(ctx, siteA, "https://a.example.com")
	if err != nil {
		t.Fatalf("add origin: %v", err)
	}

	if _, err := repo.GetOrigin(ctx, siteB, created.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-site get err = %v, want domain.ErrNotFound", err)
	}
	if _, err := repo.UpdateOrigin(ctx, siteB, created.ID, "https://b.example.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-site update err = %v, want domain.ErrNotFound", err)
	}
	if err := repo.RemoveOrigin(ctx, siteB, created.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-site remove err = %v, want domain.ErrNotFound", err)
	}

	// 原站点记录必须保持完好。
	got, err := repo.GetOrigin(ctx, siteA, created.ID)
	if err != nil {
		t.Fatalf("get origin on owning site: %v", err)
	}
	if got.Origin != "https://a.example.com" {
		t.Fatalf("owning-site origin = %q, want unchanged", got.Origin)
	}
}

// TestSiteRepoOriginDuplicate 验证重复值映射为 domain.ErrConflict。
func TestSiteRepoOriginDuplicate(t *testing.T) {
	db := newSiteTestDB(t)
	repo := NewSiteRepo(db)
	ctx := context.Background()
	siteID := createSiteRow(t, db, "Site A")

	if _, err := repo.AddOrigin(ctx, siteID, "https://app.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	if _, err := repo.AddOrigin(ctx, siteID, "https://app.example.com"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate add err = %v, want domain.ErrConflict", err)
	}

	other, err := repo.AddOrigin(ctx, siteID, "https://other.example.com")
	if err != nil {
		t.Fatalf("add second origin: %v", err)
	}
	if _, err := repo.UpdateOrigin(ctx, siteID, other.ID, "https://app.example.com"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate update err = %v, want domain.ErrConflict", err)
	}

	// 不同站点允许相同的 origin 值。
	siteB := createSiteRow(t, db, "Site B")
	if _, err := repo.AddOrigin(ctx, siteB, "https://app.example.com"); err != nil {
		t.Fatalf("add same origin to another site: %v", err)
	}
}

// TestSiteRepoAllowedOriginsStringOnly 验证 CORS 投影仍返回纯字符串列表。
func TestSiteRepoAllowedOriginsStringOnly(t *testing.T) {
	db := newSiteTestDB(t)
	repo := NewSiteRepo(db)
	ctx := context.Background()
	siteID := createSiteRow(t, db, "Site A")

	if _, err := repo.AddOrigin(ctx, siteID, "https://one.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	if _, err := repo.AddOrigin(ctx, siteID, "https://two.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}

	origins, err := repo.AllowedOrigins(ctx, siteID)
	if err != nil {
		t.Fatalf("allowed origins: %v", err)
	}
	if len(origins) != 2 || origins[0] != "https://one.example.com" || origins[1] != "https://two.example.com" {
		t.Fatalf("allowed origins = %v, want string-only list ordered by id", origins)
	}
}

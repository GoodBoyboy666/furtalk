package site

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newServiceTestDB 打开临时 SQLite 数据库并迁移站点相关表。
func newServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "site-service-test.db")
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

// newServiceWithSite 构建服务并创建一个站点，返回服务与站点 ID。
func newServiceWithSite(t *testing.T, name string) (*Service, int64) {
	t.Helper()
	db := newServiceTestDB(t)
	svc := NewService(repository.NewSiteRepo(db))
	site, err := svc.Create(context.Background(), name, "https://example.com")
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	return svc, site.ID
}

// TestServiceAddOriginNormalizesAndReturnsRecord 验证添加时规范化并返回带 ID 的记录。
func TestServiceAddOriginNormalizesAndReturnsRecord(t *testing.T) {
	svc, siteID := newServiceWithSite(t, "Site A")
	ctx := context.Background()

	created, err := svc.AddOrigin(ctx, siteID, " https://App.Example.COM ")
	if err != nil {
		t.Fatalf("add origin: %v", err)
	}
	if created.ID <= 0 {
		t.Fatalf("created origin id = %d, want positive", created.ID)
	}
	if created.Origin != "https://app.example.com" {
		t.Fatalf("created origin = %q, want normalized https://app.example.com", created.Origin)
	}

	// 站点读取必须携带稳定 ID。
	site, err := svc.Get(ctx, siteID)
	if err != nil {
		t.Fatalf("get site: %v", err)
	}
	if len(site.Origins) != 1 || site.Origins[0].ID != created.ID || site.Origins[0].Origin != "https://app.example.com" {
		t.Fatalf("site origins = %+v, want one record with id %d", site.Origins, created.ID)
	}
}

// TestServiceAddOriginRejectsInvalidValues 验证非法 origin 值返回 domain.ErrValidation。
func TestServiceAddOriginRejectsInvalidValues(t *testing.T) {
	svc, siteID := newServiceWithSite(t, "Site A")
	ctx := context.Background()

	cases := []string{
		"",
		"null",
		"*",
		"https://*.example.com",
		"not-a-url",
		"ftp://example.com",
		"https://example.com/path",
		"https://user@example.com",
		"http://not-localhost.example.com",
	}
	for _, input := range cases {
		if _, err := svc.AddOrigin(ctx, siteID, input); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("add origin %q err = %v, want domain.ErrValidation", input, err)
		}
	}
}

// TestServiceAddOriginDuplicateAndMissingSite 验证重复与站点不存在分别映射为冲突与 not found。
func TestServiceAddOriginDuplicateAndMissingSite(t *testing.T) {
	svc, siteID := newServiceWithSite(t, "Site A")
	ctx := context.Background()

	if _, err := svc.AddOrigin(ctx, siteID, "https://app.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	if _, err := svc.AddOrigin(ctx, siteID, "https://app.example.com"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate add err = %v, want domain.ErrConflict", err)
	}
	if _, err := svc.AddOrigin(ctx, 9999, "https://new.example.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing site add err = %v, want domain.ErrNotFound", err)
	}
}

// TestServiceUpdateOrigin 验证更新规范化、成功返回、跨站点与重复拒绝。
func TestServiceUpdateOrigin(t *testing.T) {
	svc, siteID := newServiceWithSite(t, "Site A")
	ctx := context.Background()

	created, err := svc.AddOrigin(ctx, siteID, "https://app.example.com")
	if err != nil {
		t.Fatalf("add origin: %v", err)
	}
	if _, err := svc.AddOrigin(ctx, siteID, "https://other.example.com"); err != nil {
		t.Fatalf("add second origin: %v", err)
	}

	updated, err := svc.UpdateOrigin(ctx, siteID, created.ID, " https://cdn.example.com ")
	if err != nil {
		t.Fatalf("update origin: %v", err)
	}
	if updated.ID != created.ID || updated.Origin != "https://cdn.example.com" {
		t.Fatalf("updated origin = %+v, want id %d with normalized value", updated, created.ID)
	}

	if _, err := svc.UpdateOrigin(ctx, siteID, created.ID, "https://other.example.com"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate update err = %v, want domain.ErrConflict", err)
	}
	if _, err := svc.UpdateOrigin(ctx, siteID, created.ID, "not-a-url"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid update err = %v, want domain.ErrValidation", err)
	}
	if _, err := svc.UpdateOrigin(ctx, 9999, created.ID, "https://x.example.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing site update err = %v, want domain.ErrNotFound", err)
	}
}

// TestServiceRemoveOriginCrossSiteRejected 验证删除必须落在同一站点作用域。
func TestServiceRemoveOriginCrossSiteRejected(t *testing.T) {
	svc, siteA := newServiceWithSite(t, "Site A")
	ctx := context.Background()
	created, err := svc.AddOrigin(ctx, siteA, "https://app.example.com")
	if err != nil {
		t.Fatalf("add origin: %v", err)
	}

	// 第二个服务实例的站点 ID 删除第一个站点的 origin 必须失败。
	second, siteB := newServiceWithSite(t, "Site B")
	if err := second.RemoveOrigin(ctx, siteB, created.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-site remove err = %v, want domain.ErrNotFound", err)
	}
	if err := svc.RemoveOrigin(ctx, siteA, created.ID); err != nil {
		t.Fatalf("owning-site remove: %v", err)
	}
}

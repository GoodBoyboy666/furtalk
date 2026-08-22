package app

import (
	"context"
	"path/filepath"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/setting"
)

// TestCommentPolicyProjectsCommentSort 验证组合根的策略适配器把动态设置中的
// comment_sort 逐字段投影到 CommentPolicy，构成 settings -> runtime-config ->
// public query 的跨层契约。
func TestCommentPolicyProjectsCommentSort(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "policy-projection.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.DynamicSetting{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	svc := setting.NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	reader := commentPolicyReader{svc: svc}

	// 默认 asc 投影。
	pol, err := reader.CommentPolicy(context.Background())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if pol.CommentSort != string(domain.CommentSortAsc) {
		t.Fatalf("comment_sort = %q, want asc default", pol.CommentSort)
	}

	// PATCH 为 desc 后投影立即反映新值。
	if _, err := svc.Patch(context.Background(), []setting.SettingItem{
		{Key: setting.SettingKeyCommentSort, Type: setting.SettingTypeString, Value: string(domain.CommentSortDesc)},
	}, 1); err != nil {
		t.Fatalf("patch comment sort: %v", err)
	}
	pol, err = reader.CommentPolicy(context.Background())
	if err != nil {
		t.Fatalf("policy after patch: %v", err)
	}
	if pol.CommentSort != string(domain.CommentSortDesc) {
		t.Fatalf("comment_sort = %q, want desc after patch", pol.CommentSort)
	}

	// 默认 EmojiCatalogURL 为空串。
	if pol.EmojiCatalogURL != "" {
		t.Fatalf("emoji_catalog_url = %q, want empty default", pol.EmojiCatalogURL)
	}

	// PATCH 后投影立即反映新目录 URL。
	if _, err := svc.Patch(context.Background(), []setting.SettingItem{
		{Key: setting.SettingKeyEmojiCatalogURL, Type: setting.SettingTypeString, Value: "https://cdn.example/emoji.json"},
	}, 1); err != nil {
		t.Fatalf("patch emoji catalog url: %v", err)
	}
	pol, err = reader.CommentPolicy(context.Background())
	if err != nil {
		t.Fatalf("policy after catalog patch: %v", err)
	}
	if pol.EmojiCatalogURL != "https://cdn.example/emoji.json" {
		t.Fatalf("emoji_catalog_url = %q, want configured value", pol.EmojiCatalogURL)
	}
}

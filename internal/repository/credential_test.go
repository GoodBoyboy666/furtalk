package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newPasskeyTestDB 打开临时 SQLite 数据库并迁移 passkey 相关表。
func newPasskeyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "passkey-repo-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.PasskeyCredential{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// insertUserRow 插入一个占位用户并返回其 ID。
func insertUserRow(t *testing.T, db *gorm.DB, email string) int64 {
	t.Helper()
	user := model.User{
		Email:           email,
		EmailNormalized: email,
		Nickname:        "user",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		CreatedAt:       time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user.ID
}

// insertPasskeyRow 直接插入一条 passkey 凭据并返回其 ID。
func insertPasskeyRow(t *testing.T, db *gorm.DB, userID int64, name string) int64 {
	t.Helper()
	row := model.PasskeyCredential{
		UserID:       userID,
		CredentialID: "cred-" + name,
		PublicKey:    []byte("public-key"),
		Name:         name,
		CreatedAt:    time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create passkey: %v", err)
	}
	return row.ID
}

// TestPasskeyRepoRenameByUserAndID 验证名称更新只影响所属用户的凭证并持久化新名称。
func TestPasskeyRepoRenameByUserAndID(t *testing.T) {
	db := newPasskeyTestDB(t)
	repo := NewPasskeyRepo(db)
	ctx := context.Background()

	userID := insertUserRow(t, db, "owner@example.com")
	id := insertPasskeyRow(t, db, userID, "原名称")
	if err := repo.RenameByUserAndID(ctx, userID, id, "新名称"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	row, err := repo.GetByUserIDAndID(ctx, userID, id)
	if err != nil {
		t.Fatalf("get renamed: %v", err)
	}
	if row.Name != "新名称" {
		t.Fatalf("name = %q, want 新名称", row.Name)
	}
}

// TestPasskeyRepoRenameByUserAndIDScopesOwnership 验证不能重命名其他用户的凭证。
func TestPasskeyRepoRenameByUserAndIDScopesOwnership(t *testing.T) {
	db := newPasskeyTestDB(t)
	repo := NewPasskeyRepo(db)
	ctx := context.Background()

	ownerID := insertUserRow(t, db, "owner@example.com")
	otherID := insertUserRow(t, db, "other@example.com")
	id := insertPasskeyRow(t, db, ownerID, "原名称")
	if err := repo.RenameByUserAndID(ctx, otherID, id, "越权名称"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want domain.ErrNotFound", err)
	}
	row, err := repo.GetByUserIDAndID(ctx, ownerID, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Name != "原名称" {
		t.Fatalf("name changed to %q despite cross-user rename", row.Name)
	}
}

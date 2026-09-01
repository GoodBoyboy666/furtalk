package repository

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newUserTestDB 打开临时 SQLite 数据库并迁移用户相关表。
func newUserTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "user-repo-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// userColumns 读取 SQLite PRAGMA table_info(users)，返回列名到 notnull 的映射。
func userColumns(t *testing.T, db *gorm.DB) map[string]bool {
	t.Helper()
	rows, err := db.Raw("PRAGMA table_info(users)").Rows()
	if err != nil {
		t.Fatalf("read table_info: %v", err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name string
		var ctype string
		var notnull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		columns[name] = notnull == 1
	}
	return columns
}

// TestUserSchemaHasPasswordColumns 验证 users 表包含可空的密码字段且不创建 password_credentials 表。
func TestUserSchemaHasPasswordColumns(t *testing.T) {
	db := newUserTestDB(t)
	columns := userColumns(t, db)
	for _, name := range []string{"password_hash", "password_changed_at"} {
		if _, ok := columns[name]; !ok {
			t.Fatalf("users table is missing %s column", name)
		}
		if columns[name] {
			t.Fatalf("users.%s must be nullable", name)
		}
	}
	var credentialTables int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='password_credentials'").Scan(&credentialTables).Error; err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if credentialTables != 0 {
		t.Fatal("password_credentials table must not be created")
	}
}

// TestUserSchemaHasSessionVersionColumn 验证 users 表包含非空、默认 1 的
// session_version 列，且既有行回填与新建行都得到正整数代次。
func TestUserSchemaHasSessionVersionColumn(t *testing.T) {
	db := newUserTestDB(t)
	columns := userColumns(t, db)
	notNull, ok := columns["session_version"]
	if !ok {
		t.Fatal("users table is missing session_version column")
	}
	if !notNull {
		t.Fatal("users.session_version must be NOT NULL")
	}

	repo := NewUserRepo(db)
	user := &domain.User{
		Email:           "version@example.com",
		EmailNormalized: "version@example.com",
		Nickname:        "version",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	ctx := context.Background()
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if user.SessionVersion != 1 {
		t.Fatalf("new user session version = %d, want DB default 1", user.SessionVersion)
	}
	fetched, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if fetched.SessionVersion != 1 {
		t.Fatalf("round-tripped session version = %d, want 1", fetched.SessionVersion)
	}
}

// TestUserSessionVersionCheckConstraint 验证 session_version 的正数 CHECK
// 约束拒绝非正代次写入。使用 map 方式插入显式零值，DB 默认值不会替换它。
func TestUserSessionVersionCheckConstraint(t *testing.T) {
	db := newUserTestDB(t)
	bad := db.Model(&model.User{}).Create(map[string]any{
		"email":            "bad@example.com",
		"email_normalized": "bad@example.com",
		"nickname":         "bad",
		"role":             domain.RoleUser,
		"status":           domain.UserStatusActive,
		"session_version":  0,
	})
	if bad.Error == nil {
		t.Fatal("insert with non-positive session_version must be rejected")
	}
}

// TestUserPasswordPairedNullConstraint 验证 CHECK 约束拒绝只有一半密码状态的插入。
func TestUserPasswordPairedNullConstraint(t *testing.T) {
	db := newUserTestDB(t)
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$c2FsdHNhbHQ"

	// 只有哈希没有时间戳必须被约束拒绝。
	partial := model.User{
		Email:           "partial@example.com",
		EmailNormalized: "partial@example.com",
		Nickname:        "partial",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		PasswordHash:    &hash,
	}
	if err := db.Create(&partial).Error; err == nil {
		t.Fatal("insert with password_hash but null password_changed_at must be rejected")
	}

	// 只有时间戳没有哈希也必须被约束拒绝。
	otherPartial := model.User{
		Email:             "other@example.com",
		EmailNormalized:   "other@example.com",
		Nickname:          "other",
		Role:              domain.RoleUser,
		Status:            domain.UserStatusActive,
		PasswordChangedAt: &now,
	}
	if err := db.Create(&otherPartial).Error; err == nil {
		t.Fatal("insert with password_changed_at but null password_hash must be rejected")
	}

	// 两者都空（未配置密码）允许。
	plain := model.User{
		Email:           "plain@example.com",
		EmailNormalized: "plain@example.com",
		Nickname:        "plain",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := db.Create(&plain).Error; err != nil {
		t.Fatalf("insert user without password must succeed: %v", err)
	}

	// 两者都非空（已配置密码）允许。
	complete := model.User{
		Email:             "complete@example.com",
		EmailNormalized:   "complete@example.com",
		Nickname:          "complete",
		Role:              domain.RoleUser,
		Status:            domain.UserStatusActive,
		PasswordHash:      &hash,
		PasswordChangedAt: &now,
	}
	if err := db.Create(&complete).Error; err != nil {
		t.Fatalf("insert user with password must succeed: %v", err)
	}
}

// TestUserRepoCreateWithPassword 验证 CreateWithPassword 插入用户与密码状态并回填主键。
func TestUserRepoCreateWithPassword(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

	user := &domain.User{
		Email:           "admin@example.com",
		EmailNormalized: "admin@example.com",
		Nickname:        "Admin",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := repo.CreateWithPassword(ctx, user, "$argon2id$hash", now); err != nil {
		t.Fatalf("create with password: %v", err)
	}
	if user.ID <= 0 {
		t.Fatal("create with password must backfill the user ID")
	}

	hash, err := repo.PasswordHash(ctx, user.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if hash != "$argon2id$hash" {
		t.Fatalf("password hash = %q, want the stored envelope", hash)
	}
	has, err := repo.HasPassword(ctx, user.ID)
	if err != nil {
		t.Fatalf("has password: %v", err)
	}
	if !has {
		t.Fatal("user created with password must report has_password = true")
	}
}

// TestUserRepoSetPassword 验证 SetPassword 同时更新两个密码列并支持查询。
func TestUserRepoSetPassword(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	user := &domain.User{
		Email:           "user@example.com",
		EmailNormalized: "user@example.com",
		Nickname:        "user",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	version, err := repo.SetPassword(ctx, user.ID, "$argon2id$v2", now)
	if err != nil {
		t.Fatalf("set password: %v", err)
	}
	if version != 2 {
		t.Fatalf("session version after first set = %d, want 2", version)
	}

	// 重复设置为相同值也必须成功（SQLite 只统计实际变更的行）。
	version, err = repo.SetPassword(ctx, user.ID, "$argon2id$v2", now)
	if err != nil {
		t.Fatalf("set password to same value: %v", err)
	}
	if version != 3 {
		t.Fatalf("session version after second set = %d, want 3", version)
	}

	hash, err := repo.PasswordHash(ctx, user.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if hash != "$argon2id$v2" {
		t.Fatalf("password hash = %q, want updated envelope", hash)
	}
	has, err := repo.HasPassword(ctx, user.ID)
	if err != nil {
		t.Fatalf("has password: %v", err)
	}
	if !has {
		t.Fatal("user with set password must report has_password = true")
	}
}

// TestUserRepoBumpSessionVersionConcurrent 验证每次并发会话撤销都获得唯一的
// 数据库生成代次，避免 PostgreSQL READ COMMITTED 下的读改写丢失递增。
func TestUserRepoBumpSessionVersionConcurrent(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	runner := gormtx.NewRunner(db)
	ctx := context.Background()
	user := &domain.User{
		Email:           "concurrent@example.com",
		EmailNormalized: "concurrent@example.com",
		Nickname:        "concurrent",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	const workers = 8
	versions := make([]int64, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var bumpErr error
			errs[i] = runner.RunInTx(ctx, func(txctx context.Context) error {
				versions[i], bumpErr = repo.BumpSessionVersion(txctx, user.ID)
				return bumpErr
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d bump session version: %v", i, err)
		}
	}

	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for i, version := range versions {
		want := int64(i + 2)
		if version != want {
			t.Fatalf("sorted returned version[%d] = %d, want %d; versions=%v", i, version, want, versions)
		}
	}
	fetched, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find concurrently bumped user: %v", err)
	}
	if fetched.SessionVersion != workers+1 {
		t.Fatalf("final session version = %d, want %d", fetched.SessionVersion, workers+1)
	}
}

// TestUserRepoSessionVersionPostgresSQL 验证 PostgreSQL 方言生成数据库原子递增
// 与 RETURNING，而不是把当前代次读回 Go 后再写入字面量。测试使用 SQLite 连接
// 仅作为 GORM DryRun 的 Conn，占位连接不会执行 SQL。
func TestUserRepoSessionVersionPostgresSQL(t *testing.T) {
	sqliteDB := newUserTestDB(t)
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
	repo := NewUserRepo(postgresDB)
	ctx := context.Background()
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)

	_, _ = repo.SetPassword(ctx, 7, "hash", now)
	if !strings.Contains(capture.sql, `"session_version"=session_version +`) || !strings.Contains(capture.sql, `RETURNING "session_version"`) {
		t.Fatalf("SetPassword SQL must atomically increment and return session_version, got: %s", capture.sql)
	}

	_, _ = repo.BumpSessionVersion(ctx, 7)
	if !strings.Contains(capture.sql, `"session_version"=session_version +`) || !strings.Contains(capture.sql, `RETURNING "session_version"`) {
		t.Fatalf("BumpSessionVersion SQL must atomically increment and return session_version, got: %s", capture.sql)
	}

	_, _, _ = repo.ResetPasswordByEmail(ctx, "dry@example.com", "hash", now, now)
	if !strings.Contains(capture.sql, `"session_version"=session_version +`) ||
		!strings.Contains(capture.sql, `RETURNING "id","session_version"`) {
		t.Fatalf("ResetPasswordByEmail SQL must atomically increment and return id/version, got: %s", capture.sql)
	}
}

// TestUserRepoPasswordMethodsNotFound 验证未配置密码与不存在用户的错误语义。
func TestUserRepoPasswordMethodsNotFound(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	user := &domain.User{
		Email:           "plain@example.com",
		EmailNormalized: "plain@example.com",
		Nickname:        "plain",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := repo.PasswordHash(ctx, user.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("password hash on plain user err = %v, want domain.ErrNotFound", err)
	}
	has, err := repo.HasPassword(ctx, user.ID)
	if err != nil {
		t.Fatalf("has password: %v", err)
	}
	if has {
		t.Fatal("plain user must report has_password = false")
	}
	if _, err := repo.SetPassword(ctx, 9999, "$argon2id$x", time.Now().UTC()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("set password on missing user err = %v, want domain.ErrNotFound", err)
	}
	if _, err := repo.PasswordHash(ctx, 9999); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("password hash on missing user err = %v, want domain.ErrNotFound", err)
	}
	if _, err := repo.HasPassword(ctx, 9999); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("has password on missing user err = %v, want domain.ErrNotFound", err)
	}
}

// TestUserRepoCreateWithPasswordConflict 验证重复邮箱映射为 domain.ErrConflict。
func TestUserRepoCreateWithPasswordConflict(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	base := &domain.User{
		Email:           "dup@example.com",
		EmailNormalized: "dup@example.com",
		Nickname:        "dup",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.CreateWithPassword(ctx, base, "$argon2id$a", now); err != nil {
		t.Fatalf("first create with password: %v", err)
	}
	second := &domain.User{
		Email:           "dup@example.com",
		EmailNormalized: "dup@example.com",
		Nickname:        "dup",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.CreateWithPassword(ctx, second, "$argon2id$b", now); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate create with password err = %v, want domain.ErrConflict", err)
	}
}

// TestUserRepoUpdateAdmin 验证 UpdateAdmin 合并写入邮箱、昵称、网站、角色、
// 状态与验证时间，且 SQLite 相同值更新也成功（RowsAffected 不用于判断存在性）。
func TestUserRepoUpdateAdmin(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	user := &domain.User{
		Email:           "old@example.com",
		EmailNormalized: "old@example.com",
		Nickname:        "old",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	website := "https://example.com"
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	fields := map[string]any{
		"email":             "new@example.com",
		"email_normalized":  "new@example.com",
		"nickname":          "new-nickname",
		"website_url":       &website,
		"role":              domain.RoleAdmin,
		"status":            domain.UserStatusActive,
		"email_verified_at": &now,
	}
	if err := repo.UpdateAdmin(ctx, user.ID, fields); err != nil {
		t.Fatalf("update admin: %v", err)
	}
	updated, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find updated user: %v", err)
	}
	if updated.Email != "new@example.com" || updated.EmailNormalized != "new@example.com" {
		t.Fatalf("email = %q/%q, want new values", updated.Email, updated.EmailNormalized)
	}
	if updated.Nickname != "new-nickname" {
		t.Fatalf("nickname = %q, want new-nickname", updated.Nickname)
	}
	if updated.WebsiteURL == nil || *updated.WebsiteURL != website {
		t.Fatalf("website = %v, want %q", updated.WebsiteURL, website)
	}
	if updated.Role != domain.RoleAdmin || updated.Status != domain.UserStatusActive {
		t.Fatalf("role/status = %q/%q, want admin/active", updated.Role, updated.Status)
	}
	if updated.EmailVerifiedAt == nil || !updated.EmailVerifiedAt.Equal(now) {
		t.Fatalf("email_verified_at = %v, want %v", updated.EmailVerifiedAt, now)
	}

	// 相同值重复更新必须成功（SQLite 只统计实际变更行）。
	if err := repo.UpdateAdmin(ctx, user.ID, fields); err != nil {
		t.Fatalf("same-value update admin: %v", err)
	}
}

// TestUserRepoUpdateAdminNullFields 验证显式 null 可清除网站与验证时间。
func TestUserRepoUpdateAdminNullFields(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	user := &domain.User{
		Email:           "clear@example.com",
		EmailNormalized: "clear@example.com",
		Nickname:        "clear",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := repo.UpdateAdmin(ctx, user.ID, map[string]any{
		"website_url":       nil,
		"email_verified_at": nil,
	}); err != nil {
		t.Fatalf("clear nullable fields: %v", err)
	}
	updated, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find updated user: %v", err)
	}
	if updated.WebsiteURL != nil {
		t.Fatalf("website = %v, want nil", updated.WebsiteURL)
	}
	if updated.EmailVerifiedAt != nil {
		t.Fatalf("email_verified_at = %v, want nil", updated.EmailVerifiedAt)
	}
}

// TestUserRepoUpdateAdminConflict 验证更新邮箱冲突映射为 domain.ErrConflict。
func TestUserRepoUpdateAdminConflict(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	first := &domain.User{
		Email:           "first@example.com",
		EmailNormalized: "first@example.com",
		Nickname:        "first",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("create first user: %v", err)
	}
	second := &domain.User{
		Email:           "second@example.com",
		EmailNormalized: "second@example.com",
		Nickname:        "second",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("create second user: %v", err)
	}
	err := repo.UpdateAdmin(ctx, second.ID, map[string]any{
		"email":            "first@example.com",
		"email_normalized": "first@example.com",
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("email conflict err = %v, want domain.ErrConflict", err)
	}
}

// TestUserRepoUpdateAdminNotFound 验证更新不存在的用户返回 domain.ErrNotFound。
func TestUserRepoUpdateAdminNotFound(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	err := repo.UpdateAdmin(ctx, 9999, map[string]any{"nickname": "x"})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("update missing user err = %v, want domain.ErrNotFound", err)
	}
}

// TestUserSchemaHasDeletionColumns 验证 users 表包含软删除生命周期字段。
func TestUserSchemaHasDeletionColumns(t *testing.T) {
	db := newUserTestDB(t)
	columns := userColumns(t, db)
	for _, name := range []string{"deleted_at", "status_before_delete"} {
		if _, ok := columns[name]; !ok {
			t.Fatalf("users table is missing %s column", name)
		}
	}
}

// TestUserRepoSoftDeleteAndRestore 验证软删除记录删除时间与前状态，恢复回滚账号状态。
func TestUserRepoSoftDeleteAndRestore(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	user := &domain.User{
		Email:           "soft@example.com",
		EmailNormalized: "soft@example.com",
		Nickname:        "soft",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

	if err := repo.SoftDelete(ctx, user.ID, domain.UserStatusActive, now); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	deleted, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find deleted user: %v", err)
	}
	if deleted.Status != domain.UserStatusDeleted || deleted.DeletedAt == nil || !deleted.DeletedAt.Equal(now) {
		t.Fatalf("soft-deleted user = %+v", deleted)
	}
	if deleted.StatusBeforeDelete == nil || *deleted.StatusBeforeDelete != domain.UserStatusActive {
		t.Fatalf("status_before_delete = %v, want active", deleted.StatusBeforeDelete)
	}

	if err := repo.Restore(ctx, user.ID); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find restored user: %v", err)
	}
	if restored.Status != domain.UserStatusActive || restored.DeletedAt != nil || restored.StatusBeforeDelete != nil {
		t.Fatalf("restored user = %+v", restored)
	}

	if err := repo.SoftDelete(ctx, user.ID, domain.UserStatusDisabled, now); err != nil {
		t.Fatalf("re-soft-delete: %v", err)
	}
	if err := repo.Restore(ctx, user.ID); err != nil {
		t.Fatalf("restore disabled: %v", err)
	}
	disabledRestored, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("find restored disabled: %v", err)
	}
	if disabledRestored.Status != domain.UserStatusDisabled {
		t.Fatalf("restore must return to prior status, got %q", disabledRestored.Status)
	}
}

// TestUserRepoSoftDeleteRestoreNotFound 验证软删/恢复/硬删不存在的用户返回 ErrNotFound。
func TestUserRepoSoftDeleteRestoreNotFound(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := repo.SoftDelete(ctx, 9999, domain.UserStatusActive, now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("soft delete missing user err = %v, want ErrNotFound", err)
	}
	if err := repo.Restore(ctx, 9999); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("restore missing user err = %v, want ErrNotFound", err)
	}
	if err := repo.Delete(ctx, 9999); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing user err = %v, want ErrNotFound", err)
	}
}

// TestUserRepoHardDeleteRemovesRow 验证硬删除物理移除用户行。
func TestUserRepoHardDeleteRemovesRow(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	user := &domain.User{
		Email:           "gone@example.com",
		EmailNormalized: "gone@example.com",
		Nickname:        "gone",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := repo.Delete(ctx, user.ID); err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if _, err := repo.FindByID(ctx, user.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("hard-deleted user still exists: %v", err)
	}
}

// TestUserRepoCountMatchesSearch 验证 Count 与 List 使用同一搜索谓词且与 limit 无关。
func TestUserRepoCountMatchesSearch(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()
	for i, email := range []string{"alice@example.com", "bob@example.com", "carol@example.com"} {
		if err := repo.Create(ctx, &domain.User{
			Email:           email,
			EmailNormalized: email,
			Nickname:        "user" + string(rune('a'+i)),
			Role:            domain.RoleUser,
			Status:          domain.UserStatusActive,
		}); err != nil {
			t.Fatalf("create user %s: %v", email, err)
		}
	}
	total, err := repo.Count(ctx, "")
	if err != nil {
		t.Fatalf("count all: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	matched, err := repo.Count(ctx, "bob")
	if err != nil {
		t.Fatalf("count search: %v", err)
	}
	if matched != 1 {
		t.Fatalf("search total = %d, want 1", matched)
	}
}

// TestUserRepoMarkEmailVerified 验证 MarkEmailVerified 幂等写入验证时间：
// 首次写入、已验证用户保留原时间，缺失用户返回 ErrNotFound。
func TestUserRepoMarkEmailVerified(t *testing.T) {
	db := newUserTestDB(t)
	repo := NewUserRepo(db)
	ctx := context.Background()

	u := &domain.User{
		Email: "mark@example.com", EmailNormalized: "mark@example.com",
		Nickname: "mark", Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	first := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	written, err := repo.MarkEmailVerified(ctx, u.ID, first)
	if err != nil {
		t.Fatalf("mark verified first: %v", err)
	}
	if !written {
		t.Fatal("first mark should report written=true")
	}
	got, err := repo.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if got.EmailVerifiedAt == nil || !got.EmailVerifiedAt.Equal(first) {
		t.Fatalf("email_verified_at = %v, want %v", got.EmailVerifiedAt, first)
	}

	later := first.Add(24 * time.Hour)
	written, err = repo.MarkEmailVerified(ctx, u.ID, later)
	if err != nil {
		t.Fatalf("mark verified second: %v", err)
	}
	if written {
		t.Fatal("second mark should report written=false (already verified)")
	}
	got, err = repo.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("find user after second: %v", err)
	}
	if got.EmailVerifiedAt == nil || !got.EmailVerifiedAt.Equal(first) {
		t.Fatalf("email_verified_at overwritten to %v, want preserved %v", got.EmailVerifiedAt, first)
	}

	if _, err := repo.MarkEmailVerified(ctx, u.ID+99999, first); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing user err = %v, want domain.ErrNotFound", err)
	}
}

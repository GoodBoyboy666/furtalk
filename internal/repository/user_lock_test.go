package repository

import (
	"context"
	"strings"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestUserRepoLockQueries 验证用户锁与活跃管理员集合锁的双方言 SQL 和 SQLite 执行路径。
func TestUserRepoLockQueries(t *testing.T) {
	sqliteDB := newUserTestDB(t)
	repo := NewUserRepo(sqliteDB)
	ctx := context.Background()
	admin := &domain.User{
		Email: "lock-admin@example.com", EmailNormalized: "lock-admin@example.com",
		Nickname: "lock-admin", Role: domain.RoleAdmin, Status: domain.UserStatusActive,
	}
	if err := repo.Create(ctx, admin); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if count, err := repo.LockActiveAdmins(ctx); err != nil || count != 1 {
		t.Fatalf("sqlite active-admin lock = %d, %v; want 1/nil", count, err)
	}
	if _, err := repo.FindByIDLocked(ctx, admin.ID); err != nil {
		t.Fatalf("sqlite locked user read: %v", err)
	}

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
	pgRepo := NewUserRepo(postgresDB)
	if _, err := pgRepo.LockActiveAdmins(ctx); err != nil {
		t.Fatalf("postgres active-admin lock dry run: %v", err)
	}
	if !strings.Contains(capture.sql, `ORDER BY id FOR UPDATE`) ||
		!strings.Contains(capture.sql, `role =`) || !strings.Contains(capture.sql, `status =`) {
		t.Fatalf("active-admin lock SQL = %q, want ordered FOR UPDATE with role/status predicates", capture.sql)
	}

	if _, err := pgRepo.FindByIDLocked(ctx, admin.ID); err != nil {
		t.Fatalf("postgres user lock dry run: %v", err)
	}
	if !strings.Contains(capture.sql, `WHERE id =`) || !strings.Contains(capture.sql, `FOR UPDATE`) {
		t.Fatalf("user lock SQL = %q, want targeted FOR UPDATE", capture.sql)
	}

	// The lock API must also compose with the ambient transaction handle.
	if err := gormtx.NewRunner(sqliteDB).RunInTx(ctx, func(txCtx context.Context) error {
		_, err := repo.FindByIDLocked(txCtx, admin.ID)
		return err
	}); err != nil {
		t.Fatalf("locked user read in transaction: %v", err)
	}
}

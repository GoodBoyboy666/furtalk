package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newPasskeyRenameEnv 装配使用真实仓储与内存缓存的改名测试环境。
func newPasskeyRenameEnv(t *testing.T) (*Service, *repository.PasskeyRepo) {
	t.Helper()
	db := newPasskeyLoginDB(t)
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{
		TxRunner:       gormtx.NewRunner(db),
		Users:          repository.NewUserRepo(db),
		Passkeys:       repository.NewPasskeyRepo(db),
		Cache:          store,
		Policy:         loginTestPolicy{},
		CaptchaPolicy:  staticCaptchaPolicy{},
		Signer:         loginTestSigner{lifetime: 7 * 24 * time.Hour},
		PasskeyAdapter: nil,
	})
	return svc, repository.NewPasskeyRepo(db)
}

// newPasskeyLoginDB 打开迁移用户与 passkey 表的临时 SQLite 数据库。
func newPasskeyLoginDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newCaptchaLoginDB(t)
	if err := database.AutoMigrate(db, &model.PasskeyCredential{}); err != nil {
		t.Fatalf("auto migrate passkey: %v", err)
	}
	return db
}

// seedPasskeyUser 创建用户并插入一条命名 passkey，返回 (userID, passkeyID)。
func seedPasskeyUser(t *testing.T, svc *Service, name string) (int64, int64) {
	t.Helper()
	user := &domain.User{
		Email: "passkey@example.com", EmailNormalized: "passkey@example.com",
		Nickname: "passkey", Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	if err := svc.users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	row := &domain.PasskeyCredential{
		UserID: user.ID, CredentialID: "cred-" + name, PublicKey: []byte("pk"),
		Name: name, CreatedAt: time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
	}
	if err := svc.passkeys.Create(context.Background(), row); err != nil {
		t.Fatalf("create passkey: %v", err)
	}
	rows, err := svc.passkeys.ListByUserID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("list passkeys: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("passkey count = %d, want 1", len(rows))
	}
	return user.ID, rows[0].ID
}

// TestRenamePasskeyPersistsTrimmedName 验证合法名称经 TrimSpace 后持久化。
func TestRenamePasskeyPersistsTrimmedName(t *testing.T) {
	svc, repo := newPasskeyRenameEnv(t)
	userID, passkeyID := seedPasskeyUser(t, svc, "旧名称")

	if err := svc.RenamePasskey(context.Background(), userID, passkeyID, "  新名称  "); err != nil {
		t.Fatalf("rename: %v", err)
	}
	row, err := repo.GetByUserIDAndID(context.Background(), userID, passkeyID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Name != "新名称" {
		t.Fatalf("name = %q, want 新名称", row.Name)
	}
}

// TestRenamePasskeyRejectsBlank 验证空白名称返回 ErrValidation 且原值保持不变。
func TestRenamePasskeyRejectsBlank(t *testing.T) {
	svc, repo := newPasskeyRenameEnv(t)
	userID, passkeyID := seedPasskeyUser(t, svc, "旧名称")

	if err := svc.RenamePasskey(context.Background(), userID, passkeyID, "   "); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v, want domain.ErrValidation", err)
	}
	row, err := repo.GetByUserIDAndID(context.Background(), userID, passkeyID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Name != "旧名称" {
		t.Fatalf("name changed to %q on invalid input", row.Name)
	}
}

// TestRenamePasskeyRejectsOverlong 验证超过 100 字符的名称返回 ErrValidation。
func TestRenamePasskeyRejectsOverlong(t *testing.T) {
	svc, repo := newPasskeyRenameEnv(t)
	userID, passkeyID := seedPasskeyUser(t, svc, "旧名称")
	long := "x" + string(make([]byte, 100))

	if err := svc.RenamePasskey(context.Background(), userID, passkeyID, long); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v, want domain.ErrValidation", err)
	}
	row, err := repo.GetByUserIDAndID(context.Background(), userID, passkeyID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Name != "旧名称" {
		t.Fatalf("name changed to %q on invalid input", row.Name)
	}
}

// TestRenamePasskeyRejectsForeignCredential 验证不能重命名不属于自己的凭证。
func TestRenamePasskeyRejectsForeignCredential(t *testing.T) {
	svc, _ := newPasskeyRenameEnv(t)
	userID, passkeyID := seedPasskeyUser(t, svc, "旧名称")
	other := &domain.User{
		Email: "other@example.com", EmailNormalized: "other@example.com",
		Nickname: "other", Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	if err := svc.users.Create(context.Background(), other); err != nil {
		t.Fatalf("create other user: %v", err)
	}

	if err := svc.RenamePasskey(context.Background(), other.ID, passkeyID, "越权名称"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want domain.ErrNotFound", err)
	}
	row, err := svc.passkeys.GetByUserIDAndID(context.Background(), userID, passkeyID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Name != "旧名称" {
		t.Fatalf("name changed to %q despite cross-user rename", row.Name)
	}
}

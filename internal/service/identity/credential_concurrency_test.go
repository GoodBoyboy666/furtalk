package identity

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
)

// newCredentialRemovalService 装配用户、passkey 与外部身份真实仓储。
func newCredentialRemovalService(t *testing.T) (*Service, *repository.UserRepo, *repository.PasskeyRepo, *repository.ExternalIdentityRepo) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "identity-credential-removal.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.PasskeyCredential{}, &model.ExternalIdentity{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	users := repository.NewUserRepo(db)
	passkeys := repository.NewPasskeyRepo(db)
	identities := repository.NewExternalIdentityRepo(db)
	svc := NewService(Dependencies{
		TxRunner:   gormtx.NewRunner(db),
		Users:      users,
		Passkeys:   passkeys,
		Identities: identities,
		Cache:      cache.NewMemory(100),
	})
	return svc, users, passkeys, identities
}

// createCredentialRemovalUser 创建一个未配置密码的用户。
func createCredentialRemovalUser(t *testing.T, users *repository.UserRepo, email string) *domain.User {
	t.Helper()
	user := &domain.User{
		Email: email, EmailNormalized: email, Nickname: "credential-user",
		Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

// TestCredentialRemovalsSerializeLastLoginMethod 验证 passkey 与外部身份并发删除不会留下零个登录方式。
func TestCredentialRemovalsSerializeLastLoginMethod(t *testing.T) {
	svc, users, passkeys, identities := newCredentialRemovalService(t)
	user := createCredentialRemovalUser(t, users, "credential-race@example.com")
	passkey := &domain.PasskeyCredential{
		UserID: user.ID, CredentialID: "credential-race-passkey", PublicKey: []byte("key"), Name: "passkey",
	}
	if err := passkeys.Create(context.Background(), passkey); err != nil {
		t.Fatalf("create passkey: %v", err)
	}
	passkeyRows, err := passkeys.ListByUserID(context.Background(), user.ID)
	if err != nil || len(passkeyRows) != 1 {
		t.Fatalf("list created passkey: count=%d err=%v", len(passkeyRows), err)
	}
	passkey.ID = passkeyRows[0].ID
	external := &domain.ExternalIdentity{
		UserID: user.ID, ProviderKey: "github", ProviderSubject: "credential-race-subject",
	}
	if err := identities.Create(context.Background(), external); err != nil {
		t.Fatalf("create external identity: %v", err)
	}
	externalRows, err := identities.ListByUserID(context.Background(), user.ID)
	if err != nil || len(externalRows) != 1 {
		t.Fatalf("list created external identity: count=%d err=%v", len(externalRows), err)
	}
	external.ID = externalRows[0].ID

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errs <- svc.DeletePasskey(context.Background(), user.ID, passkey.ID)
	}()
	go func() {
		defer wg.Done()
		<-start
		errs <- svc.DeleteExternalIdentity(context.Background(), user.ID, external.ID)
	}()
	close(start)
	wg.Wait()
	close(errs)

	var success, lastMethod int
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, domain.ErrLastLoginMethod):
			lastMethod++
		default:
			t.Fatalf("concurrent credential removal err = %v, want nil or ErrLastLoginMethod", err)
		}
	}
	if success != 1 || lastMethod != 1 {
		t.Fatalf("concurrent credential results success=%d lastMethod=%d, want 1/1", success, lastMethod)
	}
	remaining, err := svc.loginMethodCount(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("count remaining login methods: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining login methods = %d, want 1", remaining)
	}
}

// TestDeletePasskeyPreservesPasswordLogin 验证密码与 passkey 并存时可移除 passkey 且密码仍可用。
func TestDeletePasskeyPreservesPasswordLogin(t *testing.T) {
	svc, users, passkeys, _ := newCredentialRemovalService(t)
	user := createCredentialRemovalUser(t, users, "credential-password@example.com")
	if _, err := users.SetPassword(context.Background(), user.ID, "test-password-hash", time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("set password: %v", err)
	}
	passkey := &domain.PasskeyCredential{
		UserID: user.ID, CredentialID: "credential-password-passkey", PublicKey: []byte("key"), Name: "passkey",
	}
	if err := passkeys.Create(context.Background(), passkey); err != nil {
		t.Fatalf("create passkey: %v", err)
	}
	rows, err := passkeys.ListByUserID(context.Background(), user.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list created passkey: count=%d err=%v", len(rows), err)
	}
	passkey.ID = rows[0].ID
	if err := svc.DeletePasskey(context.Background(), user.ID, passkey.ID); err != nil {
		t.Fatalf("delete passkey with password: %v", err)
	}
	hasPassword, err := users.HasPassword(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("check password after passkey delete: %v", err)
	}
	if !hasPassword {
		t.Fatal("password login must remain configured")
	}
}

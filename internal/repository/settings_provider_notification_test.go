package repository

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
)

// TestNotificationProviderRoundTrip 验证通知通道 provider 行的 list/get/upsert/delete
// 与信封解码：enabled、公开配置与密文各字段正确往返，类型判别不被其他 kind 干扰。
func TestNotificationProviderRoundTrip(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	row := &NotificationProviderRow{
		ProviderKey:      "notification.webhook",
		Enabled:          true,
		PublicConfig:     []byte(`{}`),
		SecretKeyVersion: 1,
		SecretNonce:      []byte("nonce-nonce-nonce"),
		SecretCiphertext: []byte("cipher"),
	}
	if err := repo.UpsertNotificationProvider(ctx, row); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := repo.GetNotificationProvider(ctx, "notification.webhook")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ProviderKey != "notification.webhook" || !got.Enabled {
		t.Fatalf("row mismatch: %+v", got)
	}
	if string(got.SecretCiphertext) != "cipher" || got.SecretKeyVersion != 1 {
		t.Fatalf("secret envelope mismatch: %+v", got)
	}

	rows, err := repo.ListNotificationProviders(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ProviderKey != "notification.webhook" {
		t.Fatalf("list = %+v, want one notification.webhook", rows)
	}

	if err := repo.DeleteNotificationProvider(ctx, "notification.webhook"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetNotificationProvider(ctx, "notification.webhook"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get after delete error = %v, want ErrNotFound", err)
	}
}

// TestNotificationProviderWrongKind 验证类型不匹配的 key 不被识别为通知通道。
// 已有 OAuth/OIDC 行（如 line、discord）不能被通知方法误读或覆盖。
func TestNotificationProviderWrongKind(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	// 写入一个 OAuth 行（OAuth 的 discord key）。
	authRow := &AuthProviderRow{
		ProviderKey:      "discord",
		Kind:             domain.ProviderKindOAuth,
		Enabled:          true,
		SecretKeyVersion: 1,
		SecretCiphertext: []byte("auth-cipher"),
	}
	if err := repo.UpsertAuthProvider(ctx, authRow); err != nil {
		t.Fatalf("upsert auth: %v", err)
	}
	// OAuth 行不能被通知方法读到。
	if _, err := repo.GetNotificationProvider(ctx, "discord"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get notification(discord) error = %v, want ErrNotFound", err)
	}
	rows, err := repo.ListNotificationProviders(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("notification list = %+v, want empty", rows)
	}
	// 删除通知方法不应删除 OAuth 行。
	if err := repo.DeleteNotificationProvider(ctx, "discord"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete notification(discord) error = %v, want ErrNotFound", err)
	}
	if _, err := repo.GetAuthProvider(ctx, "discord"); err != nil {
		t.Fatalf("auth discord should still exist: %v", err)
	}
}

// TestNotificationProviderUpsertOverwrites 验证同 key 再次 upsert 原地覆盖。
func TestNotificationProviderUpsertOverwrites(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	first := &NotificationProviderRow{
		ProviderKey:      "notification.telegram",
		Enabled:          false,
		SecretKeyVersion: 1,
		SecretCiphertext: []byte("old"),
	}
	if err := repo.UpsertNotificationProvider(ctx, first); err != nil {
		t.Fatalf("upsert first: %v", err)
	}
	second := &NotificationProviderRow{
		ProviderKey:      "notification.telegram",
		Enabled:          true,
		SecretKeyVersion: 1,
		SecretCiphertext: []byte("new"),
	}
	if err := repo.UpsertNotificationProvider(ctx, second); err != nil {
		t.Fatalf("upsert second: %v", err)
	}
	rows, err := repo.ListNotificationProviders(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].Enabled != true || string(rows[0].SecretCiphertext) != "new" {
		t.Fatalf("rows = %+v, want single overwritten row", rows)
	}
}

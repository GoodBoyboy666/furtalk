package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	crypto "furtalk/internal/platform/crypto"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

func newMigrationDB(t *testing.T) (*gorm.DB, *repository.SettingsRepo) {
	t.Helper()
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: filepath.Join(t.TempDir(), "provider-secrets.db")})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.DynamicSetting{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db, repository.NewSettingsRepo(db)
}

func encryptedParts(t *testing.T, key []byte, version byte, plaintext string) ([]byte, []byte) {
	t.Helper()
	envelope, err := crypto.Encrypt(key, version, []byte(plaintext))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return append([]byte(nil), envelope[1:13]...), append([]byte(nil), envelope[13:]...)
}

func seedProviderRows(t *testing.T, repo *repository.SettingsRepo, oldKey []byte) {
	t.Helper()
	ctx := context.Background()
	nonce, ciphertext := encryptedParts(t, oldKey, legacyEnvelopeVersion, "captcha secret")
	if err := repo.UpsertCaptchaProvider(ctx, &repository.CaptchaProviderRow{
		ProviderKey: "turnstile", PublicConfig: []byte("{\"provider\":\"turnstile\"}"),
		SecretKeyVersion: 1, SecretNonce: nonce, SecretCiphertext: ciphertext,
	}); err != nil {
		t.Fatalf("seed captcha: %v", err)
	}
	nonce, ciphertext = encryptedParts(t, oldKey, legacyEnvelopeVersion, "oauth secret")
	if err := repo.UpsertAuthProvider(ctx, &repository.AuthProviderRow{
		ProviderKey: "github", Kind: "oauth", Enabled: true,
		PublicConfig:     []byte("{\"client_id\":\"client\"}"),
		SecretKeyVersion: 1, SecretNonce: nonce, SecretCiphertext: ciphertext,
	}); err != nil {
		t.Fatalf("seed auth: %v", err)
	}
	nonce, ciphertext = encryptedParts(t, oldKey, legacyEnvelopeVersion, "spam secret")
	if err := repo.UpsertSpamProvider(ctx, &repository.SpamProviderRow{
		ProviderKey: "spam.akismet", Enabled: true,
		PublicConfig:     []byte("{\"action\":\"pending\"}"),
		SecretKeyVersion: 1, SecretNonce: nonce, SecretCiphertext: ciphertext,
	}); err != nil {
		t.Fatalf("seed spam: %v", err)
	}
	nonce, ciphertext = encryptedParts(t, oldKey, legacyEnvelopeVersion, "notification secret")
	if err := repo.UpsertNotificationProvider(ctx, &repository.NotificationProviderRow{
		ProviderKey: "notification.telegram", Enabled: true,
		PublicConfig:     []byte("{}"),
		SecretKeyVersion: 1, SecretNonce: nonce, SecretCiphertext: ciphertext,
	}); err != nil {
		t.Fatalf("seed notification: %v", err)
	}
	if err := repo.UpsertNotificationProvider(ctx, &repository.NotificationProviderRow{
		ProviderKey: "notification.empty", Enabled: false,
		PublicConfig: []byte("{}"),
	}); err != nil {
		t.Fatalf("seed empty notification: %v", err)
	}
}

func TestMigrateDryRunAndExecuteAllProviderKinds(t *testing.T) {
	db, repo := newMigrationDB(t)
	oldRaw := bytes.Repeat([]byte("o"), 32)
	newRaw := bytes.Repeat([]byte("n"), 48)
	seedProviderRows(t, repo, oldRaw)

	report, err := migrate(context.Background(), gormtx.NewRunner(db), repo, oldRaw, newRaw, false)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !report.DryRun {
		t.Fatal("dry-run report must be marked dry-run")
	}
	for _, kind := range []string{"captcha", "auth", "spam"} {
		if got := report.ByKind[kind].Converted; got != 1 {
			t.Fatalf("%s converted = %d, want 1", kind, got)
		}
	}
	if got := report.ByKind["notification"].Converted; got != 1 {
		t.Fatalf("notification converted = %d, want 1", got)
	}
	if got := report.ByKind["notification"].NoSecret; got != 1 {
		t.Fatalf("notification no_secret = %d, want 1", got)
	}
	rows, err := repo.ListCaptchaProviders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].SecretKeyVersion != 1 {
		t.Fatalf("dry-run persisted version %d, want 1", rows[0].SecretKeyVersion)
	}

	report, err = migrate(context.Background(), gormtx.NewRunner(db), repo, oldRaw, newRaw, true)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if report.DryRun {
		t.Fatal("execute report marked dry-run")
	}
	currentKey, err := crypto.DeriveProviderKey(newRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range mustAllRows(t, repo) {
		if len(row.ciphertext) == 0 {
			continue
		}
		if row.version != int(crypto.ProviderEnvelopeVersion) {
			t.Fatalf("%s version = %d, want 2", row.key, row.version)
		}
		if _, err := cryptoxDecrypt(currentKey, crypto.ProviderEnvelopeVersion, row.nonce, row.ciphertext); err != nil {
			t.Fatalf("%s does not decrypt with current key: %v", row.key, err)
		}
	}
}

func TestMigrateUsesExactWhitespaceKeyBytes(t *testing.T) {
	db, repo := newMigrationDB(t)
	oldRaw := []byte(" " + strings.Repeat("o", 30) + " ")
	newRaw := []byte(" " + strings.Repeat("n", 32) + " ")
	seedProviderRows(t, repo, oldRaw)

	report, err := migrate(context.Background(), gormtx.NewRunner(db), repo, oldRaw, newRaw, false)
	if err != nil {
		t.Fatalf("dry-run with whitespace keys: %v", err)
	}
	if !report.DryRun {
		t.Fatal("dry-run report must be marked dry-run")
	}
	rows, err := repo.ListCaptchaProviders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].SecretKeyVersion != int(legacyEnvelopeVersion) {
		t.Fatalf("dry-run persisted version %d, want %d", rows[0].SecretKeyVersion, legacyEnvelopeVersion)
	}

	if _, err := migrate(context.Background(), gormtx.NewRunner(db), repo, oldRaw, newRaw, true); err != nil {
		t.Fatalf("execute with whitespace keys: %v", err)
	}
	exactKey, err := crypto.DeriveProviderKey(newRaw)
	if err != nil {
		t.Fatal(err)
	}
	trimmedKey, err := crypto.DeriveProviderKey(bytes.TrimSpace(newRaw))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range mustAllRows(t, repo) {
		if len(row.ciphertext) == 0 {
			continue
		}
		if _, err := cryptoxDecrypt(exactKey, crypto.ProviderEnvelopeVersion, row.nonce, row.ciphertext); err != nil {
			t.Fatalf("%s does not decrypt with exact raw key: %v", row.key, err)
		}
		if _, err := cryptoxDecrypt(trimmedKey, crypto.ProviderEnvelopeVersion, row.nonce, row.ciphertext); err == nil {
			t.Fatalf("%s decrypted with trimmed key bytes", row.key)
		}
	}
}

func TestMigrateRollsBackOnUnsupportedVersion(t *testing.T) {
	db, repo := newMigrationDB(t)
	oldRaw := bytes.Repeat([]byte("o"), 32)
	newRaw := bytes.Repeat([]byte("n"), 32)
	seedProviderRows(t, repo, oldRaw)
	nonce, ciphertext := encryptedParts(t, oldRaw, legacyEnvelopeVersion, "bad version row")
	if err := repo.UpsertAuthProvider(context.Background(), &repository.AuthProviderRow{
		ProviderKey: "oidc-bad", Kind: "oidc", Enabled: true,
		SecretKeyVersion: 99, SecretNonce: nonce, SecretCiphertext: ciphertext,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := migrate(context.Background(), gormtx.NewRunner(db), repo, oldRaw, newRaw, true); err == nil {
		t.Fatal("unsupported version must fail")
	}
	rows, err := repo.ListCaptchaProviders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].SecretKeyVersion != 1 {
		t.Fatalf("rollback left converted captcha version %d", rows[0].SecretKeyVersion)
	}
}

func TestMigrateRejectsWrongLegacyKeyWithoutChangingRows(t *testing.T) {
	db, repo := newMigrationDB(t)
	oldRaw := bytes.Repeat([]byte("o"), 32)
	wrongRaw := bytes.Repeat([]byte("x"), 32)
	newRaw := bytes.Repeat([]byte("n"), 33)
	seedProviderRows(t, repo, oldRaw)
	if _, err := migrate(context.Background(), gormtx.NewRunner(db), repo, wrongRaw, newRaw, true); err == nil {
		t.Fatal("wrong legacy key must fail")
	}
	rows, err := repo.ListCaptchaProviders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].SecretKeyVersion != 1 {
		t.Fatalf("wrong-key attempt changed version to %d", rows[0].SecretKeyVersion)
	}
}

func TestParseFlagsRequiresEnvironmentKeysAndAllowsSafeFallback(t *testing.T) {
	t.Setenv("FURTALK_DATABASE_DIALECT", "sqlite")
	t.Setenv("FURTALK_DATABASE_PATH", ":memory:")
	t.Setenv("FURTALK_TOKENS_SECRET_KEY", strings.Repeat("n", 32))
	t.Setenv("FURTALK_TOKENS_LEGACY_SECRET_KEY", "")
	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatalf("safe fallback: %v", err)
	}
	if !bytes.Equal(cfg.newRawKey, cfg.legacyRawKey) {
		t.Fatal("exactly 32-byte new key should safely default as legacy key")
	}

	t.Setenv("FURTALK_TOKENS_SECRET_KEY", strings.Repeat("n", 48))
	if _, err := parseFlags(nil); err == nil {
		t.Fatal("48-byte new key without legacy key must fail")
	}
	if _, err := parseFlags([]string{"--legacy-key", strings.Repeat("x", 32)}); err == nil || strings.Contains(err.Error(), strings.Repeat("x", 32)) {
		t.Fatalf("plaintext key flag handling = %v", err)
	}

	t.Setenv("FURTALK_TOKENS_SECRET_KEY", strings.Repeat(" ", 32))
	if _, err := parseFlags(nil); err == nil {
		t.Fatal("whitespace-only new key must fail")
	}
}

func TestParseFlagsPreservesWhitespaceInRawKeys(t *testing.T) {
	tests := []struct {
		name      string
		newRaw    string
		legacyRaw string
	}{
		{name: "leading", newRaw: " " + strings.Repeat("n", 31), legacyRaw: " " + strings.Repeat("o", 31)},
		{name: "trailing", newRaw: strings.Repeat("n", 31) + " ", legacyRaw: strings.Repeat("o", 31) + " "},
		{name: "both", newRaw: " " + strings.Repeat("n", 32) + " ", legacyRaw: " " + strings.Repeat("o", 30) + " "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FURTALK_DATABASE_DIALECT", "sqlite")
			t.Setenv("FURTALK_DATABASE_PATH", ":memory:")
			t.Setenv("FURTALK_TOKENS_SECRET_KEY", tt.newRaw)
			t.Setenv("FURTALK_TOKENS_LEGACY_SECRET_KEY", tt.legacyRaw)
			cfg, err := parseFlags(nil)
			if err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			if !bytes.Equal(cfg.newRawKey, []byte(tt.newRaw)) {
				t.Fatalf("new key bytes = %q, want exact environment value", cfg.newRawKey)
			}
			if !bytes.Equal(cfg.legacyRawKey, []byte(tt.legacyRaw)) {
				t.Fatalf("legacy key bytes = %q, want exact environment value", cfg.legacyRawKey)
			}
		})
	}
}

func TestParseFlagsValidatesPostgresFieldsWithoutExposingPassword(t *testing.T) {
	password := " database-password "
	t.Setenv("FURTALK_DATABASE_DIALECT", "postgres")
	t.Setenv("FURTALK_DATABASE_HOST", "db.example.com")
	t.Setenv("FURTALK_DATABASE_PORT", "5432")
	t.Setenv("FURTALK_DATABASE_NAME", "furtalk")
	t.Setenv("FURTALK_DATABASE_USER", "furtalk")
	t.Setenv("FURTALK_DATABASE_PASSWORD", password)
	t.Setenv("FURTALK_DATABASE_SSL_MODE", "require")
	t.Setenv("FURTALK_TOKENS_SECRET_KEY", strings.Repeat("n", 32))
	t.Setenv("FURTALK_TOKENS_LEGACY_SECRET_KEY", strings.Repeat("o", 32))
	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatalf("valid postgres config: %v", err)
	}
	if cfg.databasePass != password {
		t.Fatalf("database password = %q, want exact environment value", cfg.databasePass)
	}
	t.Setenv("FURTALK_DATABASE_PORT", "0")
	if _, err := parseFlags(nil); err == nil || strings.Contains(err.Error(), password) || strings.Contains(err.Error(), strings.TrimSpace(password)) {
		t.Fatalf("invalid postgres config = %v", err)
	}
}

func TestPrintReportDoesNotContainSecrets(t *testing.T) {
	secret := "provider-secret-value"
	var out bytes.Buffer
	err := printReport(&out, Report{DryRun: true, ByKind: map[string]KindReport{
		"captcha": {Scanned: 1, Converted: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatal("report leaked secret")
	}
}

func TestMigrateHonorsCancellation(t *testing.T) {
	db, repo := newMigrationDB(t)
	oldRaw := bytes.Repeat([]byte("o"), 32)
	seedProviderRows(t, repo, oldRaw)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := migrate(ctx, gormtx.NewRunner(db), repo, oldRaw, oldRaw, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v, want context.Canceled", err)
	}
}

type allRowsRecord struct {
	key        string
	version    int
	nonce      []byte
	ciphertext []byte
}

func mustAllRows(t *testing.T, repo *repository.SettingsRepo) []allRowsRecord {
	t.Helper()
	ctx := context.Background()
	var out []allRowsRecord
	captchas, err := repo.ListCaptchaProviders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range captchas {
		out = append(out, allRowsRecord{row.ProviderKey, row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext})
	}
	auths, err := repo.ListAuthProviders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range auths {
		out = append(out, allRowsRecord{row.ProviderKey, row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext})
	}
	spams, err := repo.ListSpamProviders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range spams {
		out = append(out, allRowsRecord{row.ProviderKey, row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext})
	}
	notifications, err := repo.ListNotificationProviders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range notifications {
		out = append(out, allRowsRecord{row.ProviderKey, row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext})
	}
	return out
}

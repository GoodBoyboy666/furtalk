package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/platform/database"
	"furtalk/internal/platform/logging"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"gorm.io/gorm"
)

// TestNewServiceLogsSetupToken 验证未初始化实例首次启动日志包含 setup_token 明文
// 与 UTC 过期时间，且 token 与 SetupToken() 返回值一致。
func TestNewServiceLogsSetupToken(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	svc := newServiceWithDB(t, &buf)
	if svc == nil {
		t.Fatal("new service with uninitialized db must succeed")
	}
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode startup log: %v\nraw: %s", err, buf.String())
	}
	token, _ := record["setup_token"].(string)
	if token == "" {
		t.Fatal("startup log must include plaintext setup_token")
	}
	if token != svc.SetupToken() {
		t.Fatalf("logged setup_token %q differs from SetupToken() %q", token, svc.SetupToken())
	}
	expires, _ := record["expires_at"].(string)
	if _, err := time.Parse(time.RFC3339, expires); err != nil {
		t.Fatalf("expires_at %q is not RFC3339: %v", expires, err)
	}
}

// TestNewServiceSilentAfterInitialized 验证已初始化实例启动不再输出明文 token。
func TestNewServiceSilentAfterInitialized(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "bootstrap-initialized.db")
	db := newMigratedDB(t, dsn)
	defer closeDB(t, db)

	repo := repository.NewBootstrapRepo(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := repo.Create(context.Background(), now, 1); err != nil {
		t.Fatalf("create bootstrap state: %v", err)
	}

	var buf bytes.Buffer
	svc, err := NewService(nil, nil, repo, logging.NewWithFormat(&buf, logging.FormatJSON))
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("initialized instance must not log a setup token, got: %s", buf.String())
	}
	if raw := svc.SetupToken(); raw != "" {
		t.Fatalf("initialized instance SetupToken() = %q, want empty", raw)
	}
}

// TestNewServiceSilentOnReadError 验证初始化状态读取失败时不输出明文 token。
func TestNewServiceSilentOnReadError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	svc, err := NewService(nil, nil, nil, logging.NewWithFormat(&buf, logging.FormatJSON))
	if err != nil {
		t.Fatal(err)
	}
	if svc == nil {
		t.Fatal("service must still be constructed on read error")
	}
	if bytes.Contains(buf.Bytes(), []byte("setup_token")) {
		t.Fatalf("read-error path must not emit setup_token, got: %s", buf.String())
	}
}

// newServiceWithDB 用未初始化的临时 SQLite 库构建 bootstrap 服务。
func newServiceWithDB(t *testing.T, buf *bytes.Buffer) *Service {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "bootstrap-fresh.db")
	db := newMigratedDB(t, dsn)
	defer closeDB(t, db)
	svc, err := NewService(nil, nil, repository.NewBootstrapRepo(db), logging.NewWithFormat(buf, logging.FormatJSON))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// newMigratedDB 建连并 AutoMigrate bootstrap 所需表。
func newMigratedDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	if err := database.AutoMigrate(db, &model.BootstrapState{}, &model.User{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// closeDB 关闭数据库连接。
func closeDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// TestSetupTokenPlainStringIsRedacted 验证普通 setup_token 字符串属性经生产
// logging handler 输出时被脱敏，只有 SetupToken helper 构造的属性放行。
func TestSetupTokenPlainStringIsRedacted(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)
	logger.Info("bootstrap", "setup_token", "should-not-leak")
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["setup_token"] != "[REDACTED]" {
		t.Fatalf("setup_token = %#v, want [REDACTED]", record["setup_token"])
	}
}

// TestSetupTokenHiddenAfterConsume 验证 token 被一次性消费后不再输出明文。
func TestSetupTokenHiddenAfterConsume(t *testing.T) {
	t.Parallel()

	token, err := newSetupToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, ok := token.plaintext(now)
	if !ok || raw == "" {
		t.Fatal("fresh token must be exposed as plaintext")
	}
	if !token.verify(raw, now) {
		t.Fatal("fresh token must verify")
	}
	if _, ok := token.plaintext(now); ok {
		t.Fatal("consumed token must not be exposed as plaintext")
	}
}

// TestSetupTokenHiddenAfterExpiry 验证过期 token 不再输出明文。
func TestSetupTokenHiddenAfterExpiry(t *testing.T) {
	t.Parallel()

	token, err := newSetupToken(-time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := token.plaintext(time.Now()); ok {
		t.Fatal("expired token must not be exposed as plaintext")
	}
}

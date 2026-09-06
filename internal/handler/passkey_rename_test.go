package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// passkeyRenameStore 是改名端点用的缓存替身。
type passkeyRenameStore struct{}

func (passkeyRenameStore) Get(ctx context.Context, key string, out any) error {
	return cache.ErrNotFound
}
func (passkeyRenameStore) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return nil
}
func (passkeyRenameStore) Delete(ctx context.Context, key string) error { return nil }
func (passkeyRenameStore) AtomicConsume(ctx context.Context, key string) (string, error) {
	return "", cache.ErrNotFound
}
func (passkeyRenameStore) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	return nil
}

// newPasskeyRenameHandlerEnv 装配带真实 SQLite 的 /me 改名路由环境，返回 (router, svc, db)。
func newPasskeyRenameHandlerEnv(t *testing.T) (*gin.Engine, *identity.Service, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "handler-passkey-rename-test.db")
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
	svc := identity.NewService(identity.Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         repository.NewUserRepo(db),
		Passkeys:      repository.NewPasskeyRepo(db),
		Cache:         passkeyRenameStore{},
		Policy:        mePasswordPolicy{},
		CaptchaPolicy: emailCodePolicy{},
		Signer:        identity.NewSigner(identity.SignerConfig{Issuer: "test", Key: []byte("test-key"), Lifetime: time.Hour}),
	})
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	api := router.Group("/api/v1", userPrincipal(1))
	RegisterMeWithAdmission(api, svc, svc, nil, middleware.CSRFProtection())
	return router, svc, db
}

// doPasskeyRenamePatch 发送带 CSRF 的 PATCH /me/passkeys/{id} 请求。
func doPasskeyRenamePatch(t *testing.T, router *gin.Engine, id int64, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/me/passkeys/"+strconv.FormatInt(id, 10), strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrf})
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	router.ServeHTTP(rec, request)
	return rec
}

// TestPasskeyRenameHTTP 验证 PATCH 改名成功返回 204。
func TestPasskeyRenameHTTP(t *testing.T) {
	router, svc, db := newPasskeyRenameHandlerEnv(t)
	userID := seedHandlerPasskeyUser(t, svc, db, "旧名称")
	passkeyID := seedHandlerPasskeyCred(t, db, userID, "旧名称")

	rec := doPasskeyRenamePatch(t, router, passkeyID, `{"name":"新名称"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	row, err := repository.NewPasskeyRepo(db).GetByUserIDAndID(context.Background(), userID, passkeyID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Name != "新名称" {
		t.Fatalf("name = %q, want 新名称", row.Name)
	}
}

// TestPasskeyRenameBlankRejected 验证空白名称返回 422 且原值不变。
func TestPasskeyRenameBlankRejected(t *testing.T) {
	router, svc, db := newPasskeyRenameHandlerEnv(t)
	userID := seedHandlerPasskeyUser(t, svc, db, "旧名称")
	passkeyID := seedHandlerPasskeyCred(t, db, userID, "旧名称")

	rec := doPasskeyRenamePatch(t, router, passkeyID, `{"name":"   "}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	row, err := repository.NewPasskeyRepo(db).GetByUserIDAndID(context.Background(), userID, passkeyID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Name != "旧名称" {
		t.Fatalf("name changed to %q on invalid input", row.Name)
	}
}

// seedHandlerPasskeyUser 创建一个用户并返回其 ID。
func seedHandlerPasskeyUser(t *testing.T, svc *identity.Service, db *gorm.DB, name string) int64 {
	t.Helper()
	user := &domain.User{
		Email: "passkey@example.com", EmailNormalized: "passkey@example.com",
		Nickname: "passkey", Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	if err := repository.NewUserRepo(db).Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	_ = name
	return user.ID
}

// seedHandlerPasskeyCred 为指定用户插入一条命名 passkey 并返回其 ID。
func seedHandlerPasskeyCred(t *testing.T, db *gorm.DB, userID int64, name string) int64 {
	t.Helper()
	row := &domain.PasskeyCredential{
		UserID: userID, CredentialID: "cred-" + name, PublicKey: []byte("pk"),
		Name: name, CreatedAt: time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC),
	}
	if err := repository.NewPasskeyRepo(db).Create(context.Background(), row); err != nil {
		t.Fatalf("create passkey: %v", err)
	}
	rows, err := repository.NewPasskeyRepo(db).ListByUserID(context.Background(), userID)
	if err != nil {
		t.Fatalf("list passkeys: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("passkey count = %d, want 1", len(rows))
	}
	return rows[0].ID
}

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/value"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

// captureResetMailer 记录投递的邮件消息。
type captureResetMailer struct {
	messages []mailer.Message
}

func (m *captureResetMailer) Send(ctx context.Context, msg mailer.Message) error {
	m.messages = append(m.messages, msg)
	return nil
}

// newPasswordResetFixture 装配真实内存缓存与 SQLite 用户仓储的重置端点。
func newPasswordResetFixture(t *testing.T, policy map[string]bool, verifier identity.CaptchaVerifier) (*gin.Engine, *cache.Memory, *repository.UserRepo, *captureResetMailer) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "handler-password-reset-test.db")
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
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	users := repository.NewUserRepo(db)
	mailer := &captureResetMailer{}
	svc := identity.NewService(identity.Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         users,
		Cache:         store,
		Policy:        authPolicyReader{},
		CaptchaPolicy: emailCodePolicy{policy},
		Captcha:       verifier,
		Mailer:        mailer,
		Templates:     emailCodeRenderer{},
	})
	translator, err := NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	RegisterAuthWithAdmission(router.Group("/api/v1"), svc, nil)
	return router, store, users, mailer
}

func postResetJSON(t *testing.T, router http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestPasswordResetCodeKnownAndUnknownAreIdentical(t *testing.T) {
	router, store, users, mailer := newPasswordResetFixture(t, map[string]bool{}, nil)
	ctx := context.Background()
	_, normalized, err := value.NormalizeEmail("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := users.Create(ctx, &domain.User{
		Email: normalized, EmailNormalized: normalized, Nickname: "t",
		Role: domain.RoleUser, Status: domain.UserStatusActive, EmailVerifiedAt: &now,
	}); err != nil {
		t.Fatal(err)
	}

	known := postResetJSON(t, router, "/api/v1/auth/password/reset-codes", `{"email":"user@example.com"}`)
	if known.Code != http.StatusNoContent {
		t.Fatalf("known email status = %d, want 204", known.Code)
	}
	unknown := postResetJSON(t, router, "/api/v1/auth/password/reset-codes", `{"email":"nobody@example.com"}`)
	if unknown.Code != http.StatusNoContent {
		t.Fatalf("unknown email status = %d, want 204", unknown.Code)
	}
	if len(mailer.messages) != 1 {
		t.Fatalf("mail count = %d, want 1 (unknown email must not send)", len(mailer.messages))
	}
	var record cache.EmailCodeRecord
	if err := store.Get(ctx, "email-code:password_reset:nobody@example.com", &record); err == nil {
		t.Fatal("unknown email must not leave a reset record")
	}
}

func TestPasswordResetCodeCaptchaHTTPMatrix(t *testing.T) {
	cases := []struct {
		name       string
		policy     map[string]bool
		verifier   identity.CaptchaVerifier
		body       string
		wantStatus int
	}{
		{name: "disabled accepts", policy: map[string]bool{}, verifier: nil, body: `{"email":"user@example.com"}`, wantStatus: http.StatusNoContent},
		{name: "required", policy: map[string]bool{"password_reset": true}, verifier: &emailCodeVerifier{}, body: `{"email":"user@example.com"}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "failed", policy: map[string]bool{"password_reset": true}, verifier: &emailCodeVerifier{err: domain.ErrCaptchaFailed}, body: `{"email":"user@example.com","captcha_token":"tok"}`, wantStatus: http.StatusForbidden},
		{name: "unavailable", policy: map[string]bool{"password_reset": true}, verifier: &emailCodeVerifier{err: domain.ErrCaptchaUnavailable}, body: `{"email":"user@example.com","captcha_token":"tok"}`, wantStatus: http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _, _, mailer := newPasswordResetFixture(t, tc.policy, tc.verifier)
			rec := postResetJSON(t, router, "/api/v1/auth/password/reset-codes", tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.policy["password_reset"] && len(mailer.messages) != 0 {
				t.Fatalf("CAPTCHA failure sent %d mails, want 0", len(mailer.messages))
			}
		})
	}
}

func TestPasswordResetConfirmSuccessWithoutSessionCookie(t *testing.T) {
	router, store, users, _ := newPasswordResetFixture(t, map[string]bool{}, nil)
	ctx := context.Background()
	_, normalized, err := value.NormalizeEmail("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Create(ctx, &domain.User{
		Email: normalized, EmailNormalized: normalized, Nickname: "t",
		Role: domain.RoleUser, Status: domain.UserStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(ctx, "email-code:password_reset:"+normalized, cache.EmailCodeRecord{
		Hash: cryptox.SHA256Hex([]byte("123456")), Attempts: 0,
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}

	rec := postResetJSON(t, router, "/api/v1/auth/password/reset",
		`{"email":"user@example.com","code":"123456","new_password":"brand-new-password"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == middleware.FirstPartyCookieName {
			t.Fatalf("reset must not write a session cookie, found %s", cookie.Name)
		}
	}
	var record cache.EmailCodeRecord
	if err := store.Get(ctx, "email-code:password_reset:"+normalized, &record); err == nil {
		t.Fatal("code must be consumed after successful reset")
	}
	user, err := users.FindByEmailNormalized(ctx, normalized)
	if err != nil {
		t.Fatal(err)
	}
	has, err := users.HasPassword(ctx, user.ID)
	if err != nil || !has {
		t.Fatalf("password must be set after reset, has=%v err=%v", has, err)
	}
}

func TestPasswordResetConfirmWrongCodeIs401(t *testing.T) {
	router, store, users, _ := newPasswordResetFixture(t, map[string]bool{}, nil)
	ctx := context.Background()
	_, normalized, err := value.NormalizeEmail("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Create(ctx, &domain.User{
		Email: normalized, EmailNormalized: normalized, Nickname: "t",
		Role: domain.RoleUser, Status: domain.UserStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(ctx, "email-code:password_reset:"+normalized, cache.EmailCodeRecord{
		Hash: cryptox.SHA256Hex([]byte("123456")), Attempts: 0,
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}

	rec := postResetJSON(t, router, "/api/v1/auth/password/reset",
		`{"email":"user@example.com","code":"000000","new_password":"brand-new-password"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status = %d, want 401", rec.Code)
	}
	user, _ := users.FindByEmailNormalized(ctx, normalized)
	has, err := users.HasPassword(ctx, user.ID)
	if err != nil || has {
		t.Fatalf("wrong code must not set a password, has=%v err=%v", has, err)
	}
}

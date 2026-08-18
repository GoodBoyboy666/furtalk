package identity

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newCaptchaLoginDB 打开临时 SQLite 数据库并迁移身份相关表。
func newCaptchaLoginDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "identity-captcha-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.Site{}, &model.Thread{}, &model.Comment{}, &model.ExternalIdentity{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// captchaLoginService 装配使用真实仓储与内存缓存的登录服务。
func captchaLoginService(t *testing.T, db *gorm.DB, policy map[string]bool, verifier CaptchaVerifier) *Service {
	t.Helper()
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{
		TxRunner:       gormtx.NewRunner(db),
		Users:          repository.NewUserRepo(db),
		Cache:          store,
		Policy:         loginTestPolicy{},
		CaptchaPolicy:  staticCaptchaPolicy{policy},
		Captcha:        verifier,
		Signer:         loginTestSigner{lifetime: 7 * 24 * time.Hour},
		PasskeyAdapter: nil,
		Templates:      stubTemplateRenderer{},
	})
	return svc
}

// insertVerifiedUser 直接插入一个已验证的活跃用户。
func insertVerifiedUser(t *testing.T, db *gorm.DB, email string) *domain.User {
	t.Helper()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	user := &domain.User{
		Email:           email,
		EmailNormalized: email,
		Nickname:        "tester",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := repository.NewUserRepo(db).Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

// seedEmailCode 直接写入一条有效的邮箱验证码记录。
func seedEmailCode(t *testing.T, svc *Service, email, code string) {
	t.Helper()
	hash := cryptox.SHA256Hex([]byte(code))
	record := EmailCodeRecord{
		Hash:      hash,
		Attempts:  0,
		ExpiresAt: svc.now().UTC().Add(svc.codeTTL),
	}
	if err := svc.emailCodes.SetEmailCode(context.Background(), emailCodePurpose, email, record, svc.codeTTL); err != nil {
		t.Fatalf("seed email code: %v", err)
	}
}

// seedPassword 直接为用户写入密码状态。
func seedPassword(t *testing.T, db *gorm.DB, userID int64, password string) {
	t.Helper()
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := repository.NewUserRepo(db).SetPassword(context.Background(), userID, hash, time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("set password: %v", err)
	}
}

// emailCodeStillValid 报告验证码是否仍存在于缓存。
func emailCodeStillValid(t *testing.T, svc *Service, email string) bool {
	t.Helper()
	_, err := svc.emailCodes.GetEmailCode(context.Background(), emailCodePurpose, email)
	return err == nil
}

func TestLoginWithEmailCodeCaptchaMatrix(t *testing.T) {
	tests := []struct {
		name       string
		policy     map[string]bool
		verifier   CaptchaVerifier
		token      string
		wantErr    error
		wantAction string
	}{
		{
			name:     "policy off stays compatible",
			policy:   map[string]bool{},
			verifier: &recordingCaptchaVerifier{},
			token:    "",
			wantErr:  nil,
		},
		{
			name:     "policy on blank token requires captcha",
			policy:   map[string]bool{EmailCodeLoginAction: true},
			verifier: &recordingCaptchaVerifier{},
			token:    "",
			wantErr:  domain.ErrCaptchaRequired,
		},
		{
			name:     "verifier failure maps to ErrCaptchaFailed",
			policy:   map[string]bool{EmailCodeLoginAction: true},
			verifier: &recordingCaptchaVerifier{err: domain.ErrCaptchaFailed},
			token:    "token",
			wantErr:  domain.ErrCaptchaFailed,
		},
		{
			name:     "provider unavailable maps to ErrCaptchaUnavailable",
			policy:   map[string]bool{EmailCodeLoginAction: true},
			verifier: &recordingCaptchaVerifier{err: domain.ErrCaptchaUnavailable},
			token:    "token",
			wantErr:  domain.ErrCaptchaUnavailable,
		},
		{
			name:     "nil verifier fails closed",
			policy:   map[string]bool{EmailCodeLoginAction: true},
			verifier: nil,
			token:    "token",
			wantErr:  domain.ErrCaptchaUnavailable,
		},
		{
			name:       "verifier success proceeds to login",
			policy:     map[string]bool{EmailCodeLoginAction: true},
			verifier:   &recordingCaptchaVerifier{},
			token:      "token",
			wantErr:    nil,
			wantAction: EmailCodeLoginAction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newCaptchaLoginDB(t)
			verifier := tt.verifier
			svc := captchaLoginService(t, db, tt.policy, verifier)
			insertVerifiedUser(t, db, "user@example.com")
			seedEmailCode(t, svc, "user@example.com", "123456")

			session, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{
				Email:        "user@example.com",
				Code:         "123456",
				CaptchaToken: tt.token,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && session == nil {
				t.Fatal("session = nil, want a logged-in session")
			}
			if tt.wantAction != "" {
				rec, ok := verifier.(*recordingCaptchaVerifier)
				if !ok {
					t.Fatal("verifier is not recordingCaptchaVerifier")
				}
				if rec.calls != 1 {
					t.Fatalf("verifier calls = %d, want 1", rec.calls)
				}
				if rec.action != tt.wantAction {
					t.Fatalf("verifier action = %q, want %q", rec.action, tt.wantAction)
				}
				if rec.token != tt.token {
					t.Fatalf("verifier token = %q, want %q", rec.token, tt.token)
				}
			}
			if tt.wantErr == nil {
				if emailCodeStillValid(t, svc, "user@example.com") {
					t.Fatal("email code should have been consumed on successful login")
				}
			} else if tt.wantErr == domain.ErrCaptchaRequired || tt.wantErr == domain.ErrCaptchaFailed || tt.wantErr == domain.ErrCaptchaUnavailable {
				if !emailCodeStillValid(t, svc, "user@example.com") {
					t.Fatal("email code must not be consumed when CAPTCHA fails")
				}
			}
		})
	}
}

// TestLoginWithEmailCodeCaptchaFailureDoesNotConsumeCode 单独证明 CAPTCHA 失败时
// 验证码缓存不被读取或消费：即使验证码有效，错误也必须在读取前返回。
func TestLoginWithEmailCodeCaptchaFailureDoesNotConsumeCode(t *testing.T) {
	db := newCaptchaLoginDB(t)
	verifier := &recordingCaptchaVerifier{err: domain.ErrCaptchaFailed}
	svc := captchaLoginService(t, db, map[string]bool{EmailCodeLoginAction: true}, verifier)
	insertVerifiedUser(t, db, "user@example.com")
	seedEmailCode(t, svc, "user@example.com", "123456")

	if _, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{
		Email:        "user@example.com",
		Code:         "123456",
		CaptchaToken: "token",
	}); !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("err = %v, want ErrCaptchaFailed", err)
	}
	if !emailCodeStillValid(t, svc, "user@example.com") {
		t.Fatal("email code must not be consumed when CAPTCHA fails")
	}
}

func TestLoginWithPasswordCaptchaMatrix(t *testing.T) {
	tests := []struct {
		name       string
		policy     map[string]bool
		verifier   CaptchaVerifier
		token      string
		wantErr    error
		wantAction string
	}{
		{
			name:     "policy off stays compatible",
			policy:   map[string]bool{},
			verifier: &recordingCaptchaVerifier{},
			token:    "",
			wantErr:  nil,
		},
		{
			name:     "policy on blank token requires captcha",
			policy:   map[string]bool{PasswordLoginAction: true},
			verifier: &recordingCaptchaVerifier{},
			token:    "",
			wantErr:  domain.ErrCaptchaRequired,
		},
		{
			name:     "verifier failure maps to ErrCaptchaFailed",
			policy:   map[string]bool{PasswordLoginAction: true},
			verifier: &recordingCaptchaVerifier{err: domain.ErrCaptchaFailed},
			token:    "token",
			wantErr:  domain.ErrCaptchaFailed,
		},
		{
			name:     "provider unavailable maps to ErrCaptchaUnavailable",
			policy:   map[string]bool{PasswordLoginAction: true},
			verifier: &recordingCaptchaVerifier{err: domain.ErrCaptchaUnavailable},
			token:    "token",
			wantErr:  domain.ErrCaptchaUnavailable,
		},
		{
			name:     "nil verifier fails closed",
			policy:   map[string]bool{PasswordLoginAction: true},
			verifier: nil,
			token:    "token",
			wantErr:  domain.ErrCaptchaUnavailable,
		},
		{
			name:       "verifier success proceeds to login",
			policy:     map[string]bool{PasswordLoginAction: true},
			verifier:   &recordingCaptchaVerifier{},
			token:      "token",
			wantErr:    nil,
			wantAction: PasswordLoginAction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newCaptchaLoginDB(t)
			verifier := tt.verifier
			svc := captchaLoginService(t, db, tt.policy, verifier)
			user := insertVerifiedUser(t, db, "user@example.com")
			seedPassword(t, db, user.ID, "correct-horse-1")

			session, err := svc.LoginWithPassword(context.Background(), "user@example.com", "correct-horse-1", tt.token)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && session == nil {
				t.Fatal("session = nil, want a logged-in session")
			}
			if tt.wantAction != "" {
				rec, ok := verifier.(*recordingCaptchaVerifier)
				if !ok {
					t.Fatal("verifier is not recordingCaptchaVerifier")
				}
				if rec.calls != 1 {
					t.Fatalf("verifier calls = %d, want 1", rec.calls)
				}
				if rec.action != tt.wantAction {
					t.Fatalf("verifier action = %q, want %q", rec.action, tt.wantAction)
				}
				if rec.token != tt.token {
					t.Fatalf("verifier token = %q, want %q", rec.token, tt.token)
				}
			}
		})
	}
}

// TestLoginWithPasswordCaptchaFailureSkipsArgon2id 证明 CAPTCHA 失败时在
// 用户/凭证查询与 Argon2id 校验之前返回，不执行昂贵哈希路径。
func TestLoginWithPasswordCaptchaFailureSkipsArgon2id(t *testing.T) {
	db := newCaptchaLoginDB(t)
	verifier := &recordingCaptchaVerifier{err: domain.ErrCaptchaFailed}
	svc := captchaLoginService(t, db, map[string]bool{PasswordLoginAction: true}, verifier)

	if _, err := svc.LoginWithPassword(context.Background(), "unknown@example.com", "anything", "token"); !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("err = %v, want ErrCaptchaFailed", err)
	}
}

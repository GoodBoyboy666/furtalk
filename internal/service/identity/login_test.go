package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
)

type loginTestPolicy struct{}

func (loginTestPolicy) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}

func (loginTestPolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, nil, "https://www.gravatar.com/avatar", nil
}

type loginTestSigner struct {
	lifetime time.Duration
}

func (s loginTestSigner) SignFirstParty(int64, int64) (string, error) { return "session-token", nil }
func (s loginTestSigner) Lifetime() time.Duration                     { return s.lifetime }

func TestCompleteLoginGeneratesFreshCSRFToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	service := &Service{
		policy: loginTestPolicy{},
		signer: loginTestSigner{lifetime: 7 * 24 * time.Hour},
		now:    func() time.Time { return now },
	}
	user := &domain.User{ID: 42, Role: domain.RoleUser, Status: domain.UserStatusActive}

	first, err := service.completeLogin(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.completeLogin(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}

	if first.CSRFToken == "" || second.CSRFToken == "" {
		t.Fatal("completeLogin returned an empty CSRF token")
	}
	if first.CSRFToken == second.CSRFToken {
		t.Fatal("completeLogin reused the CSRF token")
	}
	if len(first.CSRFToken) != 43 || len(second.CSRFToken) != 43 {
		t.Fatalf("CSRF token lengths = %d/%d, want base64url encoding of 32 bytes", len(first.CSRFToken), len(second.CSRFToken))
	}
	wantExpiry := now.Add(7 * 24 * time.Hour)
	if !first.ExpiresAt.Equal(wantExpiry) || !second.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("session expiries = %v/%v, want %v", first.ExpiresAt, second.ExpiresAt, wantExpiry)
	}
}

// TestCompleteLoginDisabledAccountRejected 验证停用账号在凭证校验通过后返回
// 独立的 ErrDisabled，而不是通用的 ErrInvalidCredentials。
func TestCompleteLoginDisabledAccountRejected(t *testing.T) {
	t.Parallel()

	service := &Service{
		policy: loginTestPolicy{},
		signer: loginTestSigner{lifetime: 7 * 24 * time.Hour},
		now:    func() time.Time { return time.Now() },
	}
	user := &domain.User{ID: 42, Role: domain.RoleUser, Status: domain.UserStatusDisabled}

	if _, err := service.completeLogin(context.Background(), user); !errors.Is(err, domain.ErrDisabled) {
		t.Fatalf("err = %v, want domain.ErrDisabled", err)
	}
}

// TestLoginWithEmailCodeDisabledAccountRejected 验证停用账号通过邮箱验证码登录时
// 消费验证码后返回 ErrDisabled，验证码正常消费、不签发会话。
func TestLoginWithEmailCodeDisabledAccountRejected(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := captchaLoginService(t, db, map[string]bool{}, &recordingCaptchaVerifier{})
	user := &domain.User{
		Email: "disabled@example.com", EmailNormalized: "disabled@example.com",
		Nickname: "disabled", Role: domain.RoleUser, Status: domain.UserStatusDisabled,
	}
	if err := repository.NewUserRepo(db).Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	seedEmailCode(t, svc, "disabled@example.com", "123456")

	if _, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{Email: "disabled@example.com", Code: "123456"}); !errors.Is(err, domain.ErrDisabled) {
		t.Fatalf("err = %v, want domain.ErrDisabled", err)
	}
	if emailCodeStillValid(t, svc, "disabled@example.com") {
		t.Fatal("email code must be consumed after successful credential verification")
	}
}

// TestLoginWithPasswordDisabledAccountRejected 验证停用账号用正确密码登录返回 ErrDisabled。
func TestLoginWithPasswordDisabledAccountRejected(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := captchaLoginService(t, db, map[string]bool{}, &recordingCaptchaVerifier{})
	user := &domain.User{
		Email: "disabled@example.com", EmailNormalized: "disabled@example.com",
		Nickname: "disabled", Role: domain.RoleUser, Status: domain.UserStatusDisabled,
	}
	if err := repository.NewUserRepo(db).Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	seedPassword(t, db, user.ID, "correct-horse-1")

	if _, err := svc.LoginWithPassword(context.Background(), "disabled@example.com", "correct-horse-1", ""); !errors.Is(err, domain.ErrDisabled) {
		t.Fatalf("err = %v, want domain.ErrDisabled", err)
	}
}

// TestLoginWithPasswordUnknownAccountStaysGeneric 验证未知账号仍保持通用 401 错误。
func TestLoginWithPasswordUnknownAccountStaysGeneric(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := captchaLoginService(t, db, map[string]bool{}, &recordingCaptchaVerifier{})

	if _, err := svc.LoginWithPassword(context.Background(), "unknown@example.com", "whatever", ""); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want domain.ErrInvalidCredentials", err)
	}
}

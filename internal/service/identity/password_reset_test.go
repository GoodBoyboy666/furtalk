package identity

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/onetime"
	"furtalk/internal/platform/value"
	"furtalk/internal/repository"
)

// capturingMailer 记录投递的消息并支持注入失败。
type capturingMailer struct {
	messages []mailer.Message
	err      error
}

func (m *capturingMailer) Send(ctx context.Context, msg mailer.Message) error {
	if m.err != nil {
		return m.err
	}
	m.messages = append(m.messages, msg)
	return nil
}

// newResetTestService 装配使用真实内存缓存与 SQLite 用户仓储的最小服务。
func newResetTestService(t *testing.T, store cache.Store, policy map[string]bool, verifier CaptchaVerifier, mailer mailer.Mailer) *Service {
	t.Helper()
	db := newEmailCodeTestDB(t)
	return NewService(Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         repository.NewUserRepo(db),
		Cache:         store,
		Policy:        loginTestPolicy{},
		CaptchaPolicy: staticCaptchaPolicy{policy: policy},
		Captcha:       verifier,
		Mailer:        mailer,
		Templates:     stubTemplateRenderer{},
	})
}

// seedResetUser 直接写入一个邮箱用户并返回规范化邮箱。
func seedResetUser(t *testing.T, svc *Service, email string, verifiedAt *time.Time) string {
	t.Helper()
	_, normalized, err := value.NormalizeEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	user := &domain.User{
		Email:           normalized,
		EmailNormalized: normalized,
		Nickname:        "tester",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: verifiedAt,
	}
	if err := svc.users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return normalized
}

// seedResetCode 直接向缓存写入一条密码重置验证码记录。
func seedResetCode(t *testing.T, ctx context.Context, store cache.Store, email, code string) {
	t.Helper()
	oneTime, err := onetime.New(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := oneTime.Issue(ctx, "email-code:"+passwordResetPurpose+":"+email, cryptox.SHA256Hex([]byte(code)), 10*time.Minute); err != nil {
		t.Fatal(err)
	}
}

func resetKeyPresent(store cache.Store, key string) bool {
	var raw json.RawMessage
	return store.Get(context.Background(), key, &raw) == nil
}

func TestRequestPasswordResetUnknownEmailIsGeneric(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	mailer := &capturingMailer{}
	svc := newResetTestService(t, store, map[string]bool{}, nil, mailer)

	err := svc.RequestPasswordReset(context.Background(), "nobody@example.com", "")
	if err != nil {
		t.Fatalf("unknown email must succeed generically, got %v", err)
	}
	if len(mailer.messages) != 0 {
		t.Fatalf("unknown email sent %d mails, want 0", len(mailer.messages))
	}
	if resetKeyPresent(store, "email-code:"+passwordResetPurpose+":nobody@example.com") {
		t.Fatal("unknown email left a reset record")
	}
	if _, err := svc.users.FindByEmailNormalized(context.Background(), "nobody@example.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown email created a user or errored unexpectedly: %v", err)
	}
}

func TestRequestPasswordResetKnownEmailSendsCode(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	mailer := &capturingMailer{}
	svc := newResetTestService(t, store, map[string]bool{}, nil, mailer)
	email := seedResetUser(t, svc, "user@example.com", nil)

	if err := svc.RequestPasswordReset(context.Background(), email, ""); err != nil {
		t.Fatalf("request reset: %v", err)
	}
	if len(mailer.messages) != 1 || mailer.messages[0].To != email {
		t.Fatalf("mail to = %v, want [%s]", mailer.messages, email)
	}
	if !resetKeyPresent(store, "email-code:"+passwordResetPurpose+":"+email) {
		t.Fatal("reset record missing")
	}
}

func TestRequestPasswordResetReissueReplacesOldCode(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	mailer := &capturingMailer{}
	svc := newResetTestService(t, store, map[string]bool{}, nil, mailer)
	email := seedResetUser(t, svc, "user@example.com", nil)

	if err := svc.RequestPasswordReset(context.Background(), email, ""); err != nil {
		t.Fatal(err)
	}
	first := mailer.messages[0]
	if err := svc.RequestPasswordReset(context.Background(), email, ""); err != nil {
		t.Fatal(err)
	}
	if len(mailer.messages) != 2 {
		t.Fatalf("mail count = %d, want 2", len(mailer.messages))
	}
	if first.TextBody == mailer.messages[1].TextBody {
		t.Fatal("reissued code must differ from the previous one")
	}
}

func TestRequestPasswordResetCaptchaBeforeLookup(t *testing.T) {
	cases := []struct {
		name     string
		verifier *recordingCaptchaVerifier
		token    string
		want     error
	}{
		{name: "required", verifier: &recordingCaptchaVerifier{}, token: "", want: domain.ErrCaptchaRequired},
		{name: "failed", verifier: &recordingCaptchaVerifier{err: domain.ErrCaptchaFailed}, token: "token", want: domain.ErrCaptchaFailed},
		{name: "unavailable", verifier: &recordingCaptchaVerifier{err: domain.ErrCaptchaUnavailable}, token: "token", want: domain.ErrCaptchaUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := cache.NewMemory(cache.DefaultMemoryLimit)
			mailer := &capturingMailer{}
			svc := newResetTestService(t, store, map[string]bool{PasswordResetAction: true}, tc.verifier, mailer)
			// 用户存在与否不影响 CAPTCHA 失败结果：门禁在 lookup 前。
			seedResetUser(t, svc, "user@example.com", nil)

			err := svc.RequestPasswordReset(context.Background(), "user@example.com", tc.token)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.token != "" && tc.verifier.calls != 1 {
				t.Fatalf("verifier calls = %d, want 1", tc.verifier.calls)
			}
			if len(mailer.messages) != 0 {
				t.Fatalf("CAPTCHA failure sent %d mails", len(mailer.messages))
			}
			if resetKeyPresent(store, "email-code:"+passwordResetPurpose+":user@example.com") {
				t.Fatal("CAPTCHA failure wrote a reset record")
			}
		})
	}
}

func TestRequestPasswordResetSkipsVerifierWhenDisabled(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	verifier := &recordingCaptchaVerifier{}
	svc := newResetTestService(t, store, map[string]bool{}, verifier, &capturingMailer{})
	seedResetUser(t, svc, "user@example.com", nil)

	if err := svc.RequestPasswordReset(context.Background(), "user@example.com", ""); err != nil {
		t.Fatalf("request reset with policy off: %v", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("verifier calls = %d, want 0 when disabled", verifier.calls)
	}
}

func TestRequestPasswordResetMailFailuresStayGeneric(t *testing.T) {
	t.Run("mailer nil", func(t *testing.T) {
		store := cache.NewMemory(cache.DefaultMemoryLimit)
		svc := newResetTestService(t, store, map[string]bool{}, nil, nil)
		email := seedResetUser(t, svc, "user@example.com", nil)
		if err := svc.RequestPasswordReset(context.Background(), email, ""); err != nil {
			t.Fatalf("nil mailer must stay generic, got %v", err)
		}
		if resetKeyPresent(store, "email-code:"+passwordResetPurpose+":"+email) {
			t.Fatal("nil mailer left a reset record")
		}
	})
	t.Run("delivery failure", func(t *testing.T) {
		store := cache.NewMemory(cache.DefaultMemoryLimit)
		mailer := &capturingMailer{err: errors.New("smtp down")}
		svc := newResetTestService(t, store, map[string]bool{}, nil, mailer)
		email := seedResetUser(t, svc, "user@example.com", nil)
		if err := svc.RequestPasswordReset(context.Background(), email, ""); err != nil {
			t.Fatalf("delivery failure must stay generic, got %v", err)
		}
		if resetKeyPresent(store, "email-code:"+passwordResetPurpose+":"+email) {
			t.Fatal("failed delivery left a reset record")
		}
	})
	t.Run("render failure", func(t *testing.T) {
		store := cache.NewMemory(cache.DefaultMemoryLimit)
		svc := newResetTestService(t, store, map[string]bool{}, nil, &capturingMailer{})
		svc.templates = failingTemplateRenderer{}
		email := seedResetUser(t, svc, "user@example.com", nil)
		if err := svc.RequestPasswordReset(context.Background(), email, ""); err != nil {
			t.Fatalf("render failure must stay generic, got %v", err)
		}
		if resetKeyPresent(store, "email-code:"+passwordResetPurpose+":"+email) {
			t.Fatal("render failure left a reset record")
		}
	})
}

func TestResetPasswordWithCodeUpdatesPasswordAndVerifies(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	svc := newResetTestService(t, store, map[string]bool{}, nil, &capturingMailer{})
	ctx := context.Background()
	email := seedResetUser(t, svc, "user@example.com", nil)
	seedResetCode(t, ctx, store, email, "123456")

	if err := svc.ResetPasswordWithCode(ctx, email, "123456", "brand-new-password"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	user, err := svc.users.FindByEmailNormalized(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("previously unverified email must be marked verified")
	}
	hash, err := svc.users.PasswordHash(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(hash, "brand-new-password") {
		t.Fatal("new password must verify")
	}
	if user.SessionVersion <= 1 {
		t.Fatalf("session version after reset = %d, want > 1 (bumped)", user.SessionVersion)
	}
	if resetKeyPresent(store, "email-code:"+passwordResetPurpose+":"+email) {
		t.Fatal("code not consumed after reset")
	}
}

func TestResetPasswordWithCodePreservesExistingVerification(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	svc := newResetTestService(t, store, map[string]bool{}, nil, &capturingMailer{})
	ctx := context.Background()
	verifiedAt := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	email := seedResetUser(t, svc, "user@example.com", &verifiedAt)
	seedResetCode(t, ctx, store, email, "123456")

	if err := svc.ResetPasswordWithCode(ctx, email, "123456", "brand-new-password"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	user, err := svc.users.FindByEmailNormalized(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if user.EmailVerifiedAt == nil || !user.EmailVerifiedAt.Equal(verifiedAt) {
		t.Fatalf("verified_at = %v, want preserved %v", user.EmailVerifiedAt, verifiedAt)
	}
}

func TestResetPasswordWithCodeWrongCodeZeroWrite(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	svc := newResetTestService(t, store, map[string]bool{}, nil, &capturingMailer{})
	ctx := context.Background()
	email := seedResetUser(t, svc, "user@example.com", nil)
	seedResetCode(t, ctx, store, email, "123456")

	if err := svc.ResetPasswordWithCode(ctx, email, "000000", "brand-new-password"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("wrong code err = %v, want ErrInvalidCredentials", err)
	}
	user, _ := svc.users.FindByEmailNormalized(ctx, email)
	has, err := svc.users.HasPassword(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("wrong code must not write a password")
	}
	if user.EmailVerifiedAt != nil {
		t.Fatal("wrong code must not write a verification time")
	}
}

func TestResetPasswordWithCodeShortPasswordDoesNotConsumeCode(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	svc := newResetTestService(t, store, map[string]bool{}, nil, &capturingMailer{})
	ctx := context.Background()
	email := seedResetUser(t, svc, "user@example.com", nil)
	seedResetCode(t, ctx, store, email, "123456")

	if err := svc.ResetPasswordWithCode(ctx, email, "123456", "short"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short password err = %v, want ErrValidation", err)
	}
	if !resetKeyPresent(store, "email-code:"+passwordResetPurpose+":"+email) {
		t.Fatal("code consumed on invalid password")
	}
}

func TestResetPasswordWithCodeConcurrentSingleSuccess(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	svc := newResetTestService(t, store, map[string]bool{}, nil, &capturingMailer{})
	ctx := context.Background()
	email := seedResetUser(t, svc, "user@example.com", nil)
	seedResetCode(t, ctx, store, email, "123456")

	const workers = 16
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = svc.ResetPasswordWithCode(ctx, email, "123456", "brand-new-password")
		}(i)
	}
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful resets = %d, want 1", successes)
	}
	user, _ := svc.users.FindByEmailNormalized(ctx, email)
	has, err := svc.users.HasPassword(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("winning reset must have set a password")
	}
}

// TestResetPasswordWithCodeInvalidatesAuthzCache 验证密码重置提交后删除 authz 缓存，
// 使既有 JWT 与旧版本缓存无法继续授权。
func TestResetPasswordWithCodeInvalidatesAuthzCache(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	svc := newResetTestService(t, store, map[string]bool{}, nil, &capturingMailer{})
	ctx := context.Background()
	email := seedResetUser(t, svc, "user@example.com", nil)
	seedResetCode(t, ctx, store, email, "123456")

	// 装载 authz 缓存后重置密码，缓存应被删除。
	user, err := svc.users.FindByEmailNormalized(ctx, email)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if _, err := svc.Resolve(ctx, user.ID); err != nil {
		t.Fatalf("prime authz cache: %v", err)
	}
	if err := svc.ResetPasswordWithCode(ctx, email, "123456", "brand-new-password"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	var info json.RawMessage
	err = store.Get(ctx, authzKey(user.ID), &info)
	if !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("authz cache after reset err = %v, want ErrNotFound (invalidated)", err)
	}
}

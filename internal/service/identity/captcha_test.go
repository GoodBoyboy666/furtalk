package identity

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// fakeEmailCacheStore 记录验证码缓存写入次数，供副作用断言使用。
type fakeEmailCacheStore struct {
	sets int
}

func (f *fakeEmailCacheStore) Get(ctx context.Context, key string, out any) error {
	return cache.ErrNotFound
}

func (f *fakeEmailCacheStore) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	f.sets++
	return nil
}

func (f *fakeEmailCacheStore) Delete(ctx context.Context, key string) error { return nil }

func (f *fakeEmailCacheStore) AtomicConsume(ctx context.Context, key string) (string, error) {
	return "", cache.ErrNotFound
}

func (f *fakeEmailCacheStore) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	return nil
}

// fakeMailer 记录邮件投递次数，供发送副作用断言使用。
type fakeMailer struct {
	sent int
}

func (f *fakeMailer) Send(ctx context.Context, msg mailer.Message) error {
	f.sent++
	return nil
}

// stubTemplateRenderer 返回可预测的 HTML 正文，供验证码邮件构造使用。
type stubTemplateRenderer struct{}

func (stubTemplateRenderer) LoginCode(d mailer.LoginCodeData) (string, error) {
	return fmt.Sprintf("<strong>%s</strong>", d.Code), nil
}

func (stubTemplateRenderer) PasswordResetCode(d mailer.PasswordResetCodeData) (string, error) {
	return fmt.Sprintf("<strong>%s</strong>", d.Code), nil
}

func (stubTemplateRenderer) Moderation(mailer.ModerationData) (string, error) { return "", nil }
func (stubTemplateRenderer) Published(mailer.PublishedData) (string, error)   { return "", nil }
func (stubTemplateRenderer) Reply(mailer.ReplyData) (string, error)           { return "", nil }

// failingTemplateRenderer 返回固定渲染错误，供邮件渲染失败语义断言。
type failingTemplateRenderer struct{}

func (failingTemplateRenderer) LoginCode(mailer.LoginCodeData) (string, error) {
	return "", errors.New("render failed")
}

func (failingTemplateRenderer) PasswordResetCode(mailer.PasswordResetCodeData) (string, error) {
	return "", errors.New("render failed")
}

func (failingTemplateRenderer) Moderation(mailer.ModerationData) (string, error) { return "", nil }
func (failingTemplateRenderer) Published(mailer.PublishedData) (string, error)   { return "", nil }
func (failingTemplateRenderer) Reply(mailer.ReplyData) (string, error)           { return "", nil }

// staticCaptchaPolicy 返回固定的 CAPTCHA action 策略。
type staticCaptchaPolicy struct {
	policy map[string]bool
}

func (p staticCaptchaPolicy) CaptchaPolicy(ctx context.Context) (map[string]bool, error) {
	return p.policy, nil
}

// recordingCaptchaVerifier 记录调用参数并返回固定错误。
type recordingCaptchaVerifier struct {
	err    error
	calls  int
	action string
	token  string
}

func (v *recordingCaptchaVerifier) Verify(ctx context.Context, action, token string) error {
	v.calls++
	v.action = action
	v.token = token
	return v.err
}

// newEmailCodeTestDB 打开临时 SQLite 数据库并迁移用户表。
func newEmailCodeTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "identity-email-code-test.db")
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
	return db
}

// newEmailCodeTestService 装配只依赖缓存、策略、验证器、邮件与真实用户仓储的最小服务。
func newEmailCodeTestService(t *testing.T, store cache.Store, policy CaptchaPolicyReader, verifier CaptchaVerifier, mailer mailer.Mailer) *Service {
	db := newEmailCodeTestDB(t)
	return NewService(Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         repository.NewUserRepo(db),
		Cache:         store,
		Policy:        loginTestPolicy{},
		CaptchaPolicy: policy,
		Captcha:       verifier,
		Mailer:        mailer,
		Templates:     stubTemplateRenderer{},
	})
}

func emailCodeEnabledPolicy() map[string]bool {
	return map[string]bool{EmailCodeAction: true}
}

// TestSendEmailCodeRequiresCaptchaWhenPolicyEnabled 证明策略开启且缺 token 时返回
// ErrCaptchaRequired，不调用验证器、不写验证码缓存也不发送邮件。
func TestSendEmailCodeRequiresCaptchaWhenPolicyEnabled(t *testing.T) {
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	verifier := &recordingCaptchaVerifier{}
	svc := newEmailCodeTestService(t, store, staticCaptchaPolicy{emailCodeEnabledPolicy()}, verifier, mailer)

	err := svc.SendEmailCode(context.Background(), "user@example.com", "")
	if !errors.Is(err, domain.ErrCaptchaRequired) {
		t.Fatalf("err = %v, want ErrCaptchaRequired", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("verifier calls = %d, want 0", verifier.calls)
	}
	if store.sets != 0 {
		t.Fatalf("email code sets = %d, want 0", store.sets)
	}
	if mailer.sent != 0 {
		t.Fatalf("mail sent = %d, want 0", mailer.sent)
	}
}

// TestSendEmailCodeMapsVerifierFailure 证明 token 校验失败映射为 ErrCaptchaFailed 且无副作用。
func TestSendEmailCodeMapsVerifierFailure(t *testing.T) {
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	verifier := &recordingCaptchaVerifier{err: domain.ErrCaptchaFailed}
	svc := newEmailCodeTestService(t, store, staticCaptchaPolicy{emailCodeEnabledPolicy()}, verifier, mailer)

	err := svc.SendEmailCode(context.Background(), "user@example.com", "token")
	if !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("err = %v, want ErrCaptchaFailed", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
	if verifier.action != EmailCodeAction {
		t.Fatalf("verifier action = %q, want %q", verifier.action, EmailCodeAction)
	}
	if store.sets != 0 {
		t.Fatalf("email code sets = %d, want 0", store.sets)
	}
	if mailer.sent != 0 {
		t.Fatalf("mail sent = %d, want 0", mailer.sent)
	}
}

// TestSendEmailCodeMapsProviderUnavailable 证明 provider 不可用映射为 ErrCaptchaUnavailable 且无副作用。
func TestSendEmailCodeMapsProviderUnavailable(t *testing.T) {
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	verifier := &recordingCaptchaVerifier{err: domain.ErrCaptchaUnavailable}
	svc := newEmailCodeTestService(t, store, staticCaptchaPolicy{emailCodeEnabledPolicy()}, verifier, mailer)

	err := svc.SendEmailCode(context.Background(), "user@example.com", "token")
	if !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("err = %v, want ErrCaptchaUnavailable", err)
	}
	if store.sets != 0 {
		t.Fatalf("email code sets = %d, want 0", store.sets)
	}
	if mailer.sent != 0 {
		t.Fatalf("mail sent = %d, want 0", mailer.sent)
	}
}

// TestSendEmailCodeNilVerifierWhenPolicyEnabled 证明策略开启但验证器缺失时返回 ErrCaptchaUnavailable。
func TestSendEmailCodeNilVerifierWhenPolicyEnabled(t *testing.T) {
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	svc := newEmailCodeTestService(t, store, staticCaptchaPolicy{emailCodeEnabledPolicy()}, nil, mailer)

	err := svc.SendEmailCode(context.Background(), "user@example.com", "token")
	if !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("err = %v, want ErrCaptchaUnavailable", err)
	}
	if store.sets != 0 {
		t.Fatalf("email code sets = %d, want 0", store.sets)
	}
	if mailer.sent != 0 {
		t.Fatalf("mail sent = %d, want 0", mailer.sent)
	}
}

// TestSendEmailCodeSendsAfterCaptcha 证明策略开启且校验成功后写入验证码缓存并发送邮件。
func TestSendEmailCodeSendsAfterCaptcha(t *testing.T) {
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	verifier := &recordingCaptchaVerifier{}
	svc := newEmailCodeTestService(t, store, staticCaptchaPolicy{emailCodeEnabledPolicy()}, verifier, mailer)

	if err := svc.SendEmailCode(context.Background(), "user@example.com", "token"); err != nil {
		t.Fatalf("SendEmailCode() error = %v, want nil", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifier.calls)
	}
	if verifier.token != "token" {
		t.Fatalf("verifier token = %q, want %q", verifier.token, "token")
	}
	if store.sets != 1 {
		t.Fatalf("email code sets = %d, want 1", store.sets)
	}
	if mailer.sent != 1 {
		t.Fatalf("mail sent = %d, want 1", mailer.sent)
	}
}

// TestSendEmailCodeSkipsCaptchaWhenPolicyDisabled 证明策略关闭时不调用验证器，
// 空 token 也放行，维持原有发送行为。
func TestSendEmailCodeSkipsCaptchaWhenPolicyDisabled(t *testing.T) {
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	verifier := &recordingCaptchaVerifier{}
	svc := newEmailCodeTestService(t, store, staticCaptchaPolicy{map[string]bool{}}, verifier, mailer)

	if err := svc.SendEmailCode(context.Background(), "user@example.com", ""); err != nil {
		t.Fatalf("SendEmailCode() error = %v, want nil", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("verifier calls = %d, want 0", verifier.calls)
	}
	if store.sets != 1 {
		t.Fatalf("email code sets = %d, want 1", store.sets)
	}
	if mailer.sent != 1 {
		t.Fatalf("mail sent = %d, want 1", mailer.sent)
	}
}

// TestSendEmailCodeRenderFailureIsUnavailable 证明 HTML 渲染失败按邮件服务不可用处理，
// 不发送残缺消息。
func TestSendEmailCodeRenderFailureIsUnavailable(t *testing.T) {
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	svc := newEmailCodeTestService(t, store, staticCaptchaPolicy{map[string]bool{}}, nil, mailer)
	svc.templates = failingTemplateRenderer{}

	if err := svc.SendEmailCode(context.Background(), "user@example.com", ""); !errors.Is(err, domain.ErrMailUnavailable) {
		t.Fatalf("render failure err = %v, want ErrMailUnavailable", err)
	}
	if mailer.sent != 0 {
		t.Fatalf("mail sent = %d, want 0", mailer.sent)
	}
}

package identity

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/oauth"
	"furtalk/internal/repository"
)

// configurableEmailPolicy 返回可配置的邮箱域名名单与头像基址。
type configurableEmailPolicy struct {
	whitelist []string
	blacklist []string
	baseURL   string
}

func (p configurableEmailPolicy) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}

func (p configurableEmailPolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	base := p.baseURL
	if base == "" {
		base = "https://www.gravatar.com/avatar"
	}
	return p.whitelist, p.blacklist, base, nil
}

// emailDomainTestService 装配带真实仓储、可配置名单策略与固定 signer 的身份服务。
func emailDomainTestService(t *testing.T, policy PolicyReader) *Service {
	t.Helper()
	db := newCaptchaLoginDB(t)
	return NewService(Dependencies{
		TxRunner:   gormtx.NewRunner(db),
		Users:      repository.NewUserRepo(db),
		Identities: repository.NewExternalIdentityRepo(db),
		Policy:     policy,
		Signer:     loginTestSigner{lifetime: 7 * 24 * 60 * 60},
		Templates:  stubTemplateRenderer{},
	})
}

func TestCheckEmailDomainAllowed(t *testing.T) {
	svc := emailDomainTestService(t, configurableEmailPolicy{whitelist: []string{"example.com"}, blacklist: []string{"blocked.com"}})
	ctx := context.Background()

	if err := svc.checkEmailDomainAllowed(ctx, "user@example.com"); err != nil {
		t.Fatalf("whitelist hit error = %v, want nil", err)
	}
	if err := svc.checkEmailDomainAllowed(ctx, "user@badexample.com"); !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("whitelist prefix error = %v, want ErrEmailDomainNotAllowed", err)
	}
	if err := svc.checkEmailDomainAllowed(ctx, "user@sub.example.com"); !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("whitelist subdomain error = %v, want ErrEmailDomainNotAllowed", err)
	}
	if err := svc.checkEmailDomainAllowed(ctx, "no-at-sign"); err == nil {
		t.Fatal("malformed email must error")
	}
}

func TestDefaultNickname(t *testing.T) {
	if got := defaultNickname("person@example.com"); got != "person" {
		t.Fatalf("defaultNickname = %q, want person", got)
	}
	if got := defaultNickname("@example.com"); got != "user" {
		t.Fatalf("empty local defaultNickname = %q, want user", got)
	}
}

func TestCreateUserAppliesIdentityRegistrationPolicy(t *testing.T) {
	ctx := context.Background()
	svc := emailDomainTestService(t, configurableEmailPolicy{blacklist: []string{"blocked.com"}})
	blocked := &domain.User{
		Email:           "new@blocked.com",
		EmailNormalized: "new@blocked.com",
		Nickname:        "new",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := svc.CreateUser(ctx, blocked); !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("blocked CreateUser error = %v", err)
	}
	if _, err := svc.users.FindByEmailNormalized(ctx, blocked.EmailNormalized); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("blocked user must not exist: %v", err)
	}

	allowed := &domain.User{
		Email:           "new@ok.com",
		EmailNormalized: "new@ok.com",
		Nickname:        "new",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := svc.CreateUser(ctx, allowed); err != nil {
		t.Fatalf("allowed CreateUser: %v", err)
	}
}

// TestSendEmailCodeRejectsDisallowedDomain 证明未知邮箱域名被拒绝时在写验证码缓存
// 与发送邮件之前返回 ErrEmailDomainNotAllowed。
func TestSendEmailCodeRejectsDisallowedDomain(t *testing.T) {
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	verifier := &recordingCaptchaVerifier{}
	svc := emailDomainTestService(t, configurableEmailPolicy{blacklist: []string{"blocked.com"}})
	svc.emailCodes = cacheEmailCodeStore{store: store}
	svc.mailer = mailer
	svc.captchaPolicy = staticCaptchaPolicy{map[string]bool{}}
	svc.captcha = verifier

	err := svc.SendEmailCode(context.Background(), "user@blocked.com", "")
	if !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("err = %v, want ErrEmailDomainNotAllowed", err)
	}
	if store.sets != 0 {
		t.Fatalf("email code sets = %d, want 0", store.sets)
	}
	if mailer.sent != 0 {
		t.Fatalf("mail sent = %d, want 0", mailer.sent)
	}
}

// TestSendEmailCodeAllowsUnknownAndExisting 证明白名单外的未知邮箱仍可发送；
// 已存在用户即使域名当前被禁止也保持原发送行为。
func TestSendEmailCodeAllowsUnknownAndExisting(t *testing.T) {
	db := newCaptchaLoginDB(t)
	store := &fakeEmailCacheStore{}
	mailer := &fakeMailer{}
	svc := NewService(Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         repository.NewUserRepo(db),
		Policy:        configurableEmailPolicy{whitelist: []string{"example.com"}, blacklist: []string{"blocked.com"}},
		CaptchaPolicy: staticCaptchaPolicy{map[string]bool{}},
		Mailer:        mailer,
		Templates:     stubTemplateRenderer{},
	})
	svc.emailCodes = cacheEmailCodeStore{store: store}

	// 白名单命中的未知邮箱可发送。
	if err := svc.SendEmailCode(context.Background(), "new@example.com", ""); err != nil {
		t.Fatalf("unknown whitelisted email error = %v, want nil", err)
	}
	if store.sets != 1 || mailer.sent != 1 {
		t.Fatalf("sets/mail = %d/%d, want 1/1", store.sets, mailer.sent)
	}

	// 已存在用户即使域名不在白名单也继续原行为。
	insertVerifiedUser(t, db, "existing@other.com")
	store.sets = 0
	mailer.sent = 0
	if err := svc.SendEmailCode(context.Background(), "existing@other.com", ""); err != nil {
		t.Fatalf("existing user error = %v, want nil", err)
	}
	if store.sets != 1 || mailer.sent != 1 {
		t.Fatalf("existing user sets/mail = %d/%d, want 1/1", store.sets, mailer.sent)
	}
}

// TestLoginWithEmailCodeRegisterRejectsDisallowedDomain 证明验证码登录的未知邮箱在
// 自动注册前被名单拒绝，不创建用户。
func TestLoginWithEmailCodeRegisterRejectsDisallowedDomain(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := NewService(Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         repository.NewUserRepo(db),
		Cache:         cache.NewMemory(10000),
		Policy:        configurableEmailPolicy{blacklist: []string{"blocked.com"}},
		CaptchaPolicy: staticCaptchaPolicy{map[string]bool{}},
		Signer:        loginTestSigner{lifetime: 7 * 24 * 60 * 60},
	})
	seedEmailCode(t, svc, "new@blocked.com", "123456")

	_, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{Email: "new@blocked.com", Code: "123456"})
	if !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("err = %v, want ErrEmailDomainNotAllowed", err)
	}
	if _, ferr := repository.NewUserRepo(db).FindByEmailNormalized(context.Background(), "new@blocked.com"); !errors.Is(ferr, domain.ErrNotFound) {
		t.Fatalf("user must not be created: %v", ferr)
	}
}

// TestRegisterOAuthUserRejectsDisallowedDomain 证明 OAuth 未知邮箱自动注册被名单拒绝时
// 不创建用户也不创建外部身份；允许的域名照常创建。
func TestRegisterOAuthUserRejectsDisallowedDomain(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := NewService(Dependencies{
		TxRunner:   gormtx.NewRunner(db),
		Users:      repository.NewUserRepo(db),
		Identities: repository.NewExternalIdentityRepo(db),
		Policy:     configurableEmailPolicy{blacklist: []string{"blocked.com"}},
		Signer:     loginTestSigner{lifetime: 7 * 24 * 60 * 60},
	})
	ctx := context.Background()
	provider := &AuthProvider{ProviderKey: "github"}
	oauthIdentity := &oauth.Identity{Subject: "sub-1", VerifiedEmail: "new@blocked.com"}
	record := OAuthState{Purpose: oauthPurposeLogin}

	_, err := svc.registerOAuthUser(ctx, provider, oauthIdentity, "new@blocked.com", record)
	if !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("err = %v, want ErrEmailDomainNotAllowed", err)
	}
	if _, ferr := repository.NewUserRepo(db).FindByEmailNormalized(ctx, "new@blocked.com"); !errors.Is(ferr, domain.ErrNotFound) {
		t.Fatalf("user must not be created: %v", ferr)
	}
	if _, ierr := repository.NewExternalIdentityRepo(db).GetByProviderSubject(ctx, "github", "sub-1"); !errors.Is(ierr, domain.ErrNotFound) {
		t.Fatalf("identity must not be created: %v", ierr)
	}

	// 允许域名照常自动注册。
	svc2 := NewService(Dependencies{
		TxRunner:   gormtx.NewRunner(db),
		Users:      repository.NewUserRepo(db),
		Identities: repository.NewExternalIdentityRepo(db),
		Policy:     configurableEmailPolicy{whitelist: []string{"ok.com"}},
		Signer:     loginTestSigner{lifetime: 7 * 24 * 60 * 60},
	})
	session, err := svc2.registerOAuthUser(ctx, provider, &oauth.Identity{Subject: "sub-2", VerifiedEmail: "new@ok.com"}, "new@ok.com", record)
	if err != nil {
		t.Fatalf("allowed register error = %v, want nil", err)
	}
	if session == nil {
		t.Fatal("session = nil, want logged-in session")
	}
	if _, ferr := repository.NewUserRepo(db).FindByEmailNormalized(ctx, "new@ok.com"); ferr != nil {
		t.Fatalf("allowed user must exist: %v", ferr)
	}
	if _, ierr := repository.NewExternalIdentityRepo(db).GetByProviderSubject(ctx, "github", "sub-2"); ierr != nil {
		t.Fatalf("allowed identity must exist: %v", ierr)
	}
}

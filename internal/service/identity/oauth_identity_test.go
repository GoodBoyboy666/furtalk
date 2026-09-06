package identity

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/oauth"
	"furtalk/internal/repository"

	"gorm.io/gorm"
)

// scriptedOAuthProvider 返回脚本化的身份或固定错误，供解析与回调流程测试使用。
// BuildAuthURL 会把 state 回显到授权 URL，测试从该 URL 提取并消费。
type scriptedOAuthProvider struct {
	name     string
	identity *oauth.Identity
	err      error
}

func (p *scriptedOAuthProvider) Name() string { return p.name }

func (p *scriptedOAuthProvider) BuildAuthURL(ctx context.Context, req oauth.AuthorizationRequest) (string, error) {
	return "https://auth.example.com/start?state=" + url.QueryEscape(req.State), nil
}

func (p *scriptedOAuthProvider) Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.Identity, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.identity, nil
}

// noRegistrationPolicy 关闭公开注册，其余策略保持默认。
type noRegistrationPolicy struct{}

func (noRegistrationPolicy) Policy(context.Context) (bool, string, error) {
	return false, domain.CommentModeAuthenticated, nil
}

func (noRegistrationPolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, nil, "https://www.gravatar.com/avatar", nil
}

// oauthIdentityTestService 装配带真实仓储、可配置策略与固定 signer 的身份服务，
// 同时返回同一数据库句柄供插入与计数断言使用。
func oauthIdentityTestService(t *testing.T, policy PolicyReader) (*Service, *gorm.DB) {
	t.Helper()
	db := newCaptchaLoginDB(t)
	return NewService(Dependencies{
		TxRunner:   gormtx.NewRunner(db),
		Users:      repository.NewUserRepo(db),
		Identities: repository.NewExternalIdentityRepo(db),
		Policy:     policy,
		Signer:     loginTestSigner{lifetime: 7 * 24 * 60 * 60},
		Templates:  stubTemplateRenderer{},
	}), db
}

// oauthStateFromURL 从授权 URL 提取 state。
func oauthStateFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("auth url missing state")
	}
	return state
}

// TestFinishOAuthOversizedProviderResponseUnavailable 验证 OAuth provider 响应
// 超过平台上限时映射为 provider unavailable，而不是普通身份校验失败。
func TestFinishOAuthOversizedProviderResponseUnavailable(t *testing.T) {
	ctx := context.Background()
	scripted := &scriptedOAuthProvider{name: "GitHub", err: oauth.ErrResponseTooLarge}
	db := newCaptchaLoginDB(t)
	svc := NewService(Dependencies{
		TxRunner:     gormtx.NewRunner(db),
		Users:        repository.NewUserRepo(db),
		Identities:   repository.NewExternalIdentityRepo(db),
		Cache:        cache.NewMemory(10000),
		Policy:       configurableEmailPolicy{},
		Providers:    oauthTestProviders{provider: &AuthProvider{ProviderKey: "github", Kind: domain.ProviderKindOAuth, ClientID: "id", ClientSecret: "secret"}},
		Signer:       loginTestSigner{lifetime: 7 * 24 * 60 * 60},
		Templates:    stubTemplateRenderer{},
		OAuthFactory: (&fakeOAuthFactory{provider: scripted}).build,
		BaseURL:      "https://example.com",
	})
	start, err := svc.BeginOAuth(ctx, "github", oauthPurposeLogin, 0, "")
	if err != nil {
		t.Fatalf("BeginOAuth: %v", err)
	}
	_, _, err = svc.FinishOAuth(ctx, "github", oauthStateFromURL(t, start.AuthURL), "code")
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("FinishOAuth oversized response err = %v, want domain.ErrUnavailable", err)
	}
}

// TestFinishOAuthBindOnlyBindThenLogin 验证 bind-only provider 可先由登录用户绑定
// （空 VerifiedEmail 落库），随后同一 subject 无需邮箱即可登录，并刷新 last_login_at。
func TestFinishOAuthBindOnlyBindThenLogin(t *testing.T) {
	ctx := context.Background()
	db := newCaptchaLoginDB(t)
	scripted := &scriptedOAuthProvider{name: "Microsoft", identity: &oauth.Identity{Subject: "ms-sub-1"}}
	svc := NewService(Dependencies{
		TxRunner:     gormtx.NewRunner(db),
		Users:        repository.NewUserRepo(db),
		Identities:   repository.NewExternalIdentityRepo(db),
		Cache:        cache.NewMemory(10000),
		Policy:       configurableEmailPolicy{},
		Providers:    oauthTestProviders{provider: &AuthProvider{ProviderKey: "microsoft"}},
		Signer:       loginTestSigner{lifetime: 7 * 24 * 60 * 60},
		Templates:    stubTemplateRenderer{},
		OAuthFactory: (&fakeOAuthFactory{provider: scripted}).build,
		BaseURL:      "https://example.com",
	})
	user := insertVerifiedUser(t, db, "user@example.com")

	// 第一步：purpose=bind 创建绑定，适配器不返回邮箱，落库为空串。
	start, err := svc.BeginOAuth(ctx, "microsoft", oauthPurposeBind, user.ID, "/account/security")
	if err != nil {
		t.Fatalf("BeginOAuth bind: %v", err)
	}
	session, redirect, err := svc.FinishOAuth(ctx, "microsoft", oauthStateFromURL(t, start.AuthURL), "code-1")
	if err != nil {
		t.Fatalf("FinishOAuth bind: %v", err)
	}
	if session == nil {
		t.Fatal("session = nil, want logged-in session")
	}
	if redirect != "/account/security" {
		t.Fatalf("redirect = %q, want /account/security", redirect)
	}
	bound, err := svc.identities.GetByProviderSubject(ctx, "microsoft", "ms-sub-1")
	if err != nil {
		t.Fatalf("get bound identity: %v", err)
	}
	if bound.UserID != user.ID {
		t.Fatalf("bound user = %d, want %d", bound.UserID, user.ID)
	}
	if bound.VerifiedEmail != "" {
		t.Fatalf("bound verified_email = %q, want empty", bound.VerifiedEmail)
	}

	// 第二步：同一 subject 直接登录，并刷新 last_login_at。
	start, err = svc.BeginOAuth(ctx, "microsoft", oauthPurposeLogin, 0, "")
	if err != nil {
		t.Fatalf("BeginOAuth login: %v", err)
	}
	session, _, err = svc.FinishOAuth(ctx, "microsoft", oauthStateFromURL(t, start.AuthURL), "code-2")
	if err != nil {
		t.Fatalf("FinishOAuth login: %v", err)
	}
	if session == nil {
		t.Fatal("login session = nil, want logged-in session")
	}
	bound, err = svc.identities.GetByProviderSubject(ctx, "microsoft", "ms-sub-1")
	if err != nil {
		t.Fatalf("re-get bound identity: %v", err)
	}
	if bound.LastLoginAt == nil {
		t.Fatal("last_login_at must be touched after login")
	}
}

// TestResolveOAuthBindOnlyUnboundLoginDenied 证明 bind-only provider 未绑定时
// login 一律通用失败：即使适配器返回看似有效的邮箱也不按邮箱查找/注册，零写入。
func TestResolveOAuthBindOnlyUnboundLoginDenied(t *testing.T) {
	ctx := context.Background()
	svc, db := oauthIdentityTestService(t, configurableEmailPolicy{})
	provider := &AuthProvider{ProviderKey: "microsoft"}

	identity := &oauth.Identity{Subject: "ms-sub-2", VerifiedEmail: "new@example.com"}
	if _, err := svc.resolveOAuthIdentity(ctx, provider, identity, OAuthState{Purpose: oauthPurposeLogin}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("unbound bind-only login err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.identities.GetByProviderSubject(ctx, "microsoft", "ms-sub-2"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("identity must not be created: %v", err)
	}
	if _, err := svc.users.FindByEmailNormalized(ctx, "new@example.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("user must not be created: %v", err)
	}
	var count int64
	if err := db.Table("users").Count(&count).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("users count = %d, want 0", count)
	}
}

// TestBeginOAuthBindOnlyRegisterRejected 证明 bind-only provider 的 register 用途
// 在 start 阶段直接以通用失败拒绝，不构建任何内容。
func TestBeginOAuthBindOnlyRegisterRejected(t *testing.T) {
	t.Parallel()
	svc := newOAuthStartService(oauthTestProviders{}, nil)
	if _, err := svc.BeginOAuth(context.Background(), "microsoft", oauthPurposeRegister, 0, ""); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("bind-only register err = %v, want ErrInvalidCredentials", err)
	}
}

// TestBeginOAuthRegistrationCapableRegisterAllowed 证明可注册 provider 的 register
// 用途不会被 start 阶段拒绝，继续返回授权 URL（正面对照）。
func TestBeginOAuthRegistrationCapableRegisterAllowed(t *testing.T) {
	t.Parallel()
	factory := &fakeOAuthFactory{provider: &fakeOAuthProvider{name: "GitHub", authURL: "https://github.com/login/oauth/authorize?x=1"}}
	svc := newOAuthStartService(oauthTestProviders{
		provider: &AuthProvider{ProviderKey: "github", Kind: domain.ProviderKindOAuth, ClientID: "id", ClientSecret: "secret"},
	}, factory.build)

	start, err := svc.BeginOAuth(context.Background(), "github", oauthPurposeRegister, 0, "")
	if err != nil {
		t.Fatalf("BeginOAuth github register: %v", err)
	}
	if start == nil || start.AuthURL == "" {
		t.Fatal("start must include a non-empty auth URL")
	}
}

// TestResolveOAuthCrossUserBindConflict 证明绑定已被其他用户占用时，bind 通用失败，
// 不把调用方切换到其他账号，也不产生任何写入。
func TestResolveOAuthCrossUserBindConflict(t *testing.T) {
	ctx := context.Background()
	svc, db := oauthIdentityTestService(t, configurableEmailPolicy{})
	userA := insertVerifiedUser(t, db, "a@example.com")
	userB := insertVerifiedUser(t, db, "b@example.com")
	if err := svc.identities.Create(ctx, &domain.ExternalIdentity{
		UserID:          userB.ID,
		ProviderKey:     "microsoft",
		ProviderSubject: "ms-sub-3",
	}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	provider := &AuthProvider{ProviderKey: "microsoft"}

	if _, err := svc.resolveOAuthIdentity(ctx, provider, &oauth.Identity{Subject: "ms-sub-3"}, OAuthState{Purpose: oauthPurposeBind, UserID: userA.ID}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("cross-user bind err = %v, want ErrInvalidCredentials", err)
	}
	bound, err := svc.identities.GetByProviderSubject(ctx, "microsoft", "ms-sub-3")
	if err != nil {
		t.Fatalf("re-get binding: %v", err)
	}
	if bound.UserID != userB.ID {
		t.Fatalf("binding owner = %d, want %d (must not switch)", bound.UserID, userB.ID)
	}
	identities, err := svc.identities.ListByUserID(ctx, userA.ID)
	if err != nil {
		t.Fatalf("list user A identities: %v", err)
	}
	if len(identities) != 0 {
		t.Fatalf("user A identities = %d, want 0", len(identities))
	}
}

// TestResolveOAuthExistingBindingRegisterLogsIn 证明旧 register 用途命中已有绑定
// 时仍然登录绑定用户（legacy 语义）。
func TestResolveOAuthExistingBindingRegisterLogsIn(t *testing.T) {
	ctx := context.Background()
	svc, db := oauthIdentityTestService(t, configurableEmailPolicy{})
	user := insertVerifiedUser(t, db, "user@example.com")
	if err := svc.identities.Create(ctx, &domain.ExternalIdentity{
		UserID:          user.ID,
		ProviderKey:     "microsoft",
		ProviderSubject: "ms-sub-4",
	}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	provider := &AuthProvider{ProviderKey: "microsoft"}

	session, err := svc.resolveOAuthIdentity(ctx, provider, &oauth.Identity{Subject: "ms-sub-4"}, OAuthState{Purpose: oauthPurposeRegister})
	if err != nil {
		t.Fatalf("register with binding err = %v, want nil", err)
	}
	if session == nil {
		t.Fatal("session = nil, want logged-in session")
	}
}

// TestResolveOAuthVerifiedEmailBindStoresEmail 证明可注册 provider 的 bind 流程
// 直接为当前用户创建绑定，并把可信邮箱原样落库。
func TestResolveOAuthVerifiedEmailBindStoresEmail(t *testing.T) {
	ctx := context.Background()
	svc, db := oauthIdentityTestService(t, configurableEmailPolicy{})
	user := insertVerifiedUser(t, db, "user@example.com")
	provider := &AuthProvider{ProviderKey: "github"}

	session, err := svc.resolveOAuthIdentity(ctx, provider, &oauth.Identity{Subject: "gh-sub-1", VerifiedEmail: "user@example.com"}, OAuthState{Purpose: oauthPurposeBind, UserID: user.ID})
	if err != nil {
		t.Fatalf("bind resolve error = %v, want nil", err)
	}
	if session == nil {
		t.Fatal("session = nil, want logged-in session")
	}
	bound, err := svc.identities.GetByProviderSubject(ctx, "github", "gh-sub-1")
	if err != nil {
		t.Fatalf("get bound identity: %v", err)
	}
	if bound.UserID != user.ID {
		t.Fatalf("bound user = %d, want %d", bound.UserID, user.ID)
	}
	if bound.VerifiedEmail != "user@example.com" {
		t.Fatalf("bound verified_email = %q, want user@example.com", bound.VerifiedEmail)
	}
}

// TestResolveOAuthMissingEmailNoRegistration 证明可注册 provider 未提供可信邮箱
// 且未绑定时通用失败，不创建用户或绑定。
func TestResolveOAuthMissingEmailNoRegistration(t *testing.T) {
	ctx := context.Background()
	svc, db := oauthIdentityTestService(t, configurableEmailPolicy{})
	provider := &AuthProvider{ProviderKey: "github"}

	if _, err := svc.resolveOAuthIdentity(ctx, provider, &oauth.Identity{Subject: "gh-sub-2"}, OAuthState{Purpose: oauthPurposeLogin}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("missing email err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.identities.GetByProviderSubject(ctx, "github", "gh-sub-2"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("identity must not be created: %v", err)
	}
	var count int64
	if err := db.Table("users").Count(&count).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("users count = %d, want 0", count)
	}
}

// TestResolveOAuthRegisterPublicClosed 证明未知邮箱自动注册在公开注册关闭时
// 返回通用失败，不创建用户或绑定。
func TestResolveOAuthRegisterPublicClosed(t *testing.T) {
	ctx := context.Background()
	svc, _ := oauthIdentityTestService(t, noRegistrationPolicy{})
	provider := &AuthProvider{ProviderKey: "github"}

	if _, err := svc.resolveOAuthIdentity(ctx, provider, &oauth.Identity{Subject: "gh-sub-3", VerifiedEmail: "new@example.com"}, OAuthState{Purpose: oauthPurposeLogin}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("public closed err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.users.FindByEmailNormalized(ctx, "new@example.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("user must not be created: %v", err)
	}
	if _, err := svc.identities.GetByProviderSubject(ctx, "github", "gh-sub-3"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("identity must not be created: %v", err)
	}
}

// TestResolveOAuthRegisterDomainBlocked 证明未知邮箱被域名名单拒绝时返回
// 明确语义错误，不创建用户或绑定。
func TestResolveOAuthRegisterDomainBlocked(t *testing.T) {
	ctx := context.Background()
	svc, _ := oauthIdentityTestService(t, configurableEmailPolicy{blacklist: []string{"blocked.com"}})
	provider := &AuthProvider{ProviderKey: "github"}

	if _, err := svc.resolveOAuthIdentity(ctx, provider, &oauth.Identity{Subject: "gh-sub-4", VerifiedEmail: "new@blocked.com"}, OAuthState{Purpose: oauthPurposeLogin}); !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("domain blocked err = %v, want ErrEmailDomainNotAllowed", err)
	}
	if _, err := svc.users.FindByEmailNormalized(ctx, "new@blocked.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("user must not be created: %v", err)
	}
	if _, err := svc.identities.GetByProviderSubject(ctx, "github", "gh-sub-4"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("identity must not be created: %v", err)
	}
}

// TestResolveOAuthRegisterCreatesUserAndBinding 证明未知邮箱 + 公开注册开启时，
// 在一个事务内创建已验证用户与外部身份，并签发会话。
func TestResolveOAuthRegisterCreatesUserAndBinding(t *testing.T) {
	ctx := context.Background()
	svc, _ := oauthIdentityTestService(t, configurableEmailPolicy{})
	provider := &AuthProvider{ProviderKey: "github"}

	session, err := svc.resolveOAuthIdentity(ctx, provider, &oauth.Identity{Subject: "gh-sub-5", VerifiedEmail: "new@ok.com"}, OAuthState{Purpose: oauthPurposeLogin})
	if err != nil {
		t.Fatalf("register resolve error = %v, want nil", err)
	}
	if session == nil {
		t.Fatal("session = nil, want logged-in session")
	}
	user, err := svc.users.FindByEmailNormalized(ctx, "new@ok.com")
	if err != nil {
		t.Fatalf("find created user: %v", err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("new oauth user must be email-verified")
	}
	bound, err := svc.identities.GetByProviderSubject(ctx, "github", "gh-sub-5")
	if err != nil {
		t.Fatalf("get bound identity: %v", err)
	}
	if bound.UserID != user.ID {
		t.Fatalf("bound user = %d, want %d", bound.UserID, user.ID)
	}
	if bound.VerifiedEmail != "new@ok.com" {
		t.Fatalf("bound verified_email = %q, want new@ok.com", bound.VerifiedEmail)
	}
}

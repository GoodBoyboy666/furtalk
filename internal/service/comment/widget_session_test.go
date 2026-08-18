package comment

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/service/identity"
)

type staticCommentPolicyReader struct {
	policy domain.CommentPolicy
	calls  int
}

func (r *staticCommentPolicyReader) CommentPolicy(context.Context) (domain.CommentPolicy, error) {
	r.calls++
	return r.policy, nil
}

// countingCaptchaVerifier 记录验证调用次数并恒通过。
type countingCaptchaVerifier struct {
	calls int
}

func (v *countingCaptchaVerifier) Verify(context.Context, string, string) error {
	v.calls++
	return nil
}

// TestCreateAnonymousRejectsClosedRegistrationWithoutSideEffects 证明注册关闭时，
// 未知邮箱的评论创建被拒绝，且零验证码、零事务、零资料写入。已存在普通用户
// 不受注册门禁影响，可继续发表评论。
func TestCreateAnonymousRejectsClosedRegistrationWithoutSideEffects(t *testing.T) {
	t.Parallel()

	db := newReplyTestDB(t)
	siteID := seedWidgetDomainSite(t, db)
	ctx := context.Background()
	if err := repository.NewUserRepo(db).Create(ctx, &domain.User{
		Email:           "existing@example.com",
		EmailNormalized: "existing@example.com",
		Nickname:        "existing",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}); err != nil {
		t.Fatalf("create existing user: %v", err)
	}
	captcha := &countingCaptchaVerifier{}
	userW := identity.NewService(identity.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
	})
	svc := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    repository.NewSiteRepo(db),
		Users:    repository.NewUserRepo(db),
		Settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:               domain.CommentModeAnonymous,
			PublicRegistration: false,
			CaptchaPolicy:      map[string]bool{"comment": true},
			Privacy:            domain.PrivacyPolicy{IPMode: "none", UAMode: "none"},
		}},
		UserW:   userW,
		Captcha: captcha,
	})

	// 未知邮箱在注册关闭时被拒，且不消耗验证码。
	_, err := svc.Create(ctx, CreateInput{
		SiteID:       siteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "unknown@example.com",
		Nickname:     "visitor",
		BodyMarkdown: "a comment",
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("unknown email error = %v, want ErrInvalidCredentials", err)
	}
	if captcha.calls != 0 {
		t.Fatalf("CAPTCHA calls = %d, want 0", captcha.calls)
	}
	if _, ferr := repository.NewUserRepo(db).FindByEmailNormalized(ctx, "unknown@example.com"); !errors.Is(ferr, domain.ErrNotFound) {
		t.Fatalf("unknown user must not be created: %v", ferr)
	}

	// 已存在普通用户不受注册门禁影响，正常发布评论。
	view, err := svc.Create(ctx, CreateInput{
		SiteID:       siteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "existing@example.com",
		Nickname:     "existing",
		BodyMarkdown: "a comment",
		CaptchaToken: "token",
	})
	if err != nil {
		t.Fatalf("existing user create error = %v, want nil", err)
	}
	if view == nil || view.UserID == 0 {
		t.Fatalf("view = %+v, want a created comment", view)
	}
}

// TestCreateAnonymousAdminEmailRequiresAuthCode 证明已存在管理员邮箱的评论创建
// 返回受控的 ErrAuthorizationRequired，且不校验验证码、不写入资料。
func TestCreateAnonymousAdminEmailRequiresAuthCode(t *testing.T) {
	t.Parallel()

	db := newReplyTestDB(t)
	siteID := seedWidgetDomainSite(t, db)
	ctx := context.Background()
	if err := repository.NewUserRepo(db).Create(ctx, &domain.User{
		Email:           "admin@example.com",
		EmailNormalized: "admin@example.com",
		Nickname:        "admin",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
	}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	captcha := &countingCaptchaVerifier{}
	userW := identity.NewService(identity.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
	})
	svc := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    repository.NewSiteRepo(db),
		Users:    repository.NewUserRepo(db),
		Settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:               domain.CommentModeAnonymous,
			PublicRegistration: false,
			CaptchaPolicy:      map[string]bool{"comment": true},
		}},
		UserW:   userW,
		Captcha: captcha,
	})

	_, err := svc.Create(ctx, CreateInput{
		SiteID:       siteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "ADMIN@example.com",
		Nickname:     "new-name",
		BodyMarkdown: "a comment",
	})
	if !errors.Is(err, domain.ErrAuthorizationRequired) {
		t.Fatalf("error = %v, want ErrAuthorizationRequired", err)
	}
	if captcha.calls != 0 {
		t.Fatalf("CAPTCHA calls = %d, want 0", captcha.calls)
	}
	user, err := repository.NewUserRepo(db).FindByEmailNormalized(ctx, "admin@example.com")
	if err != nil {
		t.Fatalf("find admin: %v", err)
	}
	if user.Nickname != "admin" {
		t.Fatalf("nickname = %q, want unchanged 'admin'", user.Nickname)
	}
}

// adminAuthzResolver 从真实用户仓储解析当前主体，用于两步授权测试。
type adminAuthzResolver struct {
	users *repository.UserRepo
}

func (r adminAuthzResolver) Resolve(ctx context.Context, userID int64) (domain.Principal, error) {
	user, err := r.users.FindByID(ctx, userID)
	if err != nil {
		return domain.Principal{}, err
	}
	return domain.Principal{UserID: user.ID, Role: user.Role, Status: user.Status}, nil
}

// TestAdminAnonymousExchangeIssuesAuthenticatedCredential 证明匿名模式下管理员经
// 显式授权后可把授权码兑换为 widget_authenticated 凭据；签发前管理员被禁用则失败关闭。
func TestAdminAnonymousExchangeIssuesAuthenticatedCredential(t *testing.T) {
	t.Parallel()

	db := newReplyTestDB(t)
	siteID := seedWidgetDomainSite(t, db)
	ctx := context.Background()
	userRepo := repository.NewUserRepo(db)
	admin := &domain.User{
		Email:           "admin@example.com",
		EmailNormalized: "admin@example.com",
		Nickname:        "admin",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
	}
	if err := userRepo.Create(ctx, admin); err != nil {
		t.Fatalf("create admin: %v", err)
	}

	pol := domain.CommentPolicy{
		Mode:               domain.CommentModeAnonymous,
		PublicRegistration: false,
		CaptchaPolicy:      map[string]bool{},
		Epoch:              1,
	}
	svc := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Sites:    repository.NewSiteRepo(db),
		Users:    userRepo,
		Settings: &staticCommentPolicyReader{policy: pol},
		Authz:    adminAuthzResolver{users: userRepo},
		Signer:   widgetDomainTestSigner{},
		Codes:    NewAuthCodeStore(cache.NewMemory(cache.DefaultMemoryLimit)),
	})

	issued, err := svc.IssueAuthorization(ctx, IssueInput{
		SiteID:    siteID,
		Origin:    "https://widget.example.com",
		RequestID: "request-1",
		UserID:    admin.ID,
		Role:      domain.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("issue authorization: %v", err)
	}

	result, err := svc.ExchangeAuthorization(ctx, issued.Code, "https://widget.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if result == nil || result.Token != "widget-token" {
		t.Fatalf("result = %+v, want issued widget-token", result)
	}

	// 授权码已被消费：再次使用会失败。
	if _, err := svc.ExchangeAuthorization(ctx, issued.Code, "https://widget.example.com"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("reuse error = %v, want ErrInvalidCredentials", err)
	}
}

// TestAdminAnonymousExchangeRejectsDemotedPrincipal 证明签发后管理员被禁用，
// 授权码交换失败关闭。
func TestAdminAnonymousExchangeRejectsDemotedPrincipal(t *testing.T) {
	t.Parallel()

	db := newReplyTestDB(t)
	siteID := seedWidgetDomainSite(t, db)
	ctx := context.Background()
	userRepo := repository.NewUserRepo(db)
	admin := &domain.User{
		Email:           "admin@example.com",
		EmailNormalized: "admin@example.com",
		Nickname:        "admin",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
	}
	if err := userRepo.Create(ctx, admin); err != nil {
		t.Fatalf("create admin: %v", err)
	}

	pol := domain.CommentPolicy{
		Mode:          domain.CommentModeAnonymous,
		CaptchaPolicy: map[string]bool{},
		Epoch:         1,
	}
	svc := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Sites:    repository.NewSiteRepo(db),
		Users:    userRepo,
		Settings: &staticCommentPolicyReader{policy: pol},
		Authz:    adminAuthzResolver{users: userRepo},
		Signer:   widgetDomainTestSigner{},
		Codes:    NewAuthCodeStore(cache.NewMemory(cache.DefaultMemoryLimit)),
	})

	issued, err := svc.IssueAuthorization(ctx, IssueInput{
		SiteID:    siteID,
		Origin:    "https://widget.example.com",
		RequestID: "request-2",
		UserID:    admin.ID,
		Role:      domain.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("issue authorization: %v", err)
	}
	if err := userRepo.UpdateRoleStatus(ctx, admin.ID, domain.RoleAdmin, domain.UserStatusDisabled); err != nil {
		t.Fatalf("disable admin: %v", err)
	}
	if _, err := svc.ExchangeAuthorization(ctx, issued.Code, "https://widget.example.com"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("exchange error = %v, want ErrInvalidCredentials", err)
	}
}

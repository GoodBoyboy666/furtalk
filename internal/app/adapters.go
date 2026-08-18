package app

import (
	"context"
	"slices"

	"furtalk/internal/domain"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"furtalk/internal/service/setting"
)

// policyReader 把 setting.Service 适配为 identity.PolicyReader。
type policyReader struct {
	svc *setting.Service
}

// Policy 返回公开注册开关与当前评论模式。
func (a policyReader) Policy(ctx context.Context) (bool, string, error) {
	v, err := a.svc.Get(ctx)
	if err != nil {
		return false, "", err
	}
	return v.Settings.PublicRegistration, v.Settings.CommentMode, nil
}

// EmailPolicy 返回当前邮箱域名名单与 Gravatar 基址。
// 返回的切片是原始数据的拷贝，调用方修改返回值不影响缓存快照。
func (a policyReader) EmailPolicy(ctx context.Context) ([]string, []string, string, error) {
	v, err := a.svc.Get(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	return slices.Clone(v.Settings.EmailDomainWhitelist),
		slices.Clone(v.Settings.EmailDomainBlacklist),
		v.Settings.GravatarBaseURL,
		nil
}

// captchaPolicyReader 把 setting.Service 适配为 identity.CaptchaPolicyReader。
type captchaPolicyReader struct {
	svc *setting.Service
}

// CaptchaPolicy 返回当前 CAPTCHA action 策略映射。
func (a captchaPolicyReader) CaptchaPolicy(ctx context.Context) (map[string]bool, error) {
	v, err := a.svc.Get(ctx)
	if err != nil {
		return nil, err
	}
	return v.Settings.CaptchaPolicy, nil
}

// identityCaptchaVerifier 把共享的 comment.CaptchaGateway 适配为 identity.CaptchaVerifier，
// 并把 platform/captcha 错误映射为 identity 域错误。
type identityCaptchaVerifier struct {
	gateway *comment.CaptchaGateway
}

// Verify 校验给定 action 的 CAPTCHA token，返回 domain 层错误。
func (a identityCaptchaVerifier) Verify(ctx context.Context, action, token string) error {
	return comment.MapError(a.gateway.Verify(ctx, action, token))
}

// oauthProviderReader 把 setting.ProviderService 适配为 identity.OAuthProviderReader。
type oauthProviderReader struct {
	svc *setting.ProviderService
}

// OAuthProviders 列出已启用且已配置的 OAuth/OIDC 提供商。
func (a oauthProviderReader) OAuthProviders(ctx context.Context) ([]identity.AuthProvider, error) {
	return a.svc.AuthProviders(ctx)
}

// OAuthProvider 按 key 返回单个 OAuth/OIDC 提供商的解密配置。
func (a oauthProviderReader) OAuthProvider(ctx context.Context, providerKey string) (*identity.AuthProvider, error) {
	return a.svc.AuthProvider(ctx, providerKey)
}

// commentPolicyReader 把 setting.Service 适配为 comment.SettingsReader。
type commentPolicyReader struct {
	svc *setting.Service
}

// CommentPolicy 返回评论用例所需的动态实例策略映射。
func (a commentPolicyReader) CommentPolicy(ctx context.Context) (domain.CommentPolicy, error) {
	v, err := a.svc.Get(ctx)
	if err != nil {
		return domain.CommentPolicy{}, err
	}
	return domain.CommentPolicy{
		Mode:                 v.Settings.CommentMode,
		Epoch:                v.Epoch,
		Moderation:           v.Settings.Moderation,
		UserDeleteMode:       v.Settings.UserDeleteMode,
		MaxReplyDepth:        v.Settings.MaxReplyDepth,
		PublicRegistration:   v.Settings.PublicRegistration,
		CaptchaPolicy:        v.Settings.CaptchaPolicy,
		EmailDomainWhitelist: slices.Clone(v.Settings.EmailDomainWhitelist),
		EmailDomainBlacklist: slices.Clone(v.Settings.EmailDomainBlacklist),
		GravatarBaseURL:      v.Settings.GravatarBaseURL,
		CommentSort:          v.Settings.CommentSort,
		OwOCatalogURL:        v.Settings.OwOCatalogURL,
		Privacy: domain.PrivacyPolicy{
			IPMode: v.Settings.Privacy.IPMode,
			UAMode: v.Settings.Privacy.UAMode,
		},
	}, nil
}

// captchaGatewayReader 把 setting.ProviderService 当前选择的 CAPTCHA provider 配置
// （含机密）提供给 comment 的动态验证 gateway。
type captchaGatewayReader struct {
	svc *setting.ProviderService
}

// SelectedCaptcha 返回当前选择 CAPTCHA 提供商的解密配置（含机密）。
func (a captchaGatewayReader) SelectedCaptcha(ctx context.Context) (*comment.CaptchaConfig, error) {
	cfg, err := a.svc.SelectedCaptcha(ctx)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &comment.CaptchaConfig{Provider: cfg.Provider, SiteKey: cfg.SiteKey, SecretKey: cfg.SecretKey, Endpoint: cfg.Endpoint}, nil
}

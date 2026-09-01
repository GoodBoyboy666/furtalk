package app

import (
	"context"
	"slices"

	"furtalk/internal/domain"
	servicecaptcha "furtalk/internal/service/captcha"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"furtalk/internal/service/notification"
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

// notificationSettingsReader 把全局设置投影为 notification 的最小开关快照。
type notificationSettingsReader struct {
	svc *setting.Service
}

func (a notificationSettingsReader) NotificationSettings(ctx context.Context) (notification.Settings, error) {
	v, err := a.svc.Get(ctx)
	if err != nil {
		return notification.Settings{}, err
	}
	return notification.Settings{
		Moderation: v.Settings.Notifications.Moderation,
		Replies:    v.Settings.Notifications.Replies,
	}, nil
}

// notificationProviderReader 把解密后的 setting DTO 投影为 notification 通道配置。
type notificationProviderReader struct {
	svc *setting.ProviderService
}

func (a notificationProviderReader) EnabledNotificationProviders(ctx context.Context) ([]notification.ChannelProvider, error) {
	providers, err := a.svc.EnabledNotificationProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]notification.ChannelProvider, 0, len(providers))
	for _, provider := range providers {
		out = append(out, notification.ChannelProvider{
			ProviderKey: provider.ProviderKey,
			Config:      projectNotificationConfig(provider.Config),
		})
	}
	return out, nil
}

func projectNotificationConfig(cfg setting.NotificationConfig) notification.ChannelConfig {
	var signingSecret *string
	if cfg.SigningSecret != nil {
		value := *cfg.SigningSecret
		signingSecret = &value
	}
	return notification.ChannelConfig{
		BotToken:           cfg.BotToken,
		ChatID:             cfg.ChatID,
		WebhookURL:         cfg.WebhookURL,
		ServerURL:          cfg.ServerURL,
		DeviceKey:          cfg.DeviceKey,
		ChannelAccessToken: cfg.ChannelAccessToken,
		TargetID:           cfg.TargetID,
		SigningSecret:      signingSecret,
	}
}

// oauthProviderReader 把 setting.ProviderService 适配为 identity.OAuthProviderReader。
type oauthProviderReader struct {
	svc *setting.ProviderService
}

// OAuthProviders 列出已启用且已配置的 OAuth/OIDC 提供商。
func (a oauthProviderReader) OAuthProviders(ctx context.Context) ([]identity.AuthProvider, error) {
	providers, err := a.svc.AuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]identity.AuthProvider, 0, len(providers))
	for _, provider := range providers {
		out = append(out, projectAuthProvider(provider))
	}
	return out, nil
}

// OAuthProvider 按 key 返回单个 OAuth/OIDC 提供商的解密配置。
func (a oauthProviderReader) OAuthProvider(ctx context.Context, providerKey string) (*identity.AuthProvider, error) {
	provider, err := a.svc.AuthProvider(ctx, providerKey)
	if err != nil || provider == nil {
		return nil, err
	}
	projected := projectAuthProvider(*provider)
	return &projected, nil
}

func projectAuthProvider(provider setting.AuthProvider) identity.AuthProvider {
	return identity.AuthProvider{
		ProviderKey:     provider.ProviderKey,
		Kind:            provider.Kind,
		Enabled:         provider.Enabled,
		Configured:      provider.Configured,
		ClientID:        provider.ClientID,
		ClientSecret:    provider.ClientSecret,
		AuthURL:         provider.AuthURL,
		TokenURL:        provider.TokenURL,
		IssuerURL:       provider.IssuerURL,
		InstanceURL:     provider.InstanceURL,
		AppleTeamID:     provider.AppleTeamID,
		AppleKeyID:      provider.AppleKeyID,
		ApplePrivateKey: provider.ApplePrivateKey,
	}
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
		Mode:               v.Settings.CommentMode,
		Epoch:              v.Epoch,
		Moderation:         v.Settings.Moderation,
		UserDeleteMode:     v.Settings.UserDeleteMode,
		MaxReplyDepth:      v.Settings.MaxReplyDepth,
		PublicRegistration: v.Settings.PublicRegistration,
		CaptchaPolicy:      v.Settings.CaptchaPolicy,
		GravatarBaseURL:    v.Settings.GravatarBaseURL,
		CommentSort:        v.Settings.CommentSort,
		EmojiCatalogURL:    v.Settings.EmojiCatalogURL,
		Privacy: domain.PrivacyPolicy{
			IPMode: v.Settings.Privacy.IPMode,
			UAMode: v.Settings.Privacy.UAMode,
		},
	}, nil
}

// captchaProviderReader 把当前 CAPTCHA provider 投影给共享业务 gateway。
type captchaProviderReader struct {
	svc *setting.ProviderService
}

// SelectedCaptcha 返回当前选择 CAPTCHA 提供商的解密配置（含机密）。
func (a captchaProviderReader) SelectedCaptcha(ctx context.Context) (*servicecaptcha.Config, error) {
	cfg, err := a.svc.SelectedCaptcha(ctx)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &servicecaptcha.Config{Provider: cfg.Provider, SiteKey: cfg.SiteKey, SecretKey: cfg.SecretKey, Endpoint: cfg.Endpoint}, nil
}

// commentCaptchaProviderReader 把当前 CAPTCHA provider 的运行时公开投影提供给 comment。
type commentCaptchaProviderReader struct {
	svc *setting.ProviderService
}

func (a commentCaptchaProviderReader) SelectedCaptcha(ctx context.Context) (*comment.CaptchaConfig, error) {
	cfg, err := a.svc.SelectedCaptcha(ctx)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &comment.CaptchaConfig{Provider: cfg.Provider, SiteKey: cfg.SiteKey, SecretKey: cfg.SecretKey, Endpoint: cfg.Endpoint}, nil
}

// spamProviderReader 把 setting.ProviderService 的垃圾检测 provider 解密配置
// 投影为 comment.SpamProviderConfig。
type spamProviderReader struct {
	svc *setting.ProviderService
}

// EnabledSpamProviders 返回全部已启用垃圾检测 provider 的解密配置。
func (a spamProviderReader) EnabledSpamProviders(ctx context.Context) ([]comment.SpamProviderConfig, error) {
	providers, err := a.svc.EnabledSpamProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]comment.SpamProviderConfig, 0, len(providers))
	for _, p := range providers {
		out = append(out, comment.SpamProviderConfig{
			ProviderKey:     p.ProviderKey,
			Enabled:         p.Enabled,
			Configured:      p.Configured,
			CheckNickname:   p.Config.CheckNickname,
			Action:          p.Config.Action,
			APIKey:          p.Config.APIKey,
			Region:          p.Config.Region,
			BizType:         p.Config.BizType,
			AccessKeyID:     p.Config.AccessKeyID,
			AccessKeySecret: p.Config.AccessKeySecret,
			SecretID:        p.Config.SecretID,
			SecretKey:       p.Config.SecretKey,
		})
	}
	return out, nil
}

package setting

import (
	"context"
	"fmt"
	"strings"

	"furtalk/internal/domain"
	"furtalk/internal/platform/captcha"
)

// maxActionLength 是公共 CAPTCHA 配置查询允许的 action 名最大长度。
const maxActionLength = 64

// PublicCaptchaConfig 单个 action 的公共 CAPTCHA 配置。
type PublicCaptchaConfig struct {
	Required    bool
	Provider    string
	SiteKey     string
	APIEndpoint string
}

// CaptchaConfigService 提供按 action 查询的公共 CAPTCHA 配置。
// 只读：不参与验证决策，业务写端点仍以自身策略为最终权威；
// 通用 action 命名（email_code、password_login、comment 等）不依赖任何 feature 常量。
type CaptchaConfigService struct {
	settings  *Service
	providers *ProviderService
}

// NewCaptchaConfigService 构建公共 CAPTCHA 配置查询服务。
func NewCaptchaConfigService(settings *Service, providers *ProviderService) *CaptchaConfigService {
	return &CaptchaConfigService{settings: settings, providers: providers}
}

// PublicConfig 返回给定 action 的公共 CAPTCHA 配置。
func (s *CaptchaConfigService) PublicConfig(ctx context.Context, action string) (*PublicCaptchaConfig, error) {
	action = strings.TrimSpace(action)
	if action == "" || len(action) > maxActionLength {
		return nil, fmt.Errorf("%w: captcha action must be non-empty and at most %d characters", domain.ErrValidation, maxActionLength)
	}
	view, err := s.settings.Get(ctx)
	if err != nil {
		return nil, err
	}
	if !view.Settings.CaptchaPolicy[action] {
		return &PublicCaptchaConfig{Required: false}, nil
	}
	cfg, err := s.providers.SelectedCaptcha(ctx)
	if err != nil {
		return nil, domain.ErrCaptchaUnavailable
	}
	if cfg == nil {
		return nil, domain.ErrCaptchaUnavailable
	}
	return &PublicCaptchaConfig{
		Required:    true,
		Provider:    cfg.Provider,
		SiteKey:     cfg.SiteKey,
		APIEndpoint: captcha.WidgetAPIURL(captcha.Config{Provider: cfg.Provider, SiteKey: cfg.SiteKey, Endpoint: cfg.Endpoint}),
	}, nil
}

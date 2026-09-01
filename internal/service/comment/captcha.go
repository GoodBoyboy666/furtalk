package comment

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"furtalk/internal/domain"
	pkgcaptcha "furtalk/internal/platform/captcha"
)

// clientTimeout 限定一次提供方 siteverify 请求的耗时。
const clientTimeout = 5 * time.Second

// MapError 把 platform/captcha 的错误分类映射为 comment 语义错误。
func MapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pkgcaptcha.ErrUnavailable):
		return domain.ErrCaptchaUnavailable
	case errors.Is(err, pkgcaptcha.ErrRequired):
		return domain.ErrCaptchaRequired
	default:
		return domain.ErrCaptchaFailed
	}
}

// checkCaptcha 对给定 action 强制执行设置的 CAPTCHA 策略。
func (s *Service) checkCaptcha(ctx context.Context, policy map[string]bool, action, token string) error {
	err := pkgcaptcha.PolicyCheck(ctx, s.captcha, policy, action, token)
	return MapError(err)
}

// CaptchaGateway 动态 CAPTCHA 验证器，每次 Verify 读取当前选择的 provider snapshot。
type CaptchaGateway struct {
	reader CaptchaProviderReader

	mu    sync.Mutex
	cache map[string]pkgcaptcha.Verifier
}

// NewCaptchaGateway 构建动态 CAPTCHA gateway。
func NewCaptchaGateway(reader CaptchaProviderReader) *CaptchaGateway {
	return &CaptchaGateway{reader: reader, cache: make(map[string]pkgcaptcha.Verifier)}
}

// Verify 读取当前选择的 CAPTCHA 提供商配置并校验 token。
func (g *CaptchaGateway) Verify(ctx context.Context, action, token string) error {
	cfg, err := g.reader.SelectedCaptcha(ctx)
	if err != nil {
		if errors.Is(err, domain.ErrProviderNotFound) {
			return fmt.Errorf("%w: no captcha provider configured", pkgcaptcha.ErrUnavailable)
		}
		return fmt.Errorf("%w: read captcha provider: %v", pkgcaptcha.ErrUnavailable, err)
	}
	if cfg == nil {
		return fmt.Errorf("%w: no captcha provider configured", pkgcaptcha.ErrUnavailable)
	}
	verifier, err := g.verifierFor(cfg)
	if err != nil {
		return fmt.Errorf("%w: %v", pkgcaptcha.ErrUnavailable, err)
	}
	return verifier.Verify(ctx, action, token)
}

// verifierFor 返回与给定配置匹配的验证器，按配置指纹缓存。
// 指纹包含 provider、site key、secret 与 endpoint，运行时 endpoint 变更不会复用旧验证器。
func (g *CaptchaGateway) verifierFor(cfg *CaptchaConfig) (pkgcaptcha.Verifier, error) {
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s", cfg.Provider, cfg.SiteKey, cfg.SecretKey, cfg.Endpoint)
	g.mu.Lock()
	defer g.mu.Unlock()
	if verifier, ok := g.cache[key]; ok {
		return verifier, nil
	}
	verifier, err := pkgcaptcha.New(pkgcaptcha.Config{
		Provider:  cfg.Provider,
		SiteKey:   cfg.SiteKey,
		SecretKey: cfg.SecretKey,
		Endpoint:  cfg.Endpoint,
		Timeout:   clientTimeout,
	}, nil)
	if err != nil {
		return nil, err
	}
	g.cache[key] = verifier
	return verifier, nil
}

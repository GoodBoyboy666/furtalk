// Package captcha 提供供各 CAPTCHA 用例共享的动态业务网关。
package captcha

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"furtalk/internal/domain"
	platformcaptcha "furtalk/internal/platform/captcha"
)

const clientTimeout = 5 * time.Second

// Config 是网关使用的已解密 CAPTCHA 提供商配置快照。
type Config struct {
	Provider  string
	SiteKey   string
	SecretKey string
	Endpoint  string
}

// ProviderReader 读取当前选中的已解密 CAPTCHA 提供商配置。
type ProviderReader interface {
	SelectedCaptcha(ctx context.Context) (*Config, error)
}

type verifierFactory func(Config) (platformcaptcha.Verifier, error)

// Gateway 在每次验证时读取当前提供商，并按完整配置指纹缓存平台客户端。
type Gateway struct {
	reader      ProviderReader
	newVerifier verifierFactory

	mu    sync.Mutex
	cache map[string]platformcaptcha.Verifier
}

// NewGateway 构建动态 CAPTCHA 网关。
func NewGateway(reader ProviderReader) *Gateway {
	return &Gateway{
		reader: reader,
		newVerifier: func(cfg Config) (platformcaptcha.Verifier, error) {
			return platformcaptcha.New(platformcaptcha.Config{
				Provider:  cfg.Provider,
				SiteKey:   cfg.SiteKey,
				SecretKey: cfg.SecretKey,
				Endpoint:  cfg.Endpoint,
				Timeout:   clientTimeout,
			}, nil)
		},
		cache: make(map[string]platformcaptcha.Verifier),
	}
}

// Verify 验证 CAPTCHA 令牌并返回领域错误。
func (g *Gateway) Verify(ctx context.Context, action, token string) error {
	if g == nil || g.reader == nil {
		return domain.ErrCaptchaUnavailable
	}
	cfg, err := g.reader.SelectedCaptcha(ctx)
	if err != nil {
		return domain.ErrCaptchaUnavailable
	}
	if cfg == nil {
		return domain.ErrCaptchaUnavailable
	}
	verifier, err := g.verifierFor(cfg)
	if err != nil {
		return domain.ErrCaptchaUnavailable
	}
	return mapError(verifier.Verify(ctx, action, token))
}

// verifierFor 按配置构建或复用 CAPTCHA 验证器。
func (g *Gateway) verifierFor(cfg *Config) (platformcaptcha.Verifier, error) {
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s", cfg.Provider, cfg.SiteKey, cfg.SecretKey, cfg.Endpoint)
	g.mu.Lock()
	defer g.mu.Unlock()
	if verifier, ok := g.cache[key]; ok {
		return verifier, nil
	}
	verifier, err := g.newVerifier(*cfg)
	if err != nil {
		return nil, err
	}
	g.cache[key] = verifier
	return verifier, nil
}

// mapError 将 CAPTCHA 提供商错误映射为领域错误。
func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, platformcaptcha.ErrUnavailable):
		return domain.ErrCaptchaUnavailable
	case errors.Is(err, platformcaptcha.ErrRequired):
		return domain.ErrCaptchaRequired
	default:
		return domain.ErrCaptchaFailed
	}
}

// Package captcha owns the dynamic business gateway shared by CAPTCHA consumers.
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

// Config is the decrypted CAPTCHA provider snapshot consumed by the gateway.
type Config struct {
	Provider  string
	SiteKey   string
	SecretKey string
	Endpoint  string
}

// ProviderReader reads the currently selected, decrypted CAPTCHA provider.
type ProviderReader interface {
	SelectedCaptcha(ctx context.Context) (*Config, error)
}

type verifierFactory func(Config) (platformcaptcha.Verifier, error)

// Gateway re-reads the current provider for every verification and caches
// platform clients by the complete provider configuration fingerprint.
type Gateway struct {
	reader      ProviderReader
	newVerifier verifierFactory

	mu    sync.Mutex
	cache map[string]platformcaptcha.Verifier
}

// NewGateway constructs the shared dynamic CAPTCHA gateway.
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

// Verify resolves the current provider, verifies the token and returns stable
// domain CAPTCHA errors to every consumer.
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

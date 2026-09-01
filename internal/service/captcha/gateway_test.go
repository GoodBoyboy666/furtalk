package captcha

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
	platformcaptcha "furtalk/internal/platform/captcha"
)

type staticReader struct {
	cfg *Config
	err error
}

func (r *staticReader) SelectedCaptcha(context.Context) (*Config, error) {
	return r.cfg, r.err
}

type fakeVerifier struct {
	err error
}

func (v fakeVerifier) Verify(context.Context, string, string) error { return v.err }

func TestGatewayCachesByCompleteConfigFingerprint(t *testing.T) {
	reader := &staticReader{cfg: &Config{Provider: "cap", SiteKey: "site", SecretKey: "secret", Endpoint: "https://one.example.com"}}
	gateway := NewGateway(reader)
	builds := 0
	gateway.newVerifier = func(Config) (platformcaptcha.Verifier, error) {
		builds++
		return fakeVerifier{}, nil
	}

	if err := gateway.Verify(context.Background(), "comment", "token"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := gateway.Verify(context.Background(), "comment", "token"); err != nil {
		t.Fatalf("cached verify: %v", err)
	}
	reader.cfg = &Config{Provider: "cap", SiteKey: "site", SecretKey: "secret", Endpoint: "https://two.example.com"}
	if err := gateway.Verify(context.Background(), "comment", "token"); err != nil {
		t.Fatalf("changed endpoint verify: %v", err)
	}
	if builds != 2 {
		t.Fatalf("verifier builds = %d, want 2", builds)
	}
}

func TestGatewayFailsClosedForProviderErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		reader *staticReader
	}{
		{name: "missing", reader: &staticReader{}},
		{name: "not found", reader: &staticReader{err: domain.ErrProviderNotFound}},
		{name: "read failure", reader: &staticReader{err: errors.New("read failed")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := NewGateway(tt.reader).Verify(context.Background(), "comment", "token"); !errors.Is(err, domain.ErrCaptchaUnavailable) {
				t.Fatalf("error = %v, want ErrCaptchaUnavailable", err)
			}
		})
	}

	gateway := NewGateway(&staticReader{cfg: &Config{Provider: "cap"}})
	gateway.newVerifier = func(Config) (platformcaptcha.Verifier, error) {
		return nil, errors.New("invalid config")
	}
	if err := gateway.Verify(context.Background(), "comment", "token"); !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("factory error = %v, want ErrCaptchaUnavailable", err)
	}
}

func TestGatewayMapsPlatformErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want error
	}{
		{name: "success"},
		{name: "required", err: platformcaptcha.ErrRequired, want: domain.ErrCaptchaRequired},
		{name: "unavailable", err: platformcaptcha.ErrUnavailable, want: domain.ErrCaptchaUnavailable},
		{name: "failed", err: platformcaptcha.ErrFailed, want: domain.ErrCaptchaFailed},
		{name: "unknown", err: errors.New("unknown"), want: domain.ErrCaptchaFailed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gateway := NewGateway(&staticReader{cfg: &Config{Provider: "test"}})
			gateway.newVerifier = func(Config) (platformcaptcha.Verifier, error) {
				return fakeVerifier{err: tt.err}, nil
			}
			err := gateway.Verify(context.Background(), "comment", "token")
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

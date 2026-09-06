package identity

import (
	"context"
	"strings"

	"furtalk/internal/domain"
)

// checkCaptcha 在给定 action 的策略开启时校验 CAPTCHA token。
func (s *Service) checkCaptcha(ctx context.Context, action, token string) error {
	policy, err := s.captchaPolicy.CaptchaPolicy(ctx)
	if err != nil {
		return err
	}
	if !policy[action] {
		return nil
	}
	if s.captcha == nil {
		return domain.ErrCaptchaUnavailable
	}
	if strings.TrimSpace(token) == "" {
		return domain.ErrCaptchaRequired
	}
	return s.captcha.Verify(ctx, action, token)
}

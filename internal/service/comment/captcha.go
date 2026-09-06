package comment

import (
	"context"
	"strings"

	"furtalk/internal/domain"
)

// checkCaptcha 对给定 action 强制执行设置的 CAPTCHA 策略。
func (s *Service) checkCaptcha(ctx context.Context, policy map[string]bool, action, token string) error {
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

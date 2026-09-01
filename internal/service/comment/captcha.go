package comment

import (
	"context"
	"errors"

	"furtalk/internal/domain"
	pkgcaptcha "furtalk/internal/platform/captcha"
)

// mapCaptchaError 把 platform 或共享 gateway 的错误分类映射为 comment 语义错误。
func mapCaptchaError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrCaptchaUnavailable):
		return domain.ErrCaptchaUnavailable
	case errors.Is(err, domain.ErrCaptchaRequired):
		return domain.ErrCaptchaRequired
	case errors.Is(err, domain.ErrCaptchaFailed):
		return domain.ErrCaptchaFailed
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
	return mapCaptchaError(err)
}

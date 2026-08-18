package identity

import (
	"context"
	"strings"

	"furtalk/internal/domain"
)

// checkCaptcha 在给定 action 的策略开启时校验 CAPTCHA token。
// 策略读取错误直接返回；策略关闭时直接放行，不读取 provider 也不要求 token；
// 策略开启时缺少 token、验证器不可用或校验失败分别映射为对应的 CAPTCHA 错误。
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

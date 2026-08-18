package identity

import (
	"context"
	"fmt"

	"furtalk/internal/domain"
	"furtalk/internal/platform/value"
)

// checkEmailDomainAllowed 校验未知邮箱的域名是否被当前名单策略允许注册。
// 白名单非空时仅精确命中白名单；白名单为空时黑名单精确命中则拒绝。
// 拒绝返回明确的 domain.ErrEmailDomainNotAllowed，不伪装成凭据失败。
func (s *Service) checkEmailDomainAllowed(ctx context.Context, normalizedEmail string) error {
	whitelist, blacklist, _, err := s.policy.EmailPolicy(ctx)
	if err != nil {
		return err
	}
	emailDomain, err := value.EmailDomain(normalizedEmail)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	if !value.EmailDomainAllowed(emailDomain, whitelist, blacklist) {
		return domain.ErrEmailDomainNotAllowed
	}
	return nil
}

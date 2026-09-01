package identity

import (
	"context"
	"fmt"
	"strings"

	"furtalk/internal/domain"
)

// checkEmailDomainAllowed 校验未知邮箱的域名是否被当前名单策略允许注册。
// 白名单非空时仅精确命中白名单；白名单为空时黑名单精确命中则拒绝。
// 拒绝返回明确的 domain.ErrEmailDomainNotAllowed，不伪装成凭据失败。
func (s *Service) checkEmailDomainAllowed(ctx context.Context, normalizedEmail string) error {
	if s.policy == nil {
		return domain.ErrUnavailable
	}
	whitelist, blacklist, _, err := s.policy.EmailPolicy(ctx)
	if err != nil {
		return err
	}
	emailDomain, err := emailDomain(normalizedEmail)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	if !emailDomainAllowed(emailDomain, whitelist, blacklist) {
		return domain.ErrEmailDomainNotAllowed
	}
	return nil
}

func emailDomain(normalizedEmail string) (string, error) {
	at := strings.LastIndex(normalizedEmail, "@")
	if at < 0 || at == len(normalizedEmail)-1 {
		return "", domain.ErrValidation
	}
	domainName := strings.ToLower(strings.TrimSpace(normalizedEmail[at+1:]))
	if domainName == "" {
		return "", domain.ErrValidation
	}
	return domainName, nil
}

func emailDomainAllowed(domainName string, whitelist, blacklist []string) bool {
	if len(whitelist) > 0 {
		return containsEmailDomain(whitelist, domainName)
	}
	return !containsEmailDomain(blacklist, domainName)
}

func containsEmailDomain(list []string, domainName string) bool {
	for _, entry := range list {
		if entry == domainName {
			return true
		}
	}
	return false
}

func defaultNickname(normalizedEmail string) string {
	local := strings.SplitN(normalizedEmail, "@", 2)[0]
	if strings.TrimSpace(local) == "" {
		return "user"
	}
	return local
}

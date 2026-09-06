package identity

import (
	"context"
	"fmt"
	"strings"

	"furtalk/internal/domain"
)

// checkEmailDomainAllowed 校验未知邮箱的域名是否被当前名单策略允许注册。
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

// emailDomain 提取邮箱域名。
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

// emailDomainAllowed 检查邮箱域名是否允许。
func emailDomainAllowed(domainName string, whitelist, blacklist []string) bool {
	if len(whitelist) > 0 {
		return containsEmailDomain(whitelist, domainName)
	}
	return !containsEmailDomain(blacklist, domainName)
}

// containsEmailDomain 检查邮箱域名列表是否包含指定域名。
func containsEmailDomain(list []string, domainName string) bool {
	for _, entry := range list {
		if entry == domainName {
			return true
		}
	}
	return false
}

// defaultNickname 根据邮箱生成默认昵称。
func defaultNickname(normalizedEmail string) string {
	local := strings.SplitN(normalizedEmail, "@", 2)[0]
	if strings.TrimSpace(local) == "" {
		return "user"
	}
	return local
}

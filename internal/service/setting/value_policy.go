package setting

import (
	"fmt"
	"strings"

	"furtalk/internal/domain"
	"furtalk/internal/platform/urlx"
)

const defaultGravatarBaseURL = "https://www.gravatar.com/avatar"

// normalizeEmailDomain 规范化单个邮箱域名。
func normalizeEmailDomain(raw string) (string, error) {
	domainName := strings.ToLower(strings.TrimSpace(raw))
	if domainName == "" {
		return "", fmt.Errorf("%w: empty email domain", domain.ErrValidation)
	}
	if strings.ContainsAny(domainName, "@:/\\*") {
		return "", fmt.Errorf("%w: email domain %q contains an invalid character", domain.ErrValidation, domainName)
	}
	if strings.HasPrefix(domainName, ".") || strings.HasSuffix(domainName, ".") || strings.Contains(domainName, "..") {
		return "", fmt.Errorf("%w: email domain %q contains an empty label", domain.ErrValidation, domainName)
	}
	for _, label := range strings.Split(domainName, ".") {
		if !validEmailDomainLabel(label) {
			return "", fmt.Errorf("%w: email domain %q contains an invalid label", domain.ErrValidation, domainName)
		}
	}
	return domainName, nil
}

// normalizeEmailDomains 规范化邮箱域名列表。
func normalizeEmailDomains(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, entry := range raw {
		domainName, err := normalizeEmailDomain(entry)
		if err != nil {
			return nil, err
		}
		if seen[domainName] {
			return nil, fmt.Errorf("%w: duplicate email domain %q", domain.ErrValidation, domainName)
		}
		seen[domainName] = true
		out = append(out, domainName)
	}
	return out, nil
}

// validEmailDomainLabel 校验邮箱域名标签。
func validEmailDomainLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// validateEmojiCatalogURL 校验 Emoji 目录 URL。
func validateEmojiCatalogURL(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	if len(value) > 2048 {
		return fmt.Errorf("%w: emoji catalog url must be at most 2048 characters", domain.ErrValidation)
	}
	u, err := urlx.ParseHTTPS(value)
	if err != nil || u.Fragment != "" {
		return fmt.Errorf("%w: emoji catalog url must be an absolute https url without userinfo or fragment", domain.ErrValidation)
	}
	return nil
}

// normalizePublicHTTPSURL 规范化公开 HTTPS URL。
func normalizePublicHTTPSURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) > 2048 {
		return "", fmt.Errorf("%w: url must be at most 2048 characters", domain.ErrValidation)
	}
	u, err := urlx.ParseHTTPS(value)
	if err != nil {
		return "", fmt.Errorf("%w: url must be an absolute https url without userinfo", domain.ErrValidation)
	}
	return u.String(), nil
}

// validatePublicHTTPSURL 校验公开 HTTPS URL。
func validatePublicHTTPSURL(raw string) error {
	_, err := normalizePublicHTTPSURL(raw)
	return err
}

// normalizeHexColor 规范化十六进制颜色值。
func normalizeHexColor(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) != 7 || value[0] != '#' {
		return "", fmt.Errorf("%w: color must use #RRGGBB format", domain.ErrValidation)
	}
	for _, r := range value[1:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return "", fmt.Errorf("%w: color must use #RRGGBB format", domain.ErrValidation)
		}
	}
	return strings.ToUpper(value), nil
}

// validateHexColor 校验十六进制颜色值。
func validateHexColor(raw string) error {
	_, err := normalizeHexColor(raw)
	return err
}

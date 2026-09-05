package setting

import (
	"fmt"
	"strings"

	"furtalk/internal/domain"
	"furtalk/internal/platform/urlx"
)

const defaultGravatarBaseURL = "https://www.gravatar.com/avatar"

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

func validatePublicHTTPSURL(raw string) error {
	_, err := normalizePublicHTTPSURL(raw)
	return err
}

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

func validateHexColor(raw string) error {
	_, err := normalizeHexColor(raw)
	return err
}

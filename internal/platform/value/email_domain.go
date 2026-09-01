// Package value 邮箱域名名单策略与 Gravatar 头像 URL 的纯函数实现。
// 只依赖标准库；错误语义由使用方 service 层映射为 domain 错误。
package value

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// DefaultGravatarBaseURL Gravatar 头像Base URL的默认值。
const DefaultGravatarBaseURL = "https://www.gravatar.com/avatar"

// NormalizeEmailDomain 格式化并校验单个邮箱域名：
// 忽略首尾空白并转小写；拒绝 @、scheme、path、port、通配符与空标签。
func NormalizeEmailDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	if domain == "" {
		return "", fmt.Errorf("%w: empty email domain", ErrInvalid)
	}
	if strings.ContainsAny(domain, "@:/\\*") {
		return "", fmt.Errorf("%w: email domain %q contains an invalid character", ErrInvalid, domain)
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", fmt.Errorf("%w: email domain %q contains an empty label", ErrInvalid, domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if !validDomainLabel(label) {
			return "", fmt.Errorf("%w: email domain %q contains an invalid label", ErrInvalid, domain)
		}
	}
	return domain, nil
}

// NormalizeEmailDomains 格式化并校验域名列表。
func NormalizeEmailDomains(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, entry := range raw {
		domain, err := NormalizeEmailDomain(entry)
		if err != nil {
			return nil, err
		}
		if seen[domain] {
			return nil, fmt.Errorf("%w: duplicate email domain %q", ErrInvalid, domain)
		}
		seen[domain] = true
		out = append(out, domain)
	}
	return out, nil
}

// validDomainLabel 报告单个 DNS 标签是否合法（小写字母、数字、连字符，不首尾连字符）。
func validDomainLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// EmailDomain 返回格式化邮箱中 @ 之后的完整域名。
func EmailDomain(normalizedEmail string) (string, error) {
	at := strings.LastIndex(normalizedEmail, "@")
	if at < 0 || at == len(normalizedEmail)-1 {
		return "", fmt.Errorf("%w: email has no domain", ErrInvalid)
	}
	domain := strings.ToLower(strings.TrimSpace(normalizedEmail[at+1:]))
	if domain == "" {
		return "", fmt.Errorf("%w: email has no domain", ErrInvalid)
	}
	return domain, nil
}

// EmailDomainAllowed 按名单策略决定域名是否允许注册：
// 白名单非空时仅精确命中白名单（黑名单不参与结果）；白名单为空时黑名单精确命中则拒绝；
// 两者都为空时允许。
func EmailDomainAllowed(domain string, whitelist, blacklist []string) bool {
	if len(whitelist) > 0 {
		return containsDomain(whitelist, domain)
	}
	return !containsDomain(blacklist, domain)
}

func containsDomain(list []string, domain string) bool {
	for _, entry := range list {
		if entry == domain {
			return true
		}
	}
	return false
}

// ValidateGravatarBaseURL 校验 Gravatar Base URL是绝对 http/https URL，
// 且不允许 userinfo、query 或 fragment。
func ValidateGravatarBaseURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: gravatar base url must be an absolute url", ErrInvalid)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: gravatar base url must use http or https", ErrInvalid)
	}
	if u.User != nil {
		return fmt.Errorf("%w: gravatar base url must not include userinfo", ErrInvalid)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("%w: gravatar base url must not include a query", ErrInvalid)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: gravatar base url must not include a fragment", ErrInvalid)
	}
	return nil
}

// GravatarURL 由格式化邮箱与已校验Base URL生成头像 URL：
// 去除Base URL末尾斜杠后追加 / 与 trim+lower 格式化邮箱的 SHA-256 小写十六进制。
func GravatarURL(normalizedEmail, baseURL string) string {
	hash := gravatarHash(normalizedEmail)
	return strings.TrimRight(baseURL, "/") + "/" + hash
}

// gravatarHash 按当前 Gravatar 地址规则计算头像哈希。
func gravatarHash(normalizedEmail string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(normalizedEmail))))
	return hex.EncodeToString(sum[:])
}

// Package value 提供业务无关的值规范化工具。
// 只依赖标准库；错误语义由使用方 service 层映射为 domain 错误。
package value

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"unicode"
)

// ErrInvalid 在输入值不符合规范时返回。
// 使用方按需包装为 domain.ErrValidation 等语义错误。
var ErrInvalid = errors.New("value: invalid")

// NormalizeEmail 返回去除首尾空白的地址及其小写查询形式。
func NormalizeEmail(raw string) (string, string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil || addr.Address == "" {
		return "", "", fmt.Errorf("%w: invalid email", ErrInvalid)
	}
	original := strings.TrimSpace(addr.Address)
	return original, strings.ToLower(original), nil
}

// DefaultNickname 用规范化邮箱的本地部分生成默认昵称。
func DefaultNickname(normalized string) string {
	local := strings.SplitN(normalized, "@", 2)[0]
	if strings.TrimSpace(local) == "" {
		return "user"
	}
	return local
}

// NormalizeWebsite 校验并规范化个人网站 URL，只允许 http 与 https。
func NormalizeWebsite(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: invalid website url", ErrInvalid)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("%w: website url must use http or https", ErrInvalid)
	}
	return u.String(), nil
}

// ValidateEmojiCatalogURL 校验 widget 远程表情目录 URL：
// 空串允许（表示不配置），非空值必须是绝对 HTTPS URL，
// 且不允许 userinfo 或 fragment；query 允许用于版本化/签名目录。
func ValidateEmojiCatalogURL(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	if len(value) > 2048 {
		return fmt.Errorf("%w: emoji catalog url must be at most 2048 characters", ErrInvalid)
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: emoji catalog url must be an absolute https url", ErrInvalid)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: emoji catalog url must use https", ErrInvalid)
	}
	if u.User != nil {
		return fmt.Errorf("%w: emoji catalog url must not include userinfo", ErrInvalid)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: emoji catalog url must not include a fragment", ErrInvalid)
	}
	return nil
}

// NormalizeHTTPSURL trims and validates an optional user-facing HTTPS link.
func NormalizeHTTPSURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) > 2048 {
		return "", fmt.Errorf("%w: url must be at most 2048 characters", ErrInvalid)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: url must not contain control characters", ErrInvalid)
		}
	}
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", fmt.Errorf("%w: url must be an absolute https url", ErrInvalid)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("%w: url must use https", ErrInvalid)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: url must not include userinfo", ErrInvalid)
	}
	return u.String(), nil
}

// ValidateHTTPSURL validates an optional absolute HTTPS URL.
func ValidateHTTPSURL(raw string) error {
	_, err := NormalizeHTTPSURL(raw)
	return err
}

// NormalizeHexColor trims and validates a standard six-digit HEX color.
// Valid values are returned in uppercase for stable persistence and diffs.
func NormalizeHexColor(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len(value) != 7 || value[0] != '#' {
		return "", fmt.Errorf("%w: color must use #RRGGBB format", ErrInvalid)
	}
	for _, r := range value[1:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return "", fmt.Errorf("%w: color must use #RRGGBB format", ErrInvalid)
		}
	}
	return strings.ToUpper(value), nil
}

// ValidateHexColor validates a standard six-digit HEX color.
func ValidateHexColor(raw string) error {
	_, err := NormalizeHexColor(raw)
	return err
}

// Package gravatar 提供不包含产品策略的 Gravatar URL 协议支持。
package gravatar

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"furtalk/internal/platform/urlx"
)

// ErrInvalidBaseURL 表示配置的 Gravatar 基础 URL 无效。
var ErrInvalidBaseURL = errors.New("gravatar: invalid base url")

// ValidateBaseURL 校验 Gravatar 基础 URL。
func ValidateBaseURL(raw string) error {
	if _, err := urlx.ParseHTTPBase(raw); err != nil {
		return fmt.Errorf("%w: must be an absolute url", ErrInvalidBaseURL)
	}
	return nil
}

// URL 根据规范化邮箱生成 Gravatar 头像 URL。
func URL(normalizedEmail, baseURL string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(normalizedEmail))))
	base, err := urlx.ParseHTTPBase(baseURL)
	if err != nil {
		return ""
	}
	return urlx.JoinPathSegments(base, hex.EncodeToString(sum[:])).String()
}

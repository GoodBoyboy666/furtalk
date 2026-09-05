// Package value 提供业务无关的值格式化工具。
// 只依赖标准库；错误语义由使用方 service 层映射为 domain 错误。
package value

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"furtalk/internal/platform/urlx"
)

// ErrInvalid 输入值不符合规范。
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

// NormalizeWebsite 校验并格式化个人网站 URL，只允许 http 与 https。
func NormalizeWebsite(raw string) (string, error) {
	u, err := urlx.ParseHTTP(raw)
	if err != nil {
		return "", fmt.Errorf("%w: invalid website url", ErrInvalid)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("%w: website url must use http or https", ErrInvalid)
	}
	return u.String(), nil
}

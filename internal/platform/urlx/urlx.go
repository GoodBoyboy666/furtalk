// Package urlx 提供后端共享的 URL 语法校验。
package urlx

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// ErrInvalid 包装所有被拒绝的 URL，使用方可以据此保留稳定的错误类别，
// 同时在调试时查看具体的技术原因。
var ErrInvalid = errors.New("urlx: invalid URL")

// ParseHTTP 解析使用 HTTP 或 HTTPS scheme 的绝对 URL。
func ParseHTTP(raw string) (*url.URL, error) {
	u, err := parseAbsolute(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, invalid("scheme must be http or https")
	}
	if u.User != nil {
		return nil, invalid("userinfo is not allowed")
	}
	if err := validateHostPort(u); err != nil {
		return nil, err
	}
	return u, nil
}

// ParseHTTPS 在 ParseHTTP 基础上要求 URL 必须使用 HTTPS scheme。
func ParseHTTPS(raw string) (*url.URL, error) {
	u, err := ParseHTTP(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, invalid("scheme must be https")
	}
	return u, nil
}

// ParseHTTPBase 解析绝对 HTTP(S) Base URL。
func ParseHTTPBase(raw string) (*url.URL, error) {
	trimmed, err := cleanRaw(raw)
	if err != nil {
		return nil, err
	}
	u, err := ParseHTTP(trimmed)
	if err != nil {
		return nil, err
	}
	if u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || strings.Contains(trimmed, "#") {
		return nil, invalid("query and fragment are not allowed in a base URL")
	}
	canonicalizeHost(u)
	trimTrailingPathSeparators(u)
	return u, nil
}

// ParseHTTPSBase 在 ParseHTTPBase 基础上要求 URL 必须使用 HTTPS scheme。
func ParseHTTPSBase(raw string) (*url.URL, error) {
	u, err := ParseHTTPBase(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, invalid("scheme must be https")
	}
	return u, nil
}

// CanonicalOrigin 返回稳定的 Web Origin。
func CanonicalOrigin(raw string) (string, error) {
	trimmed, err := cleanRaw(raw)
	if err != nil {
		return "", err
	}
	u, err := ParseHTTP(trimmed)
	if err != nil {
		return "", err
	}
	if u.Path != "" || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || strings.Contains(trimmed, "#") {
		return "", invalid("path, query and fragment are not allowed in an origin")
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && !isLoopbackHost(host) {
		return "", invalid("http origins are limited to loopback hosts")
	}
	canonicalizeHost(u)
	return u.Scheme + "://" + u.Host, nil
}

// ParseLocalReference 接受同源相对 URL 引用。
func ParseLocalReference(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return nil, invalid("control character is not allowed")
		}
	}
	if strings.Contains(trimmed, `\`) {
		return nil, invalid("backslashes are not allowed")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, invalid("parse: %v", err)
	}
	if u.IsAbs() || u.Host != "" || strings.HasPrefix(trimmed, "//") {
		return nil, invalid("reference must be relative")
	}
	return u, nil
}

// JoinPathSegments 将未预先转义的不透明路径段追加到Base副本。
func JoinPathSegments(base *url.URL, segments ...string) *url.URL {
	if base == nil {
		return nil
	}
	encoded := make([]string, len(segments))
	for i, segment := range segments {
		encoded[i] = escapeSegment(segment)
	}
	return base.JoinPath(encoded...)
}

// JoinPathDirectory 与 JoinPathSegments 相同，但结果会带一个末尾斜杠。
func JoinPathDirectory(base *url.URL, segments ...string) *url.URL {
	u := JoinPathSegments(base, segments...)
	if u == nil {
		return nil
	}
	return u.JoinPath("/")
}

// parseAbsolute 解析并校验绝对 HTTP URL。
func parseAbsolute(raw string) (*url.URL, error) {
	trimmed, err := cleanRaw(raw)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, invalid("parse: %v", err)
	}
	if u.Scheme == "" {
		return nil, invalid("scheme is required")
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, invalid("hostname is required")
	}
	return u, nil
}

// cleanRaw 清理 URL 首尾空白并拒绝控制字符。
func cleanRaw(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", invalid("URL is empty")
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", invalid("control character is not allowed")
		}
	}
	return trimmed, nil
}

// validateHostPort 校验 URL 主机名与端口。
func validateHostPort(u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return invalid("hostname is required")
	}
	if strings.ContainsAny(host, "*\\,\t\r\n ") {
		return invalid("host contains an invalid character")
	}
	_, port, hasPort, err := splitHostPort(u.Host)
	if err != nil {
		return invalid("invalid host or port: %v", err)
	}
	if !hasPort {
		return nil
	}
	if port == "" {
		return invalid("port is empty")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return invalid("port must be between 1 and 65535")
	}
	return nil
}

// splitHostPort 拆分主机与端口并校验地址格式。
func splitHostPort(raw string) (host, port string, hasPort bool, err error) {
	if strings.HasPrefix(raw, "[") {
		close := strings.IndexByte(raw, ']')
		if close < 0 {
			return "", "", false, errors.New("missing closing bracket")
		}
		host = raw[1:close]
		remainder := raw[close+1:]
		if remainder == "" {
			return host, "", false, nil
		}
		if !strings.HasPrefix(remainder, ":") {
			return "", "", false, errors.New("invalid bracketed host")
		}
		return host, remainder[1:], true, nil
	}
	if strings.Count(raw, ":") > 1 {
		return "", "", false, errors.New("IPv6 host must be bracketed")
	}
	if i := strings.LastIndexByte(raw, ':'); i >= 0 {
		return raw[:i], raw[i+1:], true, nil
	}
	return raw, "", false, nil
}

// canonicalizeHost 规范化主机名与默认端口。
func canonicalizeHost(u *url.URL) {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		// splitHostPort 已完成端口格式校验。
		portNumber, _ := strconv.Atoi(port)
		if (u.Scheme == "http" && portNumber == 80) || (u.Scheme == "https" && portNumber == 443) {
			port = ""
		} else {
			port = strconv.Itoa(portNumber)
		}
	}
	if strings.Contains(host, ":") {
		if port == "" {
			u.Host = "[" + host + "]"
		} else {
			u.Host = net.JoinHostPort(host, port)
		}
	} else if port != "" {
		u.Host = host + ":" + port
	} else {
		u.Host = host
	}
}

// trimTrailingPathSeparators 移除基础路径末尾的分隔符。
func trimTrailingPathSeparators(u *url.URL) {
	if u.RawPath != "" {
		rawPath := strings.TrimRight(u.RawPath, "/")
		if rawPath == "/" {
			rawPath = ""
		}
		if rawPath != "" {
			decoded, err := url.PathUnescape(rawPath)
			if err != nil {
				u.RawPath = ""
				u.Path = strings.TrimRight(u.Path, "/")
				return
			}
			u.RawPath, u.Path = rawPath, decoded
			return
		}
		u.RawPath = ""
		u.Path = ""
		return
	}
	u.Path = strings.TrimRight(u.Path, "/")
}

// escapeSegment 转义路径段并保护点路径语义。
func escapeSegment(segment string) string {
	escaped := url.PathEscape(segment)
	// URL.JoinPath 会清理字面量 . 和 .. 路径段。
	// 将其中的点进行百分号编码，可以保持用户输入值的不透明性，同时保留 "v1.2" 这类普通名称中的点。
	if escaped == "." || escaped == ".." {
		escaped = strings.ReplaceAll(escaped, ".", "%2E")
	}
	return escaped
}

// isLoopbackHost 判断主机是否为回环地址。
func isLoopbackHost(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// invalid 创建带有统一错误类别的 URL 错误。
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

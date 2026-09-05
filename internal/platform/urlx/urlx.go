// Package urlx contains the shared URL syntax and construction primitives used
// by the backend. It deliberately does not contain product or provider policy.
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

// ErrInvalid wraps every rejected URL so callers can retain a stable error
// category while still inspecting the technical reason during debugging.
var ErrInvalid = errors.New("urlx: invalid URL")

// ParseHTTP parses an absolute URL using the HTTP or HTTPS scheme. It trims
// outer whitespace, rejects controls, credentials, wildcard hosts, malformed
// ports, and missing hostnames, while retaining path/query/fragment components
// for callers whose protocol permits them.
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

// ParseHTTPS is ParseHTTP with an HTTPS-only scheme requirement.
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

// ParseHTTPBase parses an absolute HTTP(S) base URL. Query and fragment are
// rejected rather than silently discarded. The hostname and default port are
// canonicalized, and trailing literal path separators are removed while
// preserving escaped path semantics.
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

// ParseHTTPSBase is ParseHTTPBase with an HTTPS-only scheme requirement.
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

// CanonicalOrigin returns a stable web origin. HTTPS is accepted generally;
// HTTP is accepted only for localhost and loopback development hosts. All
// path, query, fragment, userinfo, wildcard, and malformed-port components
// are rejected, and hostname casing/default ports are normalized.
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

// ParseLocalReference accepts a same-origin relative URL reference. It rejects
// controls, backslashes, absolute URLs, and network-path references, preventing
// an ostensibly local redirect from changing its origin.
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

// JoinPathSegments appends opaque, unescaped path segments to a cloned base.
// A segment cannot introduce a slash or traversal component. The base URL is
// never modified. The resulting path has no forced trailing slash.
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

// JoinPathDirectory is JoinPathSegments with one trailing slash in the result.
func JoinPathDirectory(base *url.URL, segments ...string) *url.URL {
	u := JoinPathSegments(base, segments...)
	if u == nil {
		return nil
	}
	return u.JoinPath("/")
}

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

func canonicalizeHost(u *url.URL) {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		portNumber, _ := strconv.Atoi(port) // validateHostPort ran before canonicalization.
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

func escapeSegment(segment string) string {
	escaped := url.PathEscape(segment)
	// URL.JoinPath cleans literal . and .. elements. Percent-encoding their
	// dots keeps these user-provided values opaque while preserving ordinary
	// dots in names such as "v1.2".
	if escaped == "." || escaped == ".." {
		escaped = strings.ReplaceAll(escaped, ".", "%2E")
	}
	return escaped
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

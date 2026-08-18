package identity

import "testing"

// TestSanitizeRedirectRejectsCrossSite 验证 OAuth 回调重定向只能落在本站，
// 反斜杠、控制字符、网络路径引用与绝对/跨源目标一律回退到 `/`。
func TestSanitizeRedirectRejectsCrossSite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "absolute http", raw: "https://evil.example.com"},
		{name: "absolute http with path", raw: "http://evil.example.com/path"},
		{name: "absolute http backslash", raw: "https:\\evil.example.com"},
		{name: "absolute other scheme", raw: "javascript:alert(1)"},
		{name: "network path", raw: "//evil.example.com"},
		{name: "network path with path", raw: "//evil.example.com/path"},
		{name: "backslash path", raw: "/\\evil.example.com"},
		{name: "double backslash", raw: "\\evil.example.com"},
		{name: "backslash leading", raw: "\\\\evil.example.com"},
		{name: "backslash in path", raw: "/foo\\bar"},
		{name: "tab in path", raw: "/\tevil.example.com"},
		{name: "newline in path", raw: "/foo\nbar"},
		{name: "carriage return in path", raw: "/foo\rbar"},
		{name: "tab before network path", raw: "\t//evil.example.com"},
		{name: "control char", raw: "/\x01foo"},
		{name: "empty", raw: ""},
		{name: "only whitespace", raw: "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeRedirect(tt.raw); got != "/" {
				t.Fatalf("sanitizeRedirect(%q) = %q, want /", tt.raw, got)
			}
		})
	}
}

// TestSanitizeRedirectKeepsSameSite 验证合法的站内相对路径、锚点与查询引用原样保留。
func TestSanitizeRedirectKeepsSameSite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "root", raw: "/", want: "/"},
		{name: "relative path", raw: "/settings", want: "/settings"},
		{name: "relative path with query", raw: "/settings?tab=profile", want: "/settings?tab=profile"},
		{name: "relative path with fragment", raw: "/threads/1#comment-5", want: "/threads/1#comment-5"},
		{name: "anchor", raw: "#settings", want: "#settings"},
		{name: "query only", raw: "?tab=profile", want: "?tab=profile"},
		{name: "bare relative", raw: "dashboard", want: "dashboard"},
		{name: "parent reference", raw: "..", want: ".."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeRedirect(tt.raw); got != tt.want {
				t.Fatalf("sanitizeRedirect(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

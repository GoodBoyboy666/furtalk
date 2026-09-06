package urlx

import (
	"errors"
	"net/url"
	"testing"
)

func TestParseHTTP(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "http", raw: " http://Example.com/a?x=1#frag ", want: "http://Example.com/a?x=1#frag", ok: true},
		{name: "https ipv6", raw: "https://[2001:db8::1]/v1", want: "https://[2001:db8::1]/v1", ok: true},
		{name: "relative", raw: "/path", ok: false},
		{name: "network path", raw: "//example.com/path", ok: false},
		{name: "non web scheme", raw: "ftp://example.com/file", ok: false},
		{name: "missing host", raw: "https:/path", ok: false},
		{name: "userinfo", raw: "https://user:pass@example.com", ok: false},
		{name: "wildcard", raw: "https://*.example.com", ok: false},
		{name: "comma host", raw: "https://example.com,evil", ok: false},
		{name: "backslash host", raw: `https://example.com\\evil`, ok: false},
		{name: "control", raw: "https://example.com/a\nb", ok: false},
		{name: "empty port", raw: "https://example.com:", ok: false},
		{name: "bad port", raw: "https://example.com:abc", ok: false},
		{name: "port zero", raw: "https://example.com:0", ok: false},
		{name: "port too large", raw: "https://example.com:65536", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseHTTP(tt.raw)
			if tt.ok {
				if err != nil || u.String() != tt.want {
					t.Fatalf("ParseHTTP() = %v, %v; want %q", u, err, tt.want)
				}
			} else if err == nil || !errors.Is(err, ErrInvalid) {
				t.Fatalf("ParseHTTP() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestParseHTTPBase(t *testing.T) {
	tests := []struct {
		raw, want string
		ok        bool
	}{
		{"https://Example.com/installation///", "https://example.com/installation", true},
		{"http://localhost:80/", "http://localhost", true},
		{"https://example.com:00443/", "https://example.com", true},
		{"https://[2001:DB8::1]:443/base/", "https://[2001:db8::1]/base", true},
		{"https://example.com/base?x=1", "", false},
		{"https://example.com/base?", "", false},
		{"https://example.com/base#frag", "", false},
		{"https://example.com/base#", "", false},
		{"https://example.com/a%2Fb/", "https://example.com/a%2Fb", true},
		{"https://example.com/a%2F", "https://example.com/a%2F", true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			u, err := ParseHTTPBase(tt.raw)
			if tt.ok {
				if err != nil || u.String() != tt.want {
					t.Fatalf("ParseHTTPBase() = %v, %v; want %q", u, err, tt.want)
				}
			} else if err == nil {
				t.Fatal("ParseHTTPBase() accepted forbidden component")
			}
		})
	}
}

func TestParseHTTPS(t *testing.T) {
	if _, err := ParseHTTPS("http://localhost"); err == nil {
		t.Fatal("ParseHTTPS accepted HTTP")
	}
	if _, err := ParseHTTPS("https://example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalOrigin(t *testing.T) {
	tests := []struct {
		raw, want string
		ok        bool
	}{
		{" https://Example.COM:443 ", "https://example.com", true},
		{"https://Example.COM:8443", "https://example.com:8443", true},
		{"http://localhost:80", "http://localhost", true},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", true},
		{"http://[::1]:80", "http://[::1]", true},
		{"http://example.com", "", false},
		{"https://example.com/path", "", false},
		{"https://example.com?", "", false},
		{"https://example.com#", "", false},
		{"https://user@example.com", "", false},
		{"https://*.example.com", "", false},
		{"https://example.com:65536", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := CanonicalOrigin(tt.raw)
			if tt.ok {
				if err != nil || got != tt.want {
					t.Fatalf("CanonicalOrigin() = %q, %v; want %q", got, err, tt.want)
				}
			} else if err == nil {
				t.Fatal("CanonicalOrigin() accepted invalid origin")
			}
		})
	}
}

func TestParseLocalReference(t *testing.T) {
	for _, raw := range []string{"/oauth/callback", "?next=1", "#fragment", ""} {
		if _, err := ParseLocalReference(raw); err != nil {
			t.Errorf("ParseLocalReference(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{"https://example.com", "//example.com/path", `\\example.com\\path`, "/a\tb"} {
		if _, err := ParseLocalReference(raw); err == nil {
			t.Errorf("ParseLocalReference(%q) accepted invalid reference", raw)
		}
	}
}

func TestJoinPathSegments(t *testing.T) {
	base, _ := url.Parse("https://example.com/deploy/")
	got := JoinPathSegments(base, "a/b", "..", ".", "100%")
	if want := "https://example.com/deploy/a%2Fb/%2E%2E/%2E/100%25"; got.String() != want {
		t.Fatalf("JoinPathSegments() = %s; want %s", got, want)
	}
	if got := JoinPathDirectory(base, "site key"); got.String() != "https://example.com/deploy/site%20key/" {
		t.Fatalf("JoinPathDirectory() = %s", got)
	}
	if base.String() != "https://example.com/deploy/" {
		t.Fatalf("JoinPathSegments mutated base: %s", base)
	}
}

package value

import (
	"errors"
	"testing"
)

func TestNormalizeEmailDomain(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain", raw: "example.com", want: "example.com"},
		{name: "uppercase", raw: "Example.COM", want: "example.com"},
		{name: "surrounding whitespace", raw: "  example.com  ", want: "example.com"},
		{name: "subdomain", raw: "sub.example.com", want: "sub.example.com"},
		{name: "single label", raw: "localhost", want: "localhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeEmailDomain(tc.raw)
			if err != nil {
				t.Fatalf("NormalizeEmailDomain(%q) error = %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeEmailDomain(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNormalizeEmailDomainRejects(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		"a@b.com",
		"https://example.com",
		"http://example.com",
		"example.com/path",
		"example.com\\path",
		"example.com:8080",
		"*.example.com",
		".example.com",
		"example.com.",
		"example..com",
		"exa mple.com",
		"-example.com",
		"example-.com",
		"exa_mple.com",
	}
	for _, raw := range invalid {
		if _, err := NormalizeEmailDomain(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeEmailDomain(%q) error = %v, want ErrInvalid", raw, err)
		}
	}
}

func TestNormalizeEmailDomainsRejectsDuplicates(t *testing.T) {
	if _, err := NormalizeEmailDomains([]string{"Example.com", "example.com"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate domains error = %v, want ErrInvalid", err)
	}
	if _, err := NormalizeEmailDomains([]string{"example.com", "sub.example.com"}); err != nil {
		t.Fatalf("distinct domains error = %v, want nil", err)
	}
	if got, err := NormalizeEmailDomains([]string{" Example.com "}); err != nil || len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("NormalizeEmailDomains = %v, %v; want [example.com], nil", got, err)
	}
}

func TestEmailDomain(t *testing.T) {
	if got, err := EmailDomain("user@example.com"); err != nil || got != "example.com" {
		t.Fatalf("EmailDomain = %q, %v; want example.com, nil", got, err)
	}
	if _, err := EmailDomain("no-at-sign"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("EmailDomain(no-at-sign) error = %v, want ErrInvalid", err)
	}
	if _, err := EmailDomain("user@"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("EmailDomain(user@) error = %v, want ErrInvalid", err)
	}
}

func TestEmailDomainAllowed(t *testing.T) {
	cases := []struct {
		name      string
		domain    string
		whitelist []string
		blacklist []string
		want      bool
	}{
		{name: "both empty allows", domain: "example.com", want: true},
		{name: "whitelist exact hit", domain: "example.com", whitelist: []string{"example.com"}, want: true},
		{name: "whitelist prefix not matched", domain: "badexample.com", whitelist: []string{"example.com"}, want: false},
		{name: "whitelist subdomain not implied", domain: "sub.example.com", whitelist: []string{"example.com"}, want: false},
		{name: "whitelist ignores blacklist", domain: "blocked.com", whitelist: []string{"example.com"}, blacklist: []string{"blocked.com"}, want: false},
		{name: "whitelist hit beats blacklist", domain: "example.com", whitelist: []string{"example.com"}, blacklist: []string{"example.com"}, want: true},
		{name: "empty whitelist blacklist deny", domain: "blocked.com", blacklist: []string{"blocked.com"}, want: false},
		{name: "empty whitelist blacklist allow other", domain: "ok.com", blacklist: []string{"blocked.com"}, want: true},
		{name: "empty whitelist blacklist prefix not matched", domain: "sub.blocked.com", blacklist: []string{"blocked.com"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EmailDomainAllowed(tc.domain, tc.whitelist, tc.blacklist)
			if got != tc.want {
				t.Fatalf("EmailDomainAllowed(%q, %v, %v) = %v, want %v", tc.domain, tc.whitelist, tc.blacklist, got, tc.want)
			}
		})
	}
}

func TestGravatarURL(t *testing.T) {
	// 官方示例：先 trim/lower 再 SHA-256。
	const wantHash = "84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee"
	if got := GravatarURL("MyEmailAddress@example.com ", "https://www.gravatar.com/avatar"); got != "https://www.gravatar.com/avatar/"+wantHash {
		t.Fatalf("GravatarURL default base = %q", got)
	}
	// 基址带末尾斜杠时去除后再拼接。
	if got := GravatarURL("myemailaddress@example.com", "https://avatars.example.com/avatar/"); got != "https://avatars.example.com/avatar/"+wantHash {
		t.Fatalf("GravatarURL trailing slash base = %q", got)
	}
	// 规范化邮箱大小写不同生成相同哈希。
	if GravatarURL("USER@EXAMPLE.COM", "https://www.gravatar.com/avatar") != GravatarURL("user@example.com", "https://www.gravatar.com/avatar") {
		t.Fatal("GravatarURL must be case-insensitive on the normalized email")
	}
}

func TestValidateGravatarBaseURL(t *testing.T) {
	valid := []string{
		"https://www.gravatar.com/avatar",
		"http://avatars.example.com/avatar",
		"https://avatars.example.com/avatar/",
		"  https://avatars.example.com  ",
	}
	for _, raw := range valid {
		if err := ValidateGravatarBaseURL(raw); err != nil {
			t.Errorf("ValidateGravatarBaseURL(%q) error = %v, want nil", raw, err)
		}
	}
	invalid := []string{
		"",
		"avatars.example.com",
		"/avatar",
		"ftp://avatars.example.com/avatar",
		"https://user:pass@avatars.example.com",
		"https://avatars.example.com/avatar?d=identicon",
		"https://avatars.example.com/avatar#top",
		"javascript:alert(1)",
	}
	for _, raw := range invalid {
		if err := ValidateGravatarBaseURL(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidateGravatarBaseURL(%q) error = %v, want ErrInvalid", raw, err)
		}
	}
}

func TestNormalizeHTTPSURL(t *testing.T) {
	if got, err := NormalizeHTTPSURL(" https://example.com/terms "); err != nil || got != "https://example.com/terms" {
		t.Fatalf("NormalizeHTTPSURL = %q, %v", got, err)
	}
	for _, raw := range []string{"/terms", "http://example.com/terms", "javascript:alert(1)", "https://user:pass@example.com", "https://example.com/terms\nnext"} {
		if err := ValidateHTTPSURL(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidateHTTPSURL(%q) = %v, want ErrInvalid", raw, err)
		}
	}
	if err := ValidateHTTPSURL(""); err != nil {
		t.Fatalf("empty HTTPS URL = %v, want nil", err)
	}
}

func TestNormalizeHexColor(t *testing.T) {
	if got, err := NormalizeHexColor(" #6750a4 "); err != nil || got != "#6750A4" {
		t.Fatalf("NormalizeHexColor = %q, %v", got, err)
	}
	for _, raw := range []string{"", "6750A4", "#12345", "#GGGGGG"} {
		if err := ValidateHexColor(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidateHexColor(%q) = %v, want ErrInvalid", raw, err)
		}
	}
}

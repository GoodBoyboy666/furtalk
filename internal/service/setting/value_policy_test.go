package setting

import (
	"errors"
	"testing"

	"furtalk/internal/domain"
)

func TestNormalizeEmailDomains(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{raw: "example.com", want: "example.com"},
		{raw: " Example.COM ", want: "example.com"},
		{raw: "sub.example.com", want: "sub.example.com"},
		{raw: "localhost", want: "localhost"},
	} {
		got, err := normalizeEmailDomain(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("normalizeEmailDomain(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{"", "a@b.com", "https://example.com", "example.com/path", "example.com:8080", "*.example.com", ".example.com", "example..com", "exa mple.com", "-example.com", "example-.com", "exa_mple.com"} {
		if _, err := normalizeEmailDomain(raw); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("normalizeEmailDomain(%q) = %v", raw, err)
		}
	}
	if _, err := normalizeEmailDomains([]string{"Example.com", "example.com"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("duplicate domains error = %v", err)
	}
	if got, err := normalizeEmailDomains([]string{" Example.com "}); err != nil || len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("normalizeEmailDomains = %v, %v", got, err)
	}
}

func TestSettingURLPolicies(t *testing.T) {
	if got, err := normalizePublicHTTPSURL(" https://example.com/terms "); err != nil || got != "https://example.com/terms" {
		t.Fatalf("normalizePublicHTTPSURL = %q, %v", got, err)
	}
	for _, raw := range []string{"/terms", "http://example.com/terms", "javascript:alert(1)", "https://user:pass@example.com", "https://example.com/terms\nnext"} {
		if err := validatePublicHTTPSURL(raw); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("validatePublicHTTPSURL(%q) = %v", raw, err)
		}
	}
	for _, raw := range []string{"", "https://cdn.example/emoji.json", "https://cdn.example/emoji.json?v=1"} {
		if err := validateEmojiCatalogURL(raw); err != nil {
			t.Errorf("validateEmojiCatalogURL(%q) = %v", raw, err)
		}
	}
	for _, raw := range []string{"http://cdn.example/emoji.json", "https://user@cdn.example/emoji.json", "https://cdn.example/emoji.json#x"} {
		if err := validateEmojiCatalogURL(raw); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("validateEmojiCatalogURL(%q) = %v", raw, err)
		}
	}
}

func TestSettingColorPolicy(t *testing.T) {
	if got, err := normalizeHexColor(" #6750a4 "); err != nil || got != "#6750A4" {
		t.Fatalf("normalizeHexColor = %q, %v", got, err)
	}
	for _, raw := range []string{"", "6750A4", "#12345", "#GGGGGG"} {
		if err := validateHexColor(raw); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("validateHexColor(%q) = %v", raw, err)
		}
	}
}

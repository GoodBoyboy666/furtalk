package value

import (
	"errors"
	"testing"
)

func TestNormalizeWebsiteUsesStrictHTTPURLContract(t *testing.T) {
	if got, err := NormalizeWebsite(" https://example.com/profile?tab=about#bio "); err != nil || got != "https://example.com/profile?tab=about#bio" {
		t.Fatalf("NormalizeWebsite() = %q, %v", got, err)
	}
	for _, raw := range []string{
		"example.com/profile",
		"ftp://example.com/profile",
		"https://user:pass@example.com/profile",
		"https://example.com/profile\nnext",
	} {
		if _, err := NormalizeWebsite(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeWebsite(%q) = %v, want ErrInvalid", raw, err)
		}
	}
}

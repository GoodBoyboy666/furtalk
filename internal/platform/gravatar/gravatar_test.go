package gravatar

import (
	"errors"
	"testing"
)

func TestURL(t *testing.T) {
	const wantHash = "84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee"
	if got := URL("MyEmailAddress@example.com ", "https://www.gravatar.com/avatar"); got != "https://www.gravatar.com/avatar/"+wantHash {
		t.Fatalf("URL = %q", got)
	}
	if URL("USER@EXAMPLE.COM", "https://example.com/avatar/") != URL("user@example.com", "https://example.com/avatar") {
		t.Fatal("URL must normalize email case and a trailing base slash")
	}
}

func TestValidateBaseURL(t *testing.T) {
	for _, raw := range []string{"https://www.gravatar.com/avatar", "http://avatars.example.com/avatar", " https://avatars.example.com/avatar/ "} {
		if err := ValidateBaseURL(raw); err != nil {
			t.Errorf("ValidateBaseURL(%q) = %v", raw, err)
		}
	}
	for _, raw := range []string{"", "avatars.example.com", "ftp://avatars.example.com", "https://user:pass@avatars.example.com", "https://avatars.example.com/avatar?d=x", "https://avatars.example.com/avatar#top"} {
		if err := ValidateBaseURL(raw); !errors.Is(err, ErrInvalidBaseURL) {
			t.Errorf("ValidateBaseURL(%q) = %v", raw, err)
		}
	}
}

package value

import (
	"strings"
	"testing"
)

func TestValidateEmojiCatalogURL(t *testing.T) {
	valid := []string{
		"",
		"   ",
		"https://cdn.example/emoji.json",
		"https://cdn.example/emoji.json?signature=abc",
		"https://sub.example.com/a/b/c.json?version=1",
	}
	for _, raw := range valid {
		if err := ValidateEmojiCatalogURL(raw); err != nil {
			t.Fatalf("ValidateEmojiCatalogURL(%q) error = %v", raw, err)
		}
	}
}

func TestValidateEmojiCatalogURLRejects(t *testing.T) {
	invalid := []string{
		"http://cdn.example/emoji.json",
		"ftp://cdn.example/emoji.json",
		"javascript:alert(1)",
		"//cdn.example/emoji.json",
		"/relative/path.json",
		"https://user:pass@cdn.example/emoji.json",
		"https://cdn.example/emoji.json#fragment",
		"https://cdn.example/emoji.json#frag?q=1",
		"https://cdn.example/" + strings.Repeat("a", 2048) + ".json",
	}
	for _, raw := range invalid {
		if err := ValidateEmojiCatalogURL(raw); err == nil {
			t.Fatalf("ValidateEmojiCatalogURL(%q) accepted invalid value", raw)
		}
	}
}

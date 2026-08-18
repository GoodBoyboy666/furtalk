package value

import (
	"strings"
	"testing"
)

func TestValidateOwOCatalogURL(t *testing.T) {
	valid := []string{
		"",
		"   ",
		"https://cdn.example/owo.json",
		"https://cdn.example/owo.json?signature=abc",
		"https://sub.example.com/a/b/c.json?version=1",
	}
	for _, raw := range valid {
		if err := ValidateOwOCatalogURL(raw); err != nil {
			t.Fatalf("ValidateOwOCatalogURL(%q) error = %v", raw, err)
		}
	}
}

func TestValidateOwOCatalogURLRejects(t *testing.T) {
	invalid := []string{
		"http://cdn.example/owo.json",
		"ftp://cdn.example/owo.json",
		"javascript:alert(1)",
		"//cdn.example/owo.json",
		"/relative/path.json",
		"https://user:pass@cdn.example/owo.json",
		"https://cdn.example/owo.json#fragment",
		"https://cdn.example/owo.json#frag?q=1",
		"https://cdn.example/" + strings.Repeat("a", 2048) + ".json",
	}
	for _, raw := range invalid {
		if err := ValidateOwOCatalogURL(raw); err == nil {
			t.Fatalf("ValidateOwOCatalogURL(%q) accepted invalid value", raw)
		}
	}
}

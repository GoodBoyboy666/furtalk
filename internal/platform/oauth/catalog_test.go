package oauth

import "testing"

// TestCatalogSane 验证固定 provider 目录的完整性与内部一致性。
func TestCatalogSane(t *testing.T) {
	if len(Catalog) != 10 {
		t.Fatalf("catalog size = %d, want 10", len(Catalog))
	}
	seen := make(map[string]bool, len(Catalog))
	for i := range Catalog {
		spec := &Catalog[i]
		if spec.Key == "" || spec.Name == "" {
			t.Fatalf("entry %d must carry key and name: %+v", i, spec)
		}
		if seen[spec.Key] {
			t.Fatalf("duplicate catalog key %q", spec.Key)
		}
		seen[spec.Key] = true
		if spec.Kind != "oauth" && spec.Kind != "oidc" {
			t.Fatalf("provider %q kind = %q, want oauth or oidc", spec.Key, spec.Kind)
		}
		if spec.Registration != RegistrationVerifiedEmail && spec.Registration != RegistrationBindOnly {
			t.Fatalf("provider %q registration = %q, want verified_email or bind_only", spec.Key, spec.Registration)
		}
		if spec.Callback != CallbackQuery && spec.Callback != CallbackFormPost {
			t.Fatalf("provider %q callback = %q, want query or form_post", spec.Key, spec.Callback)
		}
		if len(spec.Config.PublicFields) == 0 {
			t.Fatalf("provider %q must declare public fields", spec.Key)
		}
		if spec.Config.SecretField == "" {
			t.Fatalf("provider %q must declare a secret field", spec.Key)
		}
		for _, field := range spec.Config.PublicFields {
			if field == spec.Config.SecretField {
				t.Fatalf("provider %q leaks secret field %q into public fields", spec.Key, field)
			}
		}
		if spec.Config.InstanceURLRequired && spec.Config.InstanceURLDefault != "" {
			t.Fatalf("provider %q cannot both require and default instance url", spec.Key)
		}
	}
}

// TestCatalogMatrix 验证每个预设的 kind/PKCE/nonce/callback 能力与实例规则。
func TestCatalogMatrix(t *testing.T) {
	matrix := map[string]struct {
		kind         string
		pkce         bool
		nonce        bool
		callback     CallbackMode
		instRequired bool
		instDefault  string
	}{
		"apple":     {kind: "oidc", pkce: false, nonce: true, callback: CallbackFormPost},
		"discord":   {kind: "oauth", pkce: false, nonce: false, callback: CallbackQuery},
		"gitea":     {kind: "oidc", pkce: true, nonce: true, callback: CallbackQuery, instRequired: true},
		"github":    {kind: "oauth", pkce: true, nonce: false, callback: CallbackQuery},
		"gitlab":    {kind: "oidc", pkce: true, nonce: true, callback: CallbackQuery, instDefault: "https://gitlab.com"},
		"google":    {kind: "oidc", pkce: true, nonce: true, callback: CallbackQuery},
		"line":      {kind: "oidc", pkce: true, nonce: true, callback: CallbackQuery},
		"mastodon":  {kind: "oauth", pkce: true, nonce: false, callback: CallbackQuery, instRequired: true},
		"microsoft": {kind: "oidc", pkce: true, nonce: true, callback: CallbackQuery},
		"twitter":   {kind: "oauth", pkce: true, nonce: false, callback: CallbackQuery},
	}
	if len(matrix) != len(Catalog) {
		t.Fatalf("matrix size = %d, want %d", len(matrix), len(Catalog))
	}
	for key, want := range matrix {
		spec, ok := LookupProvider(key)
		if !ok {
			t.Fatalf("provider %q missing from catalog", key)
		}
		if spec.Kind != want.kind || spec.PKCE != want.pkce || spec.Nonce != want.nonce || spec.Callback != want.callback {
			t.Fatalf("provider %q = kind %q pkce %v nonce %v callback %q, want kind %q pkce %v nonce %v callback %q",
				key, spec.Kind, spec.PKCE, spec.Nonce, spec.Callback, want.kind, want.pkce, want.nonce, want.callback)
		}
		if spec.Config.InstanceURLRequired != want.instRequired || spec.Config.InstanceURLDefault != want.instDefault {
			t.Fatalf("provider %q instance rules = required %v default %q, want required %v default %q",
				key, spec.Config.InstanceURLRequired, spec.Config.InstanceURLDefault, want.instRequired, want.instDefault)
		}
	}
}

// TestLookupProvider 验证目录查找：未知 key 不在目录中。
func TestLookupProvider(t *testing.T) {
	if _, ok := LookupProvider("unknown-provider"); ok {
		t.Fatal("unknown provider must not be in the catalog")
	}
	if _, ok := LookupProvider("github"); !ok {
		t.Fatal("github must be in the catalog")
	}
}

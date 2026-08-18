package setting

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/oauth"
)

// validAuthConfigs 返回每个固定预设的最小有效配置。
func validAuthConfigs() map[string]string {
	return map[string]string{
		"apple":     `{"client_id":"c","team_id":"team","key_id":"key","private_key":"pk"}`,
		"discord":   `{"client_id":"c","client_secret":"s"}`,
		"gitea":     `{"client_id":"c","client_secret":"s","instance_url":"https://gitea.example.com"}`,
		"github":    `{"client_id":"c","client_secret":"s"}`,
		"gitlab":    `{"client_id":"c","client_secret":"s"}`,
		"google":    `{"client_id":"c","client_secret":"s"}`,
		"line":      `{"client_id":"c","client_secret":"s"}`,
		"mastodon":  `{"client_id":"c","client_secret":"s","instance_url":"https://mastodon.example.com"}`,
		"microsoft": `{"client_id":"c","client_secret":"s"}`,
		"twitter":   `{"client_id":"c","client_secret":"s"}`,
	}
}

// catalogKind 返回预设要求的 kind。
func catalogKind(key string) domain.ProviderKind {
	spec, ok := oauth.LookupProvider(key)
	if !ok {
		return ""
	}
	return domain.ProviderKind(spec.Kind)
}

// TestUpsertAuthCatalogKeyKindMatrix 验证固定预设的 key/kind 矩阵：
// 每个预设只接受其目录 kind，错误 kind 在持久化前被拒绝；
// 未知 key 只允许自定义 OIDC。
func TestUpsertAuthCatalogKeyKindMatrix(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	configs := validAuthConfigs()
	for key, conf := range configs {
		kind := catalogKind(key)
		t.Run(key+" correct kind", func(t *testing.T) {
			if err := providers.UpsertAuth(ctx, key, kind, true, json.RawMessage(conf)); err != nil {
				t.Fatalf("UpsertAuth(%q, %q) = %v, want nil", key, kind, err)
			}
		})
		wrong := domain.ProviderKindOIDC
		if kind == domain.ProviderKindOIDC {
			wrong = domain.ProviderKindOAuth
		}
		t.Run(key+" wrong kind", func(t *testing.T) {
			if err := providers.UpsertAuth(ctx, key, wrong, true, json.RawMessage(conf)); !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("UpsertAuth(%q, %q) error = %v, want ErrValidation", key, wrong, err)
			}
		})
	}

	// 自定义 OAuth 拒绝、自定义 OIDC 接受。
	if err := providers.UpsertAuth(ctx, "my-custom", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"c","client_secret":"s"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("custom oauth error = %v, want ErrValidation", err)
	}
	if err := providers.UpsertAuth(ctx, "my-custom", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"c","client_secret":"s","issuer_url":"https://issuer.example.com"}`)); err != nil {
		t.Fatalf("custom oidc = %v, want nil", err)
	}
}

// TestUpsertAuthInstanceURLRules 验证实例地址规范化规则：
// gitlab 默认 https://gitlab.com 且可替换；gitea/mastodon 必填；
// 子路径保留、查询/片段/userinfo 拒绝、http 拒绝；mastodon 禁止子路径。
func TestUpsertAuthInstanceURLRules(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	// gitlab 留空使用默认实例。
	if err := providers.UpsertAuth(ctx, "gitlab", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"c","client_secret":"s"}`)); err != nil {
		t.Fatalf("gitlab default instance: %v", err)
	}
	gitlab, err := providers.AuthProvider(ctx, "gitlab")
	if err != nil {
		t.Fatalf("get gitlab: %v", err)
	}
	if gitlab.InstanceURL != "https://gitlab.com" {
		t.Fatalf("gitlab instance = %q, want https://gitlab.com", gitlab.InstanceURL)
	}

	// gitlab 显式子路径保留且规范化（主机小写、去默认端口与尾部斜杠）。
	if err := providers.UpsertAuth(ctx, "gitlab", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"c","client_secret":"s","instance_url":"https://GitLab.Example.com:443/gitlab/"}`)); err != nil {
		t.Fatalf("gitlab subpath instance: %v", err)
	}
	gitlab, err = providers.AuthProvider(ctx, "gitlab")
	if err != nil {
		t.Fatalf("get gitlab after subpath: %v", err)
	}
	if gitlab.InstanceURL != "https://gitlab.example.com/gitlab" {
		t.Fatalf("gitlab subpath instance = %q, want https://gitlab.example.com/gitlab", gitlab.InstanceURL)
	}

	// gitea/mastodon 必须显式提供实例地址。
	for _, key := range []string{"gitea", "mastodon"} {
		kind := catalogKind(key)
		if err := providers.UpsertAuth(ctx, key, kind, true,
			json.RawMessage(`{"client_id":"c","client_secret":"s"}`)); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("%s without instance error = %v, want ErrValidation", key, err)
		}
	}

	// 非法实例地址一律拒绝。
	invalid := []string{
		"http://gitea.example.com",
		"https://gitea.example.com?x=1",
		"https://gitea.example.com#frag",
		"https://user:pass@gitea.example.com",
		"gitea.example.com",
		"ftp://gitea.example.com",
	}
	for _, raw := range invalid {
		if err := providers.UpsertAuth(ctx, "gitea", domain.ProviderKindOIDC, true,
			json.RawMessage(`{"client_id":"c","client_secret":"s","instance_url":"`+raw+`"}`)); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("gitea instance %q error = %v, want ErrValidation", raw, err)
		}
	}

	// mastodon 禁止部署子路径。
	if err := providers.UpsertAuth(ctx, "mastodon", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"c","client_secret":"s","instance_url":"https://mastodon.example.com/social"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("mastodon subpath error = %v, want ErrValidation", err)
	}

	// mastodon 根 origin 成功。
	if err := providers.UpsertAuth(ctx, "mastodon", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"c","client_secret":"s","instance_url":"https://mastodon.example.com/"}`)); err != nil {
		t.Fatalf("mastodon root origin: %v", err)
	}
	mastodon, err := providers.AuthProvider(ctx, "mastodon")
	if err != nil {
		t.Fatalf("get mastodon: %v", err)
	}
	if mastodon.InstanceURL != "https://mastodon.example.com" {
		t.Fatalf("mastodon instance = %q, want https://mastodon.example.com", mastodon.InstanceURL)
	}
}

// TestUpsertAuthPublicSecretSplitting 验证每个预设的公开/机密拆分：
// public_config 只含目录公开字段且永不包含机密；解密往返保留全部字段。
func TestUpsertAuthPublicSecretSplitting(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	for key, conf := range validAuthConfigs() {
		kind := catalogKind(key)
		t.Run(key, func(t *testing.T) {
			if err := providers.UpsertAuth(ctx, key, kind, true, json.RawMessage(conf)); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			metas, err := providers.List(ctx)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			spec, ok := oauth.LookupProvider(key)
			if !ok {
				t.Fatal("preset must be in catalog")
			}
			var found *ProviderMeta
			for i := range metas {
				if metas[i].ProviderKey == key {
					found = &metas[i]
				}
			}
			if found == nil {
				t.Fatalf("provider %q missing from list", key)
			}
			var public map[string]any
			if err := json.Unmarshal(found.PublicConfig, &public); err != nil {
				t.Fatalf("decode public: %v", err)
			}
			if _, leaked := public[spec.Config.SecretField]; leaked {
				t.Fatalf("secret field %q leaked into public config: %v", spec.Config.SecretField, public)
			}
			for _, field := range spec.Config.PublicFields {
				if _, present := public[field]; !present {
					t.Fatalf("public field %q missing from public config: %v", field, public)
				}
			}
			provider, err := providers.AuthProvider(ctx, key)
			if err != nil {
				t.Fatalf("get provider: %v", err)
			}
			if provider.ClientID != "c" {
				t.Fatalf("client id = %q, want c", provider.ClientID)
			}
		})
	}
}

// TestUpsertAuthSecretPreservationCatalog 验证机密更新契约（github 的 client_secret 与
// apple 的 private_key 使用同一套语义）：新建必须提供机密；编辑缺省/空机密原样复用现有
// envelope（字节级一致）；非空机密才替换；无现有 envelope 且无新机密返回 validation。
func TestUpsertAuthSecretPreservationCatalog(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	for key, secretField := range map[string]string{
		"github": "client_secret",
		"apple":  "private_key",
	} {
		kind := catalogKind(key)
		t.Run(key+" create requires secret", func(t *testing.T) {
			conf := `{"client_id":"c"}`
			if key == "apple" {
				conf = `{"client_id":"c","team_id":"team","key_id":"key"}`
			}
			if err := providers.UpsertAuth(ctx, key, kind, true, json.RawMessage(conf)); !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("create without secret error = %v, want ErrValidation", err)
			}
		})
		t.Run(key+" blank keeps envelope", func(t *testing.T) {
			if err := providers.UpsertAuth(ctx, key, kind, true, json.RawMessage(validAuthConfigs()[key])); err != nil {
				t.Fatalf("create: %v", err)
			}
			before, err := providers.settings.GetAuthProvider(ctx, key)
			if err != nil {
				t.Fatalf("get row: %v", err)
			}
			var edit map[string]any
			if err := json.Unmarshal([]byte(validAuthConfigs()[key]), &edit); err != nil {
				t.Fatal(err)
			}
			delete(edit, secretField)
			edit["client_id"] = "updated-id"
			editJSON, err := json.Marshal(edit)
			if err != nil {
				t.Fatal(err)
			}
			if err := providers.UpsertAuth(ctx, key, kind, true, editJSON); err != nil {
				t.Fatalf("edit without secret: %v", err)
			}
			after, err := providers.settings.GetAuthProvider(ctx, key)
			if err != nil {
				t.Fatalf("get row after edit: %v", err)
			}
			if !reflect.DeepEqual(after.SecretCiphertext, before.SecretCiphertext) || !reflect.DeepEqual(after.SecretNonce, before.SecretNonce) {
				t.Fatal("envelope bytes must be preserved byte-for-byte on blank secret edit")
			}
			provider, err := providers.AuthProvider(ctx, key)
			if err != nil {
				t.Fatalf("get provider: %v", err)
			}
			if provider.ClientID != "updated-id" {
				t.Fatalf("client id = %q, want updated-id", provider.ClientID)
			}
		})
		t.Run(key+" empty string keeps envelope", func(t *testing.T) {
			before, err := providers.settings.GetAuthProvider(ctx, key)
			if err != nil {
				t.Fatalf("get row: %v", err)
			}
			var edit map[string]any
			if err := json.Unmarshal([]byte(validAuthConfigs()[key]), &edit); err != nil {
				t.Fatal(err)
			}
			edit[secretField] = ""
			editJSON, err := json.Marshal(edit)
			if err != nil {
				t.Fatal(err)
			}
			if err := providers.UpsertAuth(ctx, key, kind, true, editJSON); err != nil {
				t.Fatalf("edit with empty secret: %v", err)
			}
			after, err := providers.settings.GetAuthProvider(ctx, key)
			if err != nil {
				t.Fatalf("get row after empty edit: %v", err)
			}
			if !reflect.DeepEqual(after.SecretCiphertext, before.SecretCiphertext) || !reflect.DeepEqual(after.SecretNonce, before.SecretNonce) {
				t.Fatal("envelope bytes must be preserved on empty secret edit")
			}
		})
		t.Run(key+" replacement", func(t *testing.T) {
			var edit map[string]any
			if err := json.Unmarshal([]byte(validAuthConfigs()[key]), &edit); err != nil {
				t.Fatal(err)
			}
			edit[secretField] = "second-secret"
			editJSON, err := json.Marshal(edit)
			if err != nil {
				t.Fatal(err)
			}
			if err := providers.UpsertAuth(ctx, key, kind, true, editJSON); err != nil {
				t.Fatalf("edit with new secret: %v", err)
			}
			provider, err := providers.AuthProvider(ctx, key)
			if err != nil {
				t.Fatalf("get provider: %v", err)
			}
			got := provider.ClientSecret
			if secretField == "private_key" {
				got = provider.ApplePrivateKey
			}
			if got != "second-secret" {
				t.Fatalf("%s = %q, want second-secret", secretField, got)
			}
		})
	}
}

// TestUpsertAuthAppleAtomicPair 验证 Apple 的 key_id 与 private_key 原子对规则：
// 提供新私钥时必须同时提供 key_id；公开字段编辑可保留空私钥。
func TestUpsertAuthAppleAtomicPair(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	// 创建：有私钥无 key_id 拒绝。
	if err := providers.UpsertAuth(ctx, "apple", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"c","team_id":"team","private_key":"pk"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("create private key without key id error = %v, want ErrValidation", err)
	}

	// 创建成功。
	if err := providers.UpsertAuth(ctx, "apple", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"c","team_id":"team","key_id":"key","private_key":"pk"}`)); err != nil {
		t.Fatalf("create apple: %v", err)
	}

	// 编辑：新私钥但缺 key_id 拒绝。
	if err := providers.UpsertAuth(ctx, "apple", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"c","team_id":"team","private_key":"new-pk"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("edit new private key without key id error = %v, want ErrValidation", err)
	}

	// 编辑：缺省私钥保留 envelope，key_id 可随公开字段往返。
	before, err := providers.settings.GetAuthProvider(ctx, "apple")
	if err != nil {
		t.Fatalf("get row: %v", err)
	}
	if err := providers.UpsertAuth(ctx, "apple", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"updated","team_id":"team","key_id":"key"}`)); err != nil {
		t.Fatalf("edit without private key: %v", err)
	}
	after, err := providers.settings.GetAuthProvider(ctx, "apple")
	if err != nil {
		t.Fatalf("get row after edit: %v", err)
	}
	if !reflect.DeepEqual(after.SecretCiphertext, before.SecretCiphertext) {
		t.Fatal("apple envelope must be preserved when private key is omitted")
	}
	provider, err := providers.AuthProvider(ctx, "apple")
	if err != nil {
		t.Fatalf("get provider: %v", err)
	}
	if provider.ApplePrivateKey != "pk" {
		t.Fatalf("apple private key = %q, want preserved pk", provider.ApplePrivateKey)
	}
	if provider.AppleTeamID != "team" || provider.AppleKeyID != "key" || provider.ClientID != "updated" {
		t.Fatalf("apple public fields round trip failed: %+v", provider)
	}

	// 编辑：新私钥 + key_id 原子替换。
	if err := providers.UpsertAuth(ctx, "apple", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"updated","team_id":"team","key_id":"key-2","private_key":"pk-2"}`)); err != nil {
		t.Fatalf("rotate apple pair: %v", err)
	}
	provider, err = providers.AuthProvider(ctx, "apple")
	if err != nil {
		t.Fatalf("get provider after rotation: %v", err)
	}
	if provider.AppleKeyID != "key-2" || provider.ApplePrivateKey != "pk-2" {
		t.Fatalf("apple pair rotation = key %q private %q, want key-2/pk-2", provider.AppleKeyID, provider.ApplePrivateKey)
	}
}

// TestUpsertAuthRejectsUnknownFields 验证 auth 配置严格解码拒绝未知字段。
func TestUpsertAuthRejectsUnknownFields(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	for _, conf := range []string{
		`{"client_id":"c","client_secret":"s","enabled":true}`,
		`{"client_id":"c","client_secret":"s","bogus_field":"x"}`,
		`{"client_id":"c","client_secret":"s"} trailing`,
	} {
		if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true, json.RawMessage(conf)); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("config %q error = %v, want ErrValidation", conf, err)
		}
	}
}

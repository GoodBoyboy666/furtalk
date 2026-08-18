package setting

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/oauth"
)

// TestUpsertAuthKeyKindMatrix 验证 OAuth/OIDC 的 key/kind 支持矩阵在持久化前强制：
// github→oauth、google→oidc、自定义 key→oidc；其余组合一律拒绝。
func TestUpsertAuthKeyKindMatrix(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	valid := []struct {
		name string
		key  string
		kind domain.ProviderKind
		conf string
	}{
		{name: "github oauth", key: "github", kind: domain.ProviderKindOAuth, conf: `{"client_id":"c","client_secret":"s"}`},
		{name: "google oidc", key: "google", kind: domain.ProviderKindOIDC, conf: `{"client_id":"c","client_secret":"s"}`},
		{name: "custom oidc", key: "my-oidc", kind: domain.ProviderKindOIDC, conf: `{"client_id":"c","client_secret":"s","issuer_url":"https://issuer.example.com"}`},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			if err := providers.UpsertAuth(ctx, tc.key, tc.kind, true, json.RawMessage(tc.conf)); err != nil {
				t.Fatalf("UpsertAuth(%q, %q) = %v, want nil", tc.key, tc.kind, err)
			}
		})
	}

	invalid := []struct {
		name string
		key  string
		kind domain.ProviderKind
		conf string
	}{
		{name: "github oidc", key: "github", kind: domain.ProviderKindOIDC, conf: `{"client_id":"c","client_secret":"s","issuer_url":"https://issuer.example.com"}`},
		{name: "google oauth", key: "google", kind: domain.ProviderKindOAuth, conf: `{"client_id":"c","client_secret":"s"}`},
		{name: "custom oauth", key: "custom", kind: domain.ProviderKindOAuth, conf: `{"client_id":"c","client_secret":"s"}`},
		{name: "unknown kind", key: "x", kind: domain.ProviderKindCaptcha, conf: `{"client_id":"c"}`},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			err := providers.UpsertAuth(ctx, tc.key, tc.kind, true, json.RawMessage(tc.conf))
			if !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("UpsertAuth(%q, %q) error = %v, want ErrValidation", tc.key, tc.kind, err)
			}
		})
	}
}

// TestUpsertAuthPresetEndpoints 验证 GitHub/Google 预设锁定端点/Issuer，
// 管理员提交的端点或 Issuer 被固定预设覆盖（值来自 provider catalog）。
func TestUpsertAuthPresetEndpoints(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"c","client_secret":"s","auth_url":"https://evil.example","token_url":"https://evil.example"}`)); err != nil {
		t.Fatalf("upsert github: %v", err)
	}
	github, err := providers.AuthProvider(ctx, "github")
	if err != nil {
		t.Fatalf("get github: %v", err)
	}
	githubSpec, ok := oauth.LookupProvider("github")
	if !ok {
		t.Fatal("github must be in the provider catalog")
	}
	if github.AuthURL != githubSpec.Config.FixedPublic["auth_url"] || github.TokenURL != githubSpec.Config.FixedPublic["token_url"] {
		t.Fatalf("github endpoints = %q/%q, want preset %q/%q", github.AuthURL, github.TokenURL, githubSpec.Config.FixedPublic["auth_url"], githubSpec.Config.FixedPublic["token_url"])
	}

	if err := providers.UpsertAuth(ctx, "google", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"c","client_secret":"s","issuer_url":"https://evil.example.com"}`)); err != nil {
		t.Fatalf("upsert google: %v", err)
	}
	google, err := providers.AuthProvider(ctx, "google")
	if err != nil {
		t.Fatalf("get google: %v", err)
	}
	googleSpec, ok := oauth.LookupProvider("google")
	if !ok {
		t.Fatal("google must be in the provider catalog")
	}
	if google.IssuerURL != googleSpec.Config.FixedPublic["issuer_url"] {
		t.Fatalf("google issuer = %q, want preset %q", google.IssuerURL, googleSpec.Config.FixedPublic["issuer_url"])
	}
}

// TestUpsertAuthCustomOIDCRequiresHTTPSIssuer 验证自定义 OIDC 必须提供 HTTPS Issuer。
func TestUpsertAuthCustomOIDCRequiresHTTPSIssuer(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	for _, conf := range []string{
		`{"client_id":"c","client_secret":"s"}`,
		`{"client_id":"c","client_secret":"s","issuer_url":"http://issuer.example.com"}`,
		`{"client_id":"c","client_secret":"s","issuer_url":"issuer.example.com"}`,
	} {
		if err := providers.UpsertAuth(ctx, "my-oidc", domain.ProviderKindOIDC, true, json.RawMessage(conf)); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("custom oidc %s error = %v, want ErrValidation", conf, err)
		}
	}
}

// TestUpsertAuthSecretPreservation 验证 Secret 更新契约：
// 新建必须提供 secret；编辑缺省/空 secret 原样复用现有 envelope；非空 secret 才替换；
// 无现有 envelope 且无新 secret 返回 validation。
func TestUpsertAuthSecretPreservation(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	// 新建无 secret 被拒绝。
	if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"c"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("create without secret error = %v, want ErrValidation", err)
	}

	// 新建带 secret 成功。
	if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"c","client_secret":"first-secret"}`)); err != nil {
		t.Fatalf("create with secret: %v", err)
	}

	// 编辑缺省 secret：public 字段更新但 Secret 保留。
	if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"updated-id"}`)); err != nil {
		t.Fatalf("edit without secret: %v", err)
	}
	provider, err := providers.AuthProvider(ctx, "github")
	if err != nil {
		t.Fatalf("get github: %v", err)
	}
	if provider.ClientID != "updated-id" {
		t.Fatalf("client id = %q, want updated-id", provider.ClientID)
	}
	if provider.ClientSecret != "first-secret" {
		t.Fatalf("client secret = %q, want preserved first-secret", provider.ClientSecret)
	}

	// 编辑空 secret：同样保留。
	if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"updated-id","client_secret":""}`)); err != nil {
		t.Fatalf("edit with empty secret: %v", err)
	}
	provider, err = providers.AuthProvider(ctx, "github")
	if err != nil {
		t.Fatalf("get github after empty secret: %v", err)
	}
	if provider.ClientSecret != "first-secret" {
		t.Fatalf("client secret = %q, want still preserved", provider.ClientSecret)
	}

	// 编辑非空 secret：替换 envelope。
	if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true,
		json.RawMessage(`{"client_id":"updated-id","client_secret":"second-secret"}`)); err != nil {
		t.Fatalf("edit with new secret: %v", err)
	}
	provider, err = providers.AuthProvider(ctx, "github")
	if err != nil {
		t.Fatalf("get github after replace: %v", err)
	}
	if provider.ClientSecret != "second-secret" {
		t.Fatalf("client secret = %q, want second-secret", provider.ClientSecret)
	}
}

// TestUpsertAuthUpdateEnabledOnly 验证只翻转 enabled 时保留现有 envelope。
func TestUpsertAuthUpdateEnabledOnly(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	if err := providers.UpsertAuth(ctx, "google", domain.ProviderKindOIDC, false,
		json.RawMessage(`{"client_id":"c","client_secret":"keep-secret"}`)); err != nil {
		t.Fatalf("create google: %v", err)
	}
	if err := providers.UpsertAuth(ctx, "google", domain.ProviderKindOIDC, true,
		json.RawMessage(`{"client_id":"c"}`)); err != nil {
		t.Fatalf("toggle enabled: %v", err)
	}
	provider, err := providers.AuthProvider(ctx, "google")
	if err != nil {
		t.Fatalf("get google: %v", err)
	}
	if !provider.Enabled {
		t.Fatalf("google enabled = false, want true")
	}
	if provider.ClientSecret != "keep-secret" {
		t.Fatalf("client secret = %q, want preserved keep-secret", provider.ClientSecret)
	}
}

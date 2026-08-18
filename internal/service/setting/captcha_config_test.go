package setting

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
)

// newTestProviderService 打开临时 SQLite 数据库并构建设置与提供商服务，选择校验已互接。
func newTestProviderService(t *testing.T) (*Service, *ProviderService) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "providers-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.DynamicSetting{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	svc := NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	providers := NewProviderService(gormtx.NewRunner(db), repository.NewSettingsRepo(db), []byte("test-master-key-0123456789abcdef"))
	svc.SetCaptchaValidator(providers)
	providers.SetSettingsInvalidator(svc.Invalidate)
	return svc, providers
}

// selectCaptchaProvider 通过设置 PATCH 选择 CAPTCHA provider。
func selectCaptchaProvider(t *testing.T, svc *Service, providerKey string) {
	t.Helper()
	if _, err := svc.Patch(context.Background(), []SettingItem{
		{Key: SettingKeyCaptchaProvider, Type: SettingTypeString, Value: providerKey},
	}, 1); err != nil {
		t.Fatalf("select captcha %q: %v", providerKey, err)
	}
}

// TestCaptchaCAPEndpointRoundTrip 验证 CAP 配置的 endpoint 规范化、公开存储与解密往返。
func TestCaptchaCAPEndpointRoundTrip(t *testing.T) {
	svc, providers := newTestProviderService(t)
	ctx := context.Background()

	config, err := json.Marshal(map[string]any{
		"provider":   "cap",
		"site_key":   "site-123",
		"secret_key": "cap-secret",
		"endpoint":   "https://cap.example.com/standalone/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := providers.UpsertCaptcha(ctx, "cap", config); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	selectCaptchaProvider(t, svc, "cap")

	cfg, err := providers.SelectedCaptcha(ctx)
	if err != nil {
		t.Fatalf("selected captcha: %v", err)
	}
	if cfg.Endpoint != "https://cap.example.com/standalone" {
		t.Fatalf("endpoint = %q, want normalized without trailing slash", cfg.Endpoint)
	}
	if cfg.SecretKey != "cap-secret" || cfg.SiteKey != "site-123" {
		t.Fatalf("round-trip mismatch: %+v", cfg)
	}

	// 公开元数据必须暴露 endpoint 而不含 secret。
	metas, err := providers.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("provider count = %d, want 1", len(metas))
	}
	if metas[0].Kind != domain.ProviderKindCaptcha {
		t.Fatalf("kind = %q, want captcha", metas[0].Kind)
	}
	var public map[string]any
	if err := json.Unmarshal(metas[0].PublicConfig, &public); err != nil {
		t.Fatalf("decode public config: %v", err)
	}
	if public["endpoint"] != "https://cap.example.com/standalone" {
		t.Fatalf("public endpoint = %v, want normalized", public["endpoint"])
	}
	if _, leaked := public["secret_key"]; leaked {
		t.Fatalf("secret leaked into public config: %v", public)
	}
}

// TestCaptchaEndpointValidation 验证非法或缺失 endpoint 的保存拒绝语义：
// CAP 必填；其他类型非空 endpoint 必须为 http(s)，留空使用默认端点。
func TestCaptchaEndpointValidation(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		key     string
		conf    map[string]any
		wantErr bool
	}{
		{name: "cap missing endpoint", key: "cap", conf: map[string]any{"provider": "cap", "site_key": "s", "secret_key": "sec"}, wantErr: true},
		{name: "cap relative endpoint", key: "cap", conf: map[string]any{"provider": "cap", "site_key": "s", "secret_key": "sec", "endpoint": "cap.example.com"}, wantErr: true},
		{name: "cap bad scheme", key: "cap", conf: map[string]any{"provider": "cap", "site_key": "s", "secret_key": "sec", "endpoint": "ftp://cap.example.com"}, wantErr: true},
		{name: "non-cap without endpoint", key: "turnstile", conf: map[string]any{"provider": "turnstile", "site_key": "s", "secret_key": "sec"}, wantErr: false},
		{name: "non-cap with endpoint", key: "hcaptcha", conf: map[string]any{"provider": "hcaptcha", "site_key": "s", "secret_key": "sec", "endpoint": "https://proxy.example.com/siteverify"}, wantErr: false},
		{name: "non-cap bad endpoint", key: "recaptcha", conf: map[string]any{"provider": "recaptcha", "site_key": "s", "secret_key": "sec", "endpoint": "google.com"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.conf)
			if err != nil {
				t.Fatal(err)
			}
			err = providers.UpsertCaptcha(ctx, tc.key, raw)
			if tc.wantErr {
				if !errors.Is(err, domain.ErrValidation) {
					t.Fatalf("upsert error = %v, want ErrValidation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("upsert failed: %v", err)
			}
		})
	}
}

// TestCaptchaNonCAPEndpointRoundTrip 验证非 CAP 类型的自定义 endpoint 被规范化并解密往返。
func TestCaptchaNonCAPEndpointRoundTrip(t *testing.T) {
	svc, providers := newTestProviderService(t)
	ctx := context.Background()

	raw, _ := json.Marshal(map[string]any{
		"provider": "hcaptcha", "site_key": "hk", "secret_key": "hs",
		"endpoint": "https://proxy.example.com/siteverify/",
	})
	if err := providers.UpsertCaptcha(ctx, "hcaptcha", raw); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	selectCaptchaProvider(t, svc, "hcaptcha")
	cfg, err := providers.SelectedCaptcha(ctx)
	if err != nil {
		t.Fatalf("selected captcha: %v", err)
	}
	if cfg.Provider != "hcaptcha" || cfg.Endpoint != "https://proxy.example.com/siteverify" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

// TestCaptchaProviderKeyMustMatchType 验证 provider key 必须等于 provider 类型。
func TestCaptchaProviderKeyMustMatchType(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	raw, _ := json.Marshal(map[string]any{"provider": "turnstile", "site_key": "s", "secret_key": "sec"})
	if err := providers.UpsertCaptcha(ctx, "turnstile-main", raw); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("key mismatch error = %v, want ErrValidation", err)
	}
	if err := providers.UpsertCaptcha(ctx, "cap", raw); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("key/provider type mismatch error = %v, want ErrValidation", err)
	}
}

// TestCaptchaNonCAPNoEndpointCompatibility 验证旧的非 CAP 配置行无需 endpoint 仍可读取。
func TestCaptchaNonCAPNoEndpointCompatibility(t *testing.T) {
	svc, providers := newTestProviderService(t)
	ctx := context.Background()

	raw, _ := json.Marshal(map[string]any{"provider": "hcaptcha", "site_key": "hk", "secret_key": "hs"})
	if err := providers.UpsertCaptcha(ctx, "hcaptcha", raw); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	selectCaptchaProvider(t, svc, "hcaptcha")
	cfg, err := providers.SelectedCaptcha(ctx)
	if err != nil {
		t.Fatalf("selected captcha: %v", err)
	}
	if cfg.Provider != "hcaptcha" || cfg.Endpoint != "" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

// TestPublicCaptchaConfigDisabledSkipsProvider 验证策略关闭/缺失时返回 required=false 且不读取 provider。
func TestPublicCaptchaConfigDisabledSkipsProvider(t *testing.T) {
	svc, _ := newTestProviderService(t)
	configService := NewCaptchaConfigService(svc, nil)
	ctx := context.Background()

	// 默认策略为空，provider 服务为 nil 也应返回 required=false（不读取 provider）。
	cfg, err := configService.PublicConfig(ctx, "password_login")
	if err != nil {
		t.Fatalf("public config: %v", err)
	}
	if cfg.Required {
		t.Fatalf("required = true for disabled action, want false")
	}
}

// TestPublicCaptchaConfigEnabledProjectsPublicFields 验证策略开启时投影公开字段且不含机密。
func TestPublicCaptchaConfigEnabledProjectsPublicFields(t *testing.T) {
	svc, providers := newTestProviderService(t)
	configService := NewCaptchaConfigService(svc, providers)
	ctx := context.Background()

	raw, _ := json.Marshal(map[string]any{"provider": "cap", "site_key": "site-9", "secret_key": "sec", "endpoint": "https://cap.example.com"})
	if err := providers.UpsertCaptcha(ctx, "cap", raw); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	selectCaptchaProvider(t, svc, "cap")
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCaptchaPolicy, Type: SettingTypeJSON, Value: map[string]any{"password_login": true}},
	}, 1); err != nil {
		t.Fatalf("patch policy: %v", err)
	}

	cfg, err := configService.PublicConfig(ctx, "password_login")
	if err != nil {
		t.Fatalf("public config: %v", err)
	}
	if !cfg.Required {
		t.Fatalf("required = false for enabled action")
	}
	if cfg.Provider != "cap" || cfg.SiteKey != "site-9" {
		t.Fatalf("projection mismatch: %+v", cfg)
	}
	if cfg.APIEndpoint != "https://cap.example.com/site-9/" {
		t.Fatalf("api_endpoint = %q, want official widget endpoint", cfg.APIEndpoint)
	}
}

// TestPublicCaptchaConfigEnabledNoProviderFailsClosed 验证策略开启但未选择 provider 时返回不可用。
func TestPublicCaptchaConfigEnabledNoProviderFailsClosed(t *testing.T) {
	svc, providers := newTestProviderService(t)
	configService := NewCaptchaConfigService(svc, providers)
	ctx := context.Background()

	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCaptchaPolicy, Type: SettingTypeJSON, Value: map[string]any{"comment": true}},
	}, 1); err != nil {
		t.Fatalf("patch policy: %v", err)
	}
	_, err := configService.PublicConfig(ctx, "comment")
	if !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("error = %v, want ErrCaptchaUnavailable", err)
	}
}

// TestPublicCaptchaConfigActionValidation 验证空/超长 action 返回参数错误。
func TestPublicCaptchaConfigActionValidation(t *testing.T) {
	svc, _ := newTestProviderService(t)
	configService := NewCaptchaConfigService(svc, nil)
	ctx := context.Background()

	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	for _, action := range []string{"", "  ", string(long)} {
		if _, err := configService.PublicConfig(ctx, action); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("action=%q error = %v, want ErrValidation", action, err)
		}
	}
}

// TestSwitchCaptchaProviderKeepsRows 验证同时配置多个 CAPTCHA provider 并切换选择时，
// 未选择的配置行保持不变，读取始终跟随选择值。
func TestSwitchCaptchaProviderKeepsRows(t *testing.T) {
	svc, providers := newTestProviderService(t)
	ctx := context.Background()

	for key, conf := range map[string]map[string]any{
		"cap":       {"provider": "cap", "site_key": "s1", "secret_key": "sec1", "endpoint": "https://cap.example.com"},
		"turnstile": {"provider": "turnstile", "site_key": "s2", "secret_key": "sec2"},
	} {
		raw, err := json.Marshal(conf)
		if err != nil {
			t.Fatal(err)
		}
		if err := providers.UpsertCaptcha(ctx, key, raw); err != nil {
			t.Fatalf("upsert %s: %v", key, err)
		}
	}

	selectCaptchaProvider(t, svc, "cap")
	cfg, err := providers.SelectedCaptcha(ctx)
	if err != nil {
		t.Fatalf("selected captcha: %v", err)
	}
	if cfg.Provider != "cap" || cfg.SiteKey != "s1" {
		t.Fatalf("selection = %+v, want cap", cfg)
	}

	// 切换选择不影响其他 CAPTCHA 配置行。
	selectCaptchaProvider(t, svc, "turnstile")
	cfg, err = providers.SelectedCaptcha(ctx)
	if err != nil {
		t.Fatalf("selected captcha after switch: %v", err)
	}
	if cfg.Provider != "turnstile" || cfg.SiteKey != "s2" {
		t.Fatalf("selection = %+v, want turnstile", cfg)
	}

	metas, err := providers.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("provider count = %d, want 2 (both captcha rows must remain)", len(metas))
	}

	// 切回旧 provider 仍然可用。
	selectCaptchaProvider(t, svc, "cap")
	cfg, err = providers.SelectedCaptcha(ctx)
	if err != nil {
		t.Fatalf("selected captcha after switching back: %v", err)
	}
	if cfg.Provider != "cap" || cfg.SiteKey != "s1" {
		t.Fatalf("selection = %+v, want cap after switching back", cfg)
	}
}

// TestSelectedCaptchaMissingSelectionFailsClosed 验证选择指向缺失/类型不符的 provider 时
// 失败关闭且不回退到其他 provider。
func TestSelectedCaptchaMissingSelectionFailsClosed(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	raw, _ := json.Marshal(map[string]any{"provider": "turnstile", "site_key": "s", "secret_key": "sec"})
	if err := providers.UpsertCaptcha(ctx, "turnstile", raw); err != nil {
		t.Fatalf("upsert captcha: %v", err)
	}
	if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true, json.RawMessage(
		`{"client_id":"c","client_secret":"cs","auth_url":"https://a.example","token_url":"https://t.example"}`)); err != nil {
		t.Fatalf("upsert auth: %v", err)
	}

	// 未选择：读取失败。
	if _, err := providers.SelectedCaptcha(ctx); !errors.Is(err, domain.ErrProviderNotFound) {
		t.Fatalf("unselected error = %v, want ErrProviderNotFound", err)
	}

	// 直接写入指向缺失 provider 的旧选择（绕过 PATCH 校验，模拟陈旧选择），
	// 读取必须失败关闭，不回退到 turnstile。
	if err := providers.settings.Upsert(ctx, []repository.DynamicSettingRow{{
		Key: SettingKeyCaptchaProvider, Type: string(SettingTypeString), Value: []byte(`"missing-key"`), UpdatedBy: 0,
	}}); err != nil {
		t.Fatalf("seed stale selection: %v", err)
	}
	if _, err := providers.SelectedCaptcha(ctx); !errors.Is(err, domain.ErrProviderNotFound) {
		t.Fatalf("missing selection error = %v, want ErrProviderNotFound", err)
	}

	// 选择指向非 CAPTCHA provider：PATCH 校验失败关闭。
	svc, _ := newTestProviderService(t)
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCaptchaProvider, Type: SettingTypeString, Value: "github"},
	}, 1); !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("select auth error = %v, want ErrCaptchaUnavailable", err)
	}
}

// TestDeleteCaptchaProviderSelectionSemantics 验证删除当前选中的 CAPTCHA provider 清空选择，
// 删除未选中的 provider 不影响当前选择。
func TestDeleteCaptchaProviderSelectionSemantics(t *testing.T) {
	svc, providers := newTestProviderService(t)
	ctx := context.Background()

	for key, conf := range map[string]map[string]any{
		"cap":       {"provider": "cap", "site_key": "s1", "secret_key": "sec1", "endpoint": "https://cap.example.com"},
		"turnstile": {"provider": "turnstile", "site_key": "s2", "secret_key": "sec2"},
	} {
		raw, err := json.Marshal(conf)
		if err != nil {
			t.Fatal(err)
		}
		if err := providers.UpsertCaptcha(ctx, key, raw); err != nil {
			t.Fatalf("upsert %s: %v", key, err)
		}
	}
	selectCaptchaProvider(t, svc, "cap")

	// 删除未选中的 provider 不影响选择。
	if err := providers.Delete(ctx, "turnstile"); err != nil {
		t.Fatalf("delete unselected: %v", err)
	}
	cfg, err := providers.SelectedCaptcha(ctx)
	if err != nil {
		t.Fatalf("selected captcha: %v", err)
	}
	if cfg.Provider != "cap" || cfg.SiteKey != "s1" {
		t.Fatalf("selection changed after deleting unselected: %+v", cfg)
	}

	// 删除当前选中的 provider 清空选择设置。
	if err := providers.Delete(ctx, "cap"); err != nil {
		t.Fatalf("delete selected: %v", err)
	}
	if _, err := providers.SelectedCaptcha(ctx); !errors.Is(err, domain.ErrProviderNotFound) {
		t.Fatalf("selection after deleting selected = %v, want ErrProviderNotFound", err)
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.CaptchaProvider != "" {
		t.Fatalf("captcha_provider = %q after deleting selected, want empty", view.Settings.CaptchaProvider)
	}
}

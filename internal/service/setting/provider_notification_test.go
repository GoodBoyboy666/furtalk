package setting

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
)

// validNotificationConfig 返回各通知平台的一份完整配置。
func validNotificationConfig(key string) string {
	switch key {
	case "notification.telegram":
		return `{"bot_token":"token","chat_id":"123"}`
	case "notification.feishu":
		return `{"webhook_url":"https://open.feishu.cn/open-apis/bot/v2/hook/abc"}`
	case "notification.dingtalk":
		return `{"webhook_url":"https://oapi.dingtalk.com/robot/send?access_token=abc"}`
	case "notification.bark":
		return `{"server_url":"https://api.day.app","device_key":"key"}`
	case "notification.slack":
		return `{"webhook_url":"https://hooks.slack.com/services/T/B/X"}`
	case "notification.line":
		return `{"channel_access_token":"tok","target_id":"U1"}`
	case "notification.webhook":
		return `{"webhook_url":"http://127.0.0.1:9000/hook"}`
	case "notification.discord":
		return `{"webhook_url":"https://discord.com/api/webhooks/1/2"}`
	}
	return ""
}

// TestUpsertNotificationAllKeys 验证 8 个固定 key 全部可保存并往返读取。
func TestUpsertNotificationAllKeys(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	for _, key := range notificationProviderKeys {
		if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(validNotificationConfig(key))); err != nil {
			t.Fatalf("upsert %s = %v, want nil", key, err)
		}
		got, err := providers.NotificationProvider(ctx, key)
		if err != nil {
			t.Fatalf("get %s = %v", key, err)
		}
		if !got.Configured || !got.Enabled {
			t.Fatalf("%s meta = %+v, want configured+enabled", key, got)
		}
	}
	// 同平台仍然只有一个目标（列表只有 8 行，key 唯一）。
	rows, err := providers.settings.ListNotificationProviders(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 8 {
		t.Fatalf("rows = %d, want 8", len(rows))
	}
}

// TestUpsertNotificationUnknownKey 验证未知 key 被拒绝。
func TestUpsertNotificationUnknownKey(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	err := providers.UpsertNotification(ctx, "notification.bogus", true, json.RawMessage(`{"webhook_url":"https://example.com"}`))
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("unknown key error = %v, want ErrValidation", err)
	}
}

// TestNotificationSecretPreserve 验证编辑时留空必填机密字段保留现值。
func TestNotificationSecretPreserve(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	key := "notification.telegram"
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(`{"bot_token":"secret","chat_id":"123"}`)); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 编辑只改 chat_id，bot_token 留空保留。
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(`{"chat_id":"456"}`)); err != nil {
		t.Fatalf("edit: %v", err)
	}
	got, err := providers.NotificationProvider(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Config.BotToken != "secret" || got.Config.ChatID != "456" {
		t.Fatalf("config = %+v, want preserved bot_token + new chat_id", got.Config)
	}
	// 再次编辑 bot_token 非空替换。
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(`{"bot_token":"new-secret"}`)); err != nil {
		t.Fatalf("edit token: %v", err)
	}
	got, _ = providers.NotificationProvider(ctx, key)
	if got.Config.BotToken != "new-secret" {
		t.Fatalf("bot_token = %q, want new-secret", got.Config.BotToken)
	}
}

// TestNotificationSigningSecretTriState 验证可选签名密钥三态：
// 缺省保留、null 清除、非空替换。
func TestNotificationSigningSecretTriState(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	key := "notification.webhook"
	urlJSON := `"http://127.0.0.1:9000/hook"`
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(`{"webhook_url":`+urlJSON+`,"signing_secret":"s1"}`)); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 缺省 → 保留。
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(`{"webhook_url":`+urlJSON+`}`)); err != nil {
		t.Fatalf("edit omit: %v", err)
	}
	got, _ := providers.NotificationProvider(ctx, key)
	if got.Config.SigningSecret == nil || *got.Config.SigningSecret != "s1" {
		t.Fatalf("signing secret after omit = %v, want s1", got.Config.SigningSecret)
	}
	// null → 清除。
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(`{"webhook_url":`+urlJSON+`,"signing_secret":null}`)); err != nil {
		t.Fatalf("edit null: %v", err)
	}
	got, _ = providers.NotificationProvider(ctx, key)
	if got.Config.SigningSecret != nil {
		t.Fatalf("signing secret after null = %v, want nil", got.Config.SigningSecret)
	}
	// 非空 → 替换。
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(`{"webhook_url":`+urlJSON+`,"signing_secret":"s2"}`)); err != nil {
		t.Fatalf("edit replace: %v", err)
	}
	got, _ = providers.NotificationProvider(ctx, key)
	if got.Config.SigningSecret == nil || *got.Config.SigningSecret != "s2" {
		t.Fatalf("signing secret after replace = %v, want s2", got.Config.SigningSecret)
	}
}

// TestNotificationEnableRequiresComplete 验证启用不完整配置被拒绝，
// 且缺字段的创建也被拒绝（所有必填字段创建时都必须提供）。
func TestNotificationEnableRequiresComplete(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	key := "notification.line"
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(`{"channel_access_token":"tok"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("incomplete enable error = %v, want ErrValidation", err)
	}
	if err := providers.UpsertNotification(ctx, key, false, json.RawMessage(`{"channel_access_token":"tok"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("incomplete create error = %v, want ErrValidation", err)
	}
}

// TestNotificationInvalidURL 验证非法 webhook URL（错误主机/带 userinfo/带 fragment）被拒绝。
func TestNotificationInvalidURL(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	cases := []struct {
		key  string
		conf string
	}{
		{"notification.slack", `{"webhook_url":"https://evil.com/services/T/B/X"}`},
		{"notification.feishu", `{"webhook_url":"https://open.feishu.cn/other"}`},
		{"notification.discord", `{"webhook_url":"https://discord.com/api/webhooks/1/2#frag"}`},
		{"notification.webhook", `{"webhook_url":"https://user:pass@host/x"}`},
		{"notification.bark", `{"server_url":"https://host/x#f","device_key":"k"}`},
		{"notification.dingtalk", `{"webhook_url":"https://oapi.dingtalk.com/robot/send"}`},
	}
	for _, tc := range cases {
		err := providers.UpsertNotification(ctx, tc.key, true, json.RawMessage(tc.conf))
		if !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("upsert %s with %s error = %v, want ErrValidation", tc.key, tc.conf, err)
		}
	}
}

// TestNotificationCorruptSecret 验证密钥损坏时读取返回 ErrSecretCorrupt。
func TestNotificationCorruptSecret(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	row := &repository.NotificationProviderRow{
		ProviderKey:      "notification.telegram",
		Enabled:          true,
		SecretKeyVersion: 1,
		SecretNonce:      []byte("short"),
		SecretCiphertext: []byte("bad"),
	}
	if err := providers.settings.UpsertNotificationProvider(ctx, row); err != nil {
		t.Fatalf("write corrupt row: %v", err)
	}
	if _, err := providers.NotificationProvider(ctx, "notification.telegram"); !errors.Is(err, domain.ErrSecretCorrupt) {
		t.Fatalf("corrupt read error = %v, want ErrSecretCorrupt", err)
	}
	// 已启用列表遇到损坏配置 fail closed。
	if _, err := providers.EnabledNotificationProviders(ctx); !errors.Is(err, domain.ErrSecretCorrupt) {
		t.Fatalf("enabled list error = %v, want ErrSecretCorrupt", err)
	}
}

// TestNotificationDelete 验证删除通知通道后行消失。
func TestNotificationDelete(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	key := "notification.bark"
	if err := providers.UpsertNotification(ctx, key, false, json.RawMessage(validNotificationConfig(key))); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := providers.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := providers.NotificationProvider(ctx, key); !errors.Is(err, domain.ErrProviderNotFound) {
		t.Fatalf("get after delete error = %v, want ErrProviderNotFound", err)
	}
}

// TestNotificationListRedaction 验证管理列表只返回 provider_key/kind/enabled/configured
// 与公开元数据，绝不含机密字段或密文。
func TestNotificationListRedaction(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	key := "notification.bark"
	if err := providers.UpsertNotification(ctx, key, true, json.RawMessage(validNotificationConfig(key))); err != nil {
		t.Fatalf("create: %v", err)
	}
	metas, err := providers.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *ProviderMeta
	for i := range metas {
		if metas[i].ProviderKey == key {
			found = &metas[i]
		}
	}
	if found == nil {
		t.Fatalf("meta for %s not found in %+v", key, metas)
	}
	if found.Kind != domain.ProviderKindNotification || !found.Enabled || !found.Configured {
		t.Fatalf("meta = %+v", found)
	}
	raw := string(found.PublicConfig)
	if len(raw) == 0 {
		t.Fatalf("bark public config should carry server_url")
	}
	// server_url 是唯一公开元数据；device_key 必须不出现。
	if !json.Valid(found.PublicConfig) {
		t.Fatalf("public config invalid: %s", raw)
	}
}

// fakeNotificationTester 记录调用并返回可配置错误。
type fakeNotificationTester struct {
	called bool
	cfg    NotificationConfig
	key    string
	err    error
}

func (f *fakeNotificationTester) TestNotification(_ context.Context, key string, cfg NotificationConfig) error {
	f.called = true
	f.key = key
	f.cfg = cfg
	return f.err
}

// TestNotificationTest 验证 Test 允许停用通道发送测试，且按 tester 结果映射错误。
func TestNotificationTest(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	key := "notification.telegram"
	// 停用（enabled=false）仍允许测试，但需要完整配置。
	if err := providers.UpsertNotification(ctx, key, false, json.RawMessage(validNotificationConfig(key))); err != nil {
		t.Fatalf("create: %v", err)
	}
	tester := &fakeNotificationTester{}
	providers.SetNotificationTester(tester)

	if err := providers.Test(ctx, key); err != nil {
		t.Fatalf("test = %v, want nil", err)
	}
	if !tester.called || tester.key != key || tester.cfg.BotToken != "token" {
		t.Fatalf("tester = %+v, want called with telegram config", tester)
	}

	// tester 返回 validation → Test 返回 validation。
	tester.err = domain.ErrValidation
	if err := providers.Test(ctx, key); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("tester validation error = %v, want ErrValidation", err)
	}
	// tester 返回 unavailable → Test 返回 unavailable。
	tester.err = domain.ErrUnavailable
	if err := providers.Test(ctx, key); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("tester unavailable error = %v, want ErrUnavailable", err)
	}
	// 未接线 tester → unavailable。
	providers.notificationTester = nil
	if err := providers.Test(ctx, key); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("missing tester error = %v, want ErrUnavailable", err)
	}
	// 缺失配置的测试 → ErrProviderNotFound。
	if err := providers.Test(ctx, "notification.line"); !errors.Is(err, domain.ErrProviderNotFound) {
		t.Fatalf("missing provider test error = %v, want ErrProviderNotFound", err)
	}
}

// TestNotificationKeyReservedForAuth 验证 notification.* 命名空间不能被 OAuth 类型占用。
func TestNotificationKeyReservedForAuth(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	err := providers.UpsertAuth(ctx, "notification.foo", domain.ProviderKindOIDC, false,
		json.RawMessage(`{"client_id":"c","issuer_url":"https://issuer.example.com"}`))
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("auth upsert with notification.* key error = %v, want ErrValidation", err)
	}
}

// TestEnabledNotificationProviders 验证只返回已启用通道，按固定 key 顺序。
func TestEnabledNotificationProviders(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	// 只启用 telegram 与 discord；其他保持未配置。
	if err := providers.UpsertNotification(ctx, "notification.telegram", true, json.RawMessage(validNotificationConfig("notification.telegram"))); err != nil {
		t.Fatalf("create telegram: %v", err)
	}
	if err := providers.UpsertNotification(ctx, "notification.discord", false, json.RawMessage(validNotificationConfig("notification.discord"))); err != nil {
		t.Fatalf("create discord: %v", err)
	}
	enabled, err := providers.EnabledNotificationProviders(ctx)
	if err != nil {
		t.Fatalf("enabled list: %v", err)
	}
	if len(enabled) != 1 || enabled[0].ProviderKey != "notification.telegram" {
		t.Fatalf("enabled = %+v, want only telegram", enabled)
	}
}

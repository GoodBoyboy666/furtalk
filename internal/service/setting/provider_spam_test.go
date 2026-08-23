package setting

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"furtalk/internal/domain"
)

// writeKeywordFile 写入临时词库文件并返回绝对路径。
func writeKeywordFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keywords.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write keyword file: %v", err)
	}
	return path
}

// TestUpsertSpamLocal 验证本地词库渠道：合法文件 + action + enabled 可保存，
// 无 action、非法 action、缺失/非法文件路径均被拒绝。
func TestUpsertSpamLocal(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	path := writeKeywordFile(t, "广告\n免费领取\n")

	cases := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{name: "valid pending", config: `{"file_path":"` + path + `","check_nickname":true,"action":"pending"}`},
		{name: "valid spam", config: `{"file_path":"` + path + `","action":"spam"}`},
		{name: "missing action", config: `{"file_path":"` + path + `"}`, wantErr: true},
		{name: "bad action", config: `{"file_path":"` + path + `","action":"block"}`, wantErr: true},
		{name: "missing file", config: `{"action":"spam"}`, wantErr: true},
		{name: "bad file path", config: `{"file_path":"/no/such/file.txt","action":"spam"}`, wantErr: true},
		{name: "unknown field", config: `{"file_path":"` + path + `","action":"spam","nope":1}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := providers.UpsertSpam(ctx, "spam.local", true, json.RawMessage(tc.config))
			if tc.wantErr {
				if !errors.Is(err, domain.ErrValidation) {
					t.Fatalf("UpsertSpam error = %v, want ErrValidation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("UpsertSpam = %v, want nil", err)
			}
		})
	}
}

// TestUpsertSpamAkismetSecretContract 验证 Akismet 的 Secret 更新契约：
// 新建必填、整组空白保留、enabled 需要 Secret。
func TestUpsertSpamAkismetSecretContract(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	if err := providers.UpsertSpam(ctx, "spam.akismet", true, json.RawMessage(`{"action":"spam"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("enable akismet without secret error = %v, want ErrValidation", err)
	}
	if err := providers.UpsertSpam(ctx, "spam.akismet", true, json.RawMessage(`{"action":"spam","api_key":"ak-key"}`)); err != nil {
		t.Fatalf("upsert akismet with secret = %v, want nil", err)
	}
	got, err := providers.SpamProvider(ctx, "spam.akismet")
	if err != nil {
		t.Fatalf("get akismet: %v", err)
	}
	if !got.Configured || got.Config.APIKey != "ak-key" || got.Config.Action != "spam" {
		t.Fatalf("akismet config mismatch: %+v", got.Config)
	}

	// 编辑留空 Secret：保留现有 envelope。
	if err := providers.UpsertSpam(ctx, "spam.akismet", true, json.RawMessage(`{"action":"pending"}`)); err != nil {
		t.Fatalf("upsert akismet blank secret = %v, want nil", err)
	}
	got, err = providers.SpamProvider(ctx, "spam.akismet")
	if err != nil {
		t.Fatalf("get akismet after blank edit: %v", err)
	}
	if got.Config.APIKey != "ak-key" {
		t.Fatalf("akismet api key after blank edit = %q, want preserved ak-key", got.Config.APIKey)
	}
	if got.Config.Action != "pending" {
		t.Fatalf("akismet action after edit = %q, want pending", got.Config.Action)
	}
}

// TestUpsertSpamCloudSecretGroup 验证云渠道 Secret 组必须完整提交或整组空白。
func TestUpsertSpamCloudSecretGroup(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	valid := `{"region":"cn-shanghai","access_key_id":"id","access_key_secret":"secret"}`
	if err := providers.UpsertSpam(ctx, "spam.aliyun", true, json.RawMessage(valid)); err != nil {
		t.Fatalf("upsert aliyun full secret = %v, want nil", err)
	}
	got, err := providers.SpamProvider(ctx, "spam.aliyun")
	if err != nil {
		t.Fatalf("get aliyun: %v", err)
	}
	if got.Config.AccessKeyID != "id" || got.Config.AccessKeySecret != "secret" || got.Config.Region != "cn-shanghai" {
		t.Fatalf("aliyun config mismatch: %+v", got.Config)
	}

	partial := `{"region":"cn-shanghai","access_key_id":"id"}`
	if err := providers.UpsertSpam(ctx, "spam.aliyun", true, json.RawMessage(partial)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("upsert aliyun partial secret error = %v, want ErrValidation", err)
	}
	missingRegion := `{"access_key_id":"id","access_key_secret":"secret"}`
	if err := providers.UpsertSpam(ctx, "spam.aliyun", true, json.RawMessage(missingRegion)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("upsert aliyun missing region error = %v, want ErrValidation", err)
	}
}

// TestUpsertSpamKeyMatrix 验证只接受固定 spam key，未知 key 与未知字段被拒绝。
func TestUpsertSpamKeyMatrix(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	if err := providers.UpsertSpam(ctx, "spam.bogus", true, json.RawMessage(`{"action":"spam"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("upsert unknown spam key error = %v, want ErrValidation", err)
	}
	if err := providers.UpsertSpam(ctx, "not-a-spam", true, json.RawMessage(`{"action":"spam"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("upsert non-spam key error = %v, want ErrValidation", err)
	}
}

// TestReserveSpamKeys 验证 CAPTCHA/OAuth upsert 不得使用 spam.* 保留 key。
func TestReserveSpamKeys(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()

	if err := providers.UpsertCaptcha(ctx, "spam.local", json.RawMessage(`{"provider":"spam.local","site_key":"s","secret_key":"k"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("upsert captcha with spam key error = %v, want ErrValidation", err)
	}
	if err := providers.UpsertAuth(ctx, "spam.akismet", domain.ProviderKindOIDC, true, json.RawMessage(`{"client_id":"c","client_secret":"s","issuer_url":"https://i.example.com"}`)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("upsert auth with spam key error = %v, want ErrValidation", err)
	}
}

// TestEnabledSpamProvidersOrder 验证运行时读取只返回已启用渠道且按固定执行顺序。
func TestEnabledSpamProvidersOrder(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	path := writeKeywordFile(t, "广告\n")

	if err := providers.UpsertSpam(ctx, "spam.tencent", true, json.RawMessage(`{"region":"ap-guangzhou","secret_id":"id","secret_key":"key"}`)); err != nil {
		t.Fatalf("upsert tencent: %v", err)
	}
	if err := providers.UpsertSpam(ctx, "spam.local", true, json.RawMessage(`{"file_path":"`+path+`","action":"pending"}`)); err != nil {
		t.Fatalf("upsert local: %v", err)
	}
	// 禁用的 akismet 不应出现。
	if err := providers.UpsertSpam(ctx, "spam.akismet", false, json.RawMessage(`{"action":"spam","api_key":"k"}`)); err != nil {
		t.Fatalf("upsert akismet disabled: %v", err)
	}

	enabled, err := providers.EnabledSpamProviders(ctx)
	if err != nil {
		t.Fatalf("list enabled spam: %v", err)
	}
	if len(enabled) != 2 {
		t.Fatalf("enabled count = %d, want 2", len(enabled))
	}
	if enabled[0].ProviderKey != "spam.local" || enabled[1].ProviderKey != "spam.tencent" {
		t.Fatalf("enabled order = %q, %q; want local then tencent", enabled[0].ProviderKey, enabled[1].ProviderKey)
	}
}

// TestSpamListConfigured 验证管理列表对 spam 项的 configured/enabled 投影：
// 本地由 file_path 决定，外部由 Secret 决定。
func TestSpamListConfigured(t *testing.T) {
	_, providers := newTestProviderService(t)
	ctx := context.Background()
	path := writeKeywordFile(t, "广告\n")

	if err := providers.UpsertSpam(ctx, "spam.local", true, json.RawMessage(`{"file_path":"`+path+`","action":"pending"}`)); err != nil {
		t.Fatalf("upsert local: %v", err)
	}
	if err := providers.UpsertSpam(ctx, "spam.akismet", false, json.RawMessage(`{"action":"spam","api_key":"k"}`)); err != nil {
		t.Fatalf("upsert akismet: %v", err)
	}
	if err := providers.UpsertSpam(ctx, "spam.aliyun", false, json.RawMessage(`{"region":"cn-shanghai"}`)); err != nil {
		t.Fatalf("upsert aliyun unconfigured: %v", err)
	}

	metas, err := providers.List(ctx)
	if err != nil {
		t.Fatalf("list providers: %v", err)
	}
	local := findMeta(metas, "spam.local")
	if local == nil || !local.Configured || !local.Enabled || local.Kind != domain.ProviderKindSpam {
		t.Fatalf("spam.local meta = %+v, want configured+enabled+spam", local)
	}
	akismet := findMeta(metas, "spam.akismet")
	if akismet == nil || !akismet.Configured || akismet.Enabled {
		t.Fatalf("spam.akismet meta = %+v, want configured but disabled", akismet)
	}
	aliyun := findMeta(metas, "spam.aliyun")
	if aliyun == nil || aliyun.Configured {
		t.Fatalf("spam.aliyun meta = %+v, want unconfigured", aliyun)
	}
}

func findMeta(metas []ProviderMeta, key string) *ProviderMeta {
	for i := range metas {
		if metas[i].ProviderKey == key {
			return &metas[i]
		}
	}
	return nil
}

package setting

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/value"
)

// TestDefaultsIncludeEmailAndAvatarSettings 验证默认设置携带空名单与默认 Gravatar 基址，
// 且公开设置项与持久化默认项都包含三个新 key。
func TestDefaultsIncludeEmailAndAvatarSettings(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(view.Settings.EmailDomainWhitelist) != 0 {
		t.Fatalf("whitelist = %v, want empty", view.Settings.EmailDomainWhitelist)
	}
	if len(view.Settings.EmailDomainBlacklist) != 0 {
		t.Fatalf("blacklist = %v, want empty", view.Settings.EmailDomainBlacklist)
	}
	if view.Settings.GravatarBaseURL != value.DefaultGravatarBaseURL {
		t.Fatalf("gravatar base = %q, want %q", view.Settings.GravatarBaseURL, value.DefaultGravatarBaseURL)
	}

	items, err := svc.PublicItems(ctx)
	if err != nil {
		t.Fatalf("public items: %v", err)
	}
	for _, want := range []string{SettingKeyEmailDomainWhitelist, SettingKeyEmailDomainBlacklist, SettingKeyGravatarBaseURL} {
		var found bool
		for _, item := range items {
			if item.Key == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("key %q missing from public items", want)
		}
	}
}

// TestPatchEmailDomainSettingsRoundTrip 验证域名名单规范化存储并回读，
// 列表顺序保持不变，Gravatar 基址去除首尾空白。
func TestPatchEmailDomainSettingsRoundTrip(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	_, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: []any{" Example.COM ", "sub.example.com"}},
		{Key: SettingKeyEmailDomainBlacklist, Type: SettingTypeJSON, Value: []any{"Blocked.Example"}},
		{Key: SettingKeyGravatarBaseURL, Type: SettingTypeString, Value: "  https://avatars.example.com/avatar/  "},
	}, 1)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(view.Settings.EmailDomainWhitelist, []string{"example.com", "sub.example.com"}) {
		t.Fatalf("whitelist = %v, want [example.com sub.example.com]", view.Settings.EmailDomainWhitelist)
	}
	if !reflect.DeepEqual(view.Settings.EmailDomainBlacklist, []string{"blocked.example"}) {
		t.Fatalf("blacklist = %v, want [blocked.example]", view.Settings.EmailDomainBlacklist)
	}
	if view.Settings.GravatarBaseURL != "https://avatars.example.com/avatar/" {
		t.Fatalf("gravatar base = %q, want trimmed url", view.Settings.GravatarBaseURL)
	}
}

// TestPatchEmailDomainValidationErrors 验证非法域名、规范化重复域名与非法
// Gravatar 基址使整个 PATCH 失败且不落库。
func TestPatchEmailDomainValidationErrors(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		items []SettingItem
	}{
		{name: "domain with @", items: []SettingItem{
			{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: []any{"a@b.com"}},
		}},
		{name: "domain with scheme", items: []SettingItem{
			{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: []any{"https://example.com"}},
		}},
		{name: "domain with path", items: []SettingItem{
			{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: []any{"example.com/x"}},
		}},
		{name: "domain with port", items: []SettingItem{
			{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: []any{"example.com:8080"}},
		}},
		{name: "wildcard", items: []SettingItem{
			{Key: SettingKeyEmailDomainBlacklist, Type: SettingTypeJSON, Value: []any{"*.example.com"}},
		}},
		{name: "empty label", items: []SettingItem{
			{Key: SettingKeyEmailDomainBlacklist, Type: SettingTypeJSON, Value: []any{".example.com"}},
		}},
		{name: "duplicate after normalization", items: []SettingItem{
			{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: []any{"Example.com", "example.com"}},
		}},
		{name: "gravatar relative url", items: []SettingItem{
			{Key: SettingKeyGravatarBaseURL, Type: SettingTypeString, Value: "avatars.example.com/avatar"},
		}},
		{name: "gravatar userinfo", items: []SettingItem{
			{Key: SettingKeyGravatarBaseURL, Type: SettingTypeString, Value: "https://user:pass@avatars.example.com"},
		}},
		{name: "gravatar query", items: []SettingItem{
			{Key: SettingKeyGravatarBaseURL, Type: SettingTypeString, Value: "https://avatars.example.com/avatar?d=identicon"},
		}},
		{name: "gravatar fragment", items: []SettingItem{
			{Key: SettingKeyGravatarBaseURL, Type: SettingTypeString, Value: "https://avatars.example.com/avatar#top"},
		}},
		{name: "gravatar non-http scheme", items: []SettingItem{
			{Key: SettingKeyGravatarBaseURL, Type: SettingTypeString, Value: "ftp://avatars.example.com/avatar"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestService(t)
			_, err := svc.Patch(ctx, tc.items, 1)
			if !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("Patch error = %v, want ErrValidation", err)
			}
			view, err := svc.Get(ctx)
			if err != nil {
				t.Fatalf("get after rejected patch: %v", err)
			}
			if !reflect.DeepEqual(view.Settings, DefaultSettings()) {
				t.Fatalf("settings after rejected patch = %+v, want defaults", view.Settings)
			}
		})
	}
}

// TestPatchEmailDomainBatchAtomicity 验证批次中合法域名项与非法项共存时整体失败，
// 合法项也不写入。
func TestPatchEmailDomainBatchAtomicity(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	_, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: []any{"example.com"}},
		{Key: SettingKeyGravatarBaseURL, Type: SettingTypeString, Value: "not a url"},
	}, 1)
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Patch error = %v, want ErrValidation", err)
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(view.Settings.EmailDomainWhitelist) != 0 {
		t.Fatalf("whitelist must not be written by failed batch: %v", view.Settings.EmailDomainWhitelist)
	}
	if view.Settings.GravatarBaseURL != value.DefaultGravatarBaseURL {
		t.Fatalf("gravatar base must stay default: %q", view.Settings.GravatarBaseURL)
	}
}

// TestPatchEmailDomainInvalidatesCache 验证名单/基址更新后缓存失效，Get 立即返回新值。
func TestPatchEmailDomainInvalidatesCache(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: []any{"example.com"}},
	}, 1); err != nil {
		t.Fatalf("patch: %v", err)
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(view.Settings.EmailDomainWhitelist, []string{"example.com"}) {
		t.Fatalf("whitelist = %v, want [example.com] (cache must be invalidated)", view.Settings.EmailDomainWhitelist)
	}
}

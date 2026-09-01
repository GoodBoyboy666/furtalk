package app

import (
	"context"
	"path/filepath"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"
	"furtalk/internal/service/notification"
	"furtalk/internal/service/setting"
)

func TestProjectAuthProviderCopiesEveryConsumerField(t *testing.T) {
	source := setting.AuthProvider{
		ProviderKey:     "apple",
		Kind:            domain.ProviderKindOIDC,
		Enabled:         true,
		Configured:      true,
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		AuthURL:         "https://example.com/auth",
		TokenURL:        "https://example.com/token",
		IssuerURL:       "https://example.com",
		InstanceURL:     "https://instance.example.com",
		AppleTeamID:     "team",
		AppleKeyID:      "key",
		ApplePrivateKey: "private-key",
	}
	want := identity.AuthProvider{
		ProviderKey:     source.ProviderKey,
		Kind:            source.Kind,
		Enabled:         source.Enabled,
		Configured:      source.Configured,
		ClientID:        source.ClientID,
		ClientSecret:    source.ClientSecret,
		AuthURL:         source.AuthURL,
		TokenURL:        source.TokenURL,
		IssuerURL:       source.IssuerURL,
		InstanceURL:     source.InstanceURL,
		AppleTeamID:     source.AppleTeamID,
		AppleKeyID:      source.AppleKeyID,
		ApplePrivateKey: source.ApplePrivateKey,
	}
	if got := projectAuthProvider(source); got != want {
		t.Fatalf("projectAuthProvider() = %#v, want %#v", got, want)
	}
}

func TestProjectNotificationConfigCopiesEveryConsumerField(t *testing.T) {
	secret := "signing-secret"
	source := setting.NotificationConfig{
		BotToken:           "bot-token",
		ChatID:             "chat-id",
		WebhookURL:         "https://example.com/webhook",
		ServerURL:          "https://example.com/server",
		DeviceKey:          "device-key",
		ChannelAccessToken: "channel-token",
		TargetID:           "target-id",
		SigningSecret:      &secret,
	}
	want := notification.ChannelConfig{
		BotToken:           source.BotToken,
		ChatID:             source.ChatID,
		WebhookURL:         source.WebhookURL,
		ServerURL:          source.ServerURL,
		DeviceKey:          source.DeviceKey,
		ChannelAccessToken: source.ChannelAccessToken,
		TargetID:           source.TargetID,
		SigningSecret:      source.SigningSecret,
	}
	got := projectNotificationConfig(source)
	if got.BotToken != want.BotToken || got.ChatID != want.ChatID || got.WebhookURL != want.WebhookURL ||
		got.ServerURL != want.ServerURL || got.DeviceKey != want.DeviceKey ||
		got.ChannelAccessToken != want.ChannelAccessToken || got.TargetID != want.TargetID ||
		got.SigningSecret == nil || *got.SigningSecret != *want.SigningSecret {
		t.Fatalf("projectNotificationConfig() = %#v, want %#v", got, want)
	}
	if got.SigningSecret == source.SigningSecret {
		t.Fatal("signing secret pointer was not copied")
	}
}

// TestCommentPolicyProjectsCommentSort 验证组合根的策略适配器把动态设置中的
// comment_sort 逐字段投影到 CommentPolicy，构成 settings -> runtime-config ->
// public query 的跨层契约。
func TestCommentPolicyProjectsCommentSort(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "policy-projection.db")
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

	svc := setting.NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	reader := commentPolicyReader{svc: svc}
	notificationReader := notificationSettingsReader{svc: svc}
	notificationSettings, err := notificationReader.NotificationSettings(context.Background())
	if err != nil {
		t.Fatalf("notification settings: %v", err)
	}
	if !notificationSettings.Moderation || !notificationSettings.Replies {
		t.Fatalf("notification settings = %+v, want both defaults enabled", notificationSettings)
	}

	// 默认 asc 投影。
	pol, err := reader.CommentPolicy(context.Background())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if pol.CommentSort != string(domain.CommentSortAsc) {
		t.Fatalf("comment_sort = %q, want asc default", pol.CommentSort)
	}

	// PATCH 为 desc 后投影立即反映新值。
	if _, err := svc.Patch(context.Background(), []setting.SettingItem{
		{Key: setting.SettingKeyCommentSort, Type: setting.SettingTypeString, Value: string(domain.CommentSortDesc)},
	}, 1); err != nil {
		t.Fatalf("patch comment sort: %v", err)
	}
	pol, err = reader.CommentPolicy(context.Background())
	if err != nil {
		t.Fatalf("policy after patch: %v", err)
	}
	if pol.CommentSort != string(domain.CommentSortDesc) {
		t.Fatalf("comment_sort = %q, want desc after patch", pol.CommentSort)
	}

	// 默认 EmojiCatalogURL 为空串。
	if pol.EmojiCatalogURL != "" {
		t.Fatalf("emoji_catalog_url = %q, want empty default", pol.EmojiCatalogURL)
	}

	// PATCH 后投影立即反映新目录 URL。
	if _, err := svc.Patch(context.Background(), []setting.SettingItem{
		{Key: setting.SettingKeyEmojiCatalogURL, Type: setting.SettingTypeString, Value: "https://cdn.example/emoji.json"},
	}, 1); err != nil {
		t.Fatalf("patch emoji catalog url: %v", err)
	}
	pol, err = reader.CommentPolicy(context.Background())
	if err != nil {
		t.Fatalf("policy after catalog patch: %v", err)
	}
	if pol.EmojiCatalogURL != "https://cdn.example/emoji.json" {
		t.Fatalf("emoji_catalog_url = %q, want configured value", pol.EmojiCatalogURL)
	}
}

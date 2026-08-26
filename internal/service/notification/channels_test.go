package notification

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/notifier"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/setting"

	"gorm.io/gorm"
)

// fakeChannelReader 返回可编程的已启用通道列表。
type fakeChannelReader struct {
	providers []setting.NotificationProvider
	err       error
}

func (f *fakeChannelReader) EnabledNotificationProviders(context.Context) ([]setting.NotificationProvider, error) {
	return f.providers, f.err
}

// fakeChannelDispatcher 记录全部投递并按平台返回可配置错误。
type fakeChannelDispatcher struct {
	mu       sync.Mutex
	configs  []notifier.Config
	messages []notifier.Message
	errBy    map[string]error
}

func (f *fakeChannelDispatcher) Send(_ context.Context, cfg notifier.Config, msg notifier.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configs = append(f.configs, cfg)
	f.messages = append(f.messages, msg)
	if f.errBy != nil {
		if err := f.errBy[string(cfg.Platform)]; err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeChannelDispatcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.configs)
}

// newChannelHarness 构建带站点仓储、fake channel reader/dispatcher、无 SMTP 的通知服务。
// mailer 为 nil，用于证明非邮件通道在 SMTP 缺失时仍可投递。
func newChannelHarness(t *testing.T, providers []setting.NotificationProvider, errBy map[string]error) (*gorm.DB, *Service, *fakeChannelDispatcher, *setting.Service) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "channel-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}, &model.Comment{}, &model.CommentLike{}, &model.NotificationPreferences{}, &model.DynamicSetting{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	users := repository.NewUserRepo(db)
	comments := repository.NewCommentRepo(db)
	threads := repository.NewThreadRepo(db)
	prefs := repository.NewPreferenceRepo(db)
	sites := repository.NewSiteRepo(db)
	settingsSvc := setting.NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	reader := &fakeChannelReader{providers: providers}
	dispatcher := &fakeChannelDispatcher{errBy: errBy}
	svc := NewService(users, comments, threads, prefs, nil, settingsSvc, sites, reader, dispatcher, nil, nil, nil, fakeSigner{}, "https://furtalk.example.com", nil)
	return db, svc, dispatcher, settingsSvc
}

// telegramProvider 返回一个已配置的 Telegram 通道。
func telegramProvider() setting.NotificationProvider {
	return setting.NotificationProvider{
		ProviderKey: "notification.telegram",
		Enabled:     true,
		Configured:  true,
		Config: setting.NotificationConfig{
			BotToken: "tok",
			ChatID:   "123",
		},
	}
}

// webhookProvider 返回一个已配置的通用 WebHook 通道。
func webhookProvider(secret *string) setting.NotificationProvider {
	return setting.NotificationProvider{
		ProviderKey: "notification.webhook",
		Enabled:     true,
		Configured:  true,
		Config: setting.NotificationConfig{
			WebhookURL:    "http://127.0.0.1:9000/hook",
			SigningSecret: secret,
		},
	}
}

// createdEvent 构造一条 comment.created 事件。
func createdEvent(fx notificationFixture) domain.CommentEvent {
	return domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	}
}

// TestChannelDeliveryPublished 验证 published 评论向全部已启用通道各投递一次。
func TestChannelDeliveryPublished(t *testing.T) {
	providers := []setting.NotificationProvider{telegramProvider(), webhookProvider(nil)}
	db, svc, dispatcher, _ := newChannelHarness(t, providers, nil)
	fx := seedNotificationData(t, db)

	svc.handle(context.Background(), createdEvent(fx))

	if dispatcher.count() != 2 {
		t.Fatalf("dispatches = %d, want 2", dispatcher.count())
	}
	platforms := map[notifier.Platform]bool{}
	for _, cfg := range dispatcher.configs {
		platforms[cfg.Platform] = true
	}
	if !platforms[notifier.PlatformTelegram] || !platforms[notifier.PlatformWebHook] {
		t.Fatalf("platforms = %v, want telegram + webhook", platforms)
	}
}

// TestChannelDeliveryPending 验证 pending 评论投递 pending_comment 通知。
func TestChannelDeliveryPending(t *testing.T) {
	db, svc, dispatcher, _ := newChannelHarness(t, []setting.NotificationProvider{webhookProvider(nil)}, nil)
	fx := seedNotificationData(t, db)
	setCommentStatus(t, db, fx.CommentID, domain.CommentStatusPending)

	svc.handle(context.Background(), createdEvent(fx))

	if dispatcher.count() != 1 {
		t.Fatalf("dispatches = %d, want 1", dispatcher.count())
	}
	var env map[string]any
	if err := json.Unmarshal(dispatcher.messages[0].WebHookRaw, &env); err != nil {
		t.Fatalf("decode webhook raw: %v", err)
	}
	if env["notification_type"] != "pending_comment" {
		t.Fatalf("notification_type = %v, want pending_comment", env["notification_type"])
	}
	if env["event"] != "comment.created" {
		t.Fatalf("event = %v, want comment.created", env["event"])
	}
}

// TestChannelNoDeliveryForSpam 验证 spam 状态不投递通道。
func TestChannelNoDeliveryForSpam(t *testing.T) {
	db, svc, dispatcher, _ := newChannelHarness(t, []setting.NotificationProvider{telegramProvider()}, nil)
	fx := seedNotificationData(t, db)
	setCommentStatus(t, db, fx.CommentID, domain.CommentStatusSpam)

	svc.handle(context.Background(), createdEvent(fx))

	if dispatcher.count() != 0 {
		t.Fatalf("dispatches = %d, want 0 for spam", dispatcher.count())
	}
}

// TestChannelNoDeliveryForPublishedEvent 验证 comment.published 事件不投递通道。
func TestChannelNoDeliveryForPublishedEvent(t *testing.T) {
	db, svc, dispatcher, _ := newChannelHarness(t, []setting.NotificationProvider{telegramProvider()}, nil)
	fx := seedNotificationData(t, db)

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentPublished,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if dispatcher.count() != 0 {
		t.Fatalf("dispatches = %d, want 0 for published event", dispatcher.count())
	}
}

// TestChannelMessageFields 验证通道消息包含站点/页面/作者/正文/状态/时间，
// 且不含邮箱、IP、UA。
func TestChannelMessageFields(t *testing.T) {
	db, svc, dispatcher, _ := newChannelHarness(t, []setting.NotificationProvider{telegramProvider(), webhookProvider(nil)}, nil)
	fx := seedNotificationData(t, db)

	svc.handle(context.Background(), createdEvent(fx))

	if dispatcher.count() != 2 {
		t.Fatalf("dispatches = %d, want 2", dispatcher.count())
	}
	for _, msg := range dispatcher.messages {
		// 纯文本包含站点名、页面、作者昵称、状态与正文。
		for _, want := range []string{"站点：Site", "测试页面", "https://example.com/blog/post?utm=1", "author", "published", "new comment body"} {
			if !strings.Contains(msg.Text, want) {
				t.Fatalf("text missing %q: %q", want, msg.Text)
			}
		}
		// 绝不包含邮箱/IP/UA。
		for _, banned := range []string{"author@example.com", "admin@example.com", "1.2.3.4", "Mozilla", "User-Agent"} {
			if strings.Contains(msg.Text, banned) {
				t.Fatalf("text leaks %q: %q", banned, msg.Text)
			}
		}
		// WebHook 信封字段完整且为十进制字符串 ID。
		var env map[string]any
		if err := json.Unmarshal(msg.WebHookRaw, &env); err != nil {
			t.Fatalf("decode webhook raw: %v", err)
		}
		if env["version"] != "1" || env["event"] != "comment.created" {
			t.Fatalf("envelope header = %v", env)
		}
		siteObj := env["site"].(map[string]any)
		if siteObj["id"] != itoa64(fx.SiteID) {
			t.Fatalf("site.id = %v, want decimal %d", siteObj["id"], fx.SiteID)
		}
		commentObj := env["comment"].(map[string]any)
		if commentObj["id"] != itoa64(fx.CommentID) {
			t.Fatalf("comment.id = %v, want decimal %d", commentObj["id"], fx.CommentID)
		}
		if commentObj["parent_id"] != itoa64(fx.ParentID) {
			t.Fatalf("comment.parent_id = %v, want decimal %d", commentObj["parent_id"], fx.ParentID)
		}
		raw, _ := json.Marshal(env)
		body := string(raw)
		for _, banned := range []string{"author@example.com", "admin@example.com"} {
			if strings.Contains(body, banned) {
				t.Fatalf("envelope leaks %q: %s", banned, body)
			}
		}
	}
}

// TestChannelFailureIsolation 验证一个通道失败不阻止其他通道与继续投递。
func TestChannelFailureIsolation(t *testing.T) {
	providers := []setting.NotificationProvider{telegramProvider(), webhookProvider(nil)}
	errBy := map[string]error{string(notifier.PlatformTelegram): notifier.ErrDelivery}
	db, svc, dispatcher, _ := newChannelHarness(t, providers, errBy)
	fx := seedNotificationData(t, db)

	svc.handle(context.Background(), createdEvent(fx))

	// 两个通道都被尝试，其中一个失败只记录日志。
	if dispatcher.count() != 2 {
		t.Fatalf("dispatches = %d, want 2 (both attempted)", dispatcher.count())
	}
}

// TestChannelSMTPNilStillDelivers 验证 SMTP 缺失（mailer=nil）时非邮件通道仍投递。
func TestChannelSMTPNilStillDelivers(t *testing.T) {
	db, svc, dispatcher, _ := newChannelHarness(t, []setting.NotificationProvider{telegramProvider()}, nil)
	if svc.mailer != nil {
		t.Fatal("harness must run with nil mailer")
	}
	fx := seedNotificationData(t, db)
	svc.handle(context.Background(), createdEvent(fx))
	if dispatcher.count() != 1 {
		t.Fatalf("dispatches = %d, want 1 with nil mailer", dispatcher.count())
	}
}

// TestChannelReaderErrorSkips 验证通道读取失败只记录日志，不 panic。
func TestChannelReaderErrorSkips(t *testing.T) {
	db, svc, dispatcher, _ := newChannelHarness(t, nil, nil)
	svc.channels = &fakeChannelReader{err: context.Canceled}
	fx := seedNotificationData(t, db)
	svc.handle(context.Background(), createdEvent(fx))
	if dispatcher.count() != 0 {
		t.Fatalf("dispatches = %d, want 0 on reader error", dispatcher.count())
	}
}

// setCommentStatus 直接更新评论状态（测试辅助）。
func setCommentStatus(t *testing.T, db *gorm.DB, commentID int64, status domain.CommentStatus) {
	t.Helper()
	if err := db.Model(&model.Comment{}).Where("id = ?", commentID).Update("status", string(status)).Error; err != nil {
		t.Fatalf("set status %s: %v", status, err)
	}
}

// itoa64 十进制格式化辅助。
func itoa64(v int64) string {
	return strconv.FormatInt(v, 10)
}

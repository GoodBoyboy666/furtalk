package notification

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/setting"

	"gorm.io/gorm"
)

// captureMailer 记录全部投递消息。
type captureMailer struct {
	messages []mailer.Message
}

func (m *captureMailer) Send(ctx context.Context, msg mailer.Message) error {
	m.messages = append(m.messages, msg)
	return nil
}

// recordingRenderer 记录各场景模板数据并返回可预测的 HTML。
type recordingRenderer struct {
	moderation *mailer.ModerationData
	published  *mailer.PublishedData
	reply      *mailer.ReplyData
}

func (r *recordingRenderer) LoginCode(d mailer.LoginCodeData) (string, error) {
	return "<p>login</p>", nil
}

func (r *recordingRenderer) PasswordResetCode(d mailer.PasswordResetCodeData) (string, error) {
	return "<p>reset</p>", nil
}

func (r *recordingRenderer) Moderation(d mailer.ModerationData) (string, error) {
	r.moderation = &d
	return "<p>moderation</p>", nil
}

func (r *recordingRenderer) Published(d mailer.PublishedData) (string, error) {
	r.published = &d
	return "<p>published</p>", nil
}

func (r *recordingRenderer) Reply(d mailer.ReplyData) (string, error) {
	r.reply = &d
	return "<p>reply</p>", nil
}

// fakeSigner 生成确定性的退订令牌。
type fakeSigner struct{}

func (fakeSigner) SignUnsubscribe(userID int64, kind string, _ time.Duration) (string, error) {
	return "token-" + strconv.FormatInt(userID, 10) + "-" + kind, nil
}

func (fakeSigner) ParseUnsubscribe(string) (int64, string, error) { return 0, "", nil }

// notificationFixture 是一次通知测试的种子数据。
type notificationFixture struct {
	SiteID       int64
	ThreadID     int64
	AdminID      int64
	AuthorID     int64
	ParentUserID int64
	CommentID    int64
	ParentID     int64
}

// newNotificationHarness 打开临时 SQLite 数据库，迁移全部通知相关表并装配服务。
func newNotificationHarness(t *testing.T) (*gorm.DB, *Service, *captureMailer, *recordingRenderer, *setting.Service) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "notification-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}, &model.Comment{}, &model.NotificationPreferences{}, &model.DynamicSetting{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	users := repository.NewUserRepo(db)
	comments := repository.NewCommentRepo(db)
	prefs := repository.NewPreferenceRepo(db)
	settingsSvc := setting.NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))

	mailer := &captureMailer{}
	renderer := &recordingRenderer{}
	svc := NewService(users, comments, prefs, nil, settingsSvc, nil, mailer, renderer, fakeSigner{}, "https://furtalk.example.com", nil)
	return db, svc, mailer, renderer, settingsSvc
}

// seedNotificationData 插入站点、线程、管理员、作者、父评论作者与两条评论。
func seedNotificationData(t *testing.T, db *gorm.DB) notificationFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	users := repository.NewUserRepo(db)
	comments := repository.NewCommentRepo(db)

	admin := &domain.User{Email: "admin@example.com", EmailNormalized: "admin@example.com", Nickname: "admin", Role: domain.RoleAdmin, Status: domain.UserStatusActive}
	if err := users.Create(ctx, admin); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	author := &domain.User{Email: "author@example.com", EmailNormalized: "author@example.com", Nickname: "author", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := users.Create(ctx, author); err != nil {
		t.Fatalf("create author: %v", err)
	}
	parentUser := &domain.User{Email: "parent@example.com", EmailNormalized: "parent@example.com", Nickname: "parent", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := users.Create(ctx, parentUser); err != nil {
		t.Fatalf("create parent user: %v", err)
	}

	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := repository.NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, site.ID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}

	parent := &domain.Comment{
		SiteID:       site.ID,
		ThreadID:     thread.ID,
		UserID:       parentUser.ID,
		Depth:        0,
		BodyMarkdown: "parent comment body",
		Status:       domain.CommentStatusPublished,
		IPMode:       domain.PrivacyModeNone,
		UAMode:       domain.PrivacyModeNone,
		CreatedAt:    now,
		UpdatedAt:    now,
		PublishedAt:  &now,
	}
	if err := comments.Create(ctx, parent); err != nil {
		t.Fatalf("create parent comment: %v", err)
	}

	comment := &domain.Comment{
		SiteID:       site.ID,
		ThreadID:     thread.ID,
		UserID:       author.ID,
		ParentID:     &parent.ID,
		RootID:       &parent.ID,
		Depth:        1,
		BodyMarkdown: "new comment body",
		Status:       domain.CommentStatusPublished,
		IPMode:       domain.PrivacyModeNone,
		UAMode:       domain.PrivacyModeNone,
		CreatedAt:    now,
		UpdatedAt:    now,
		PublishedAt:  &now,
	}
	if err := comments.Create(ctx, comment); err != nil {
		t.Fatalf("create comment: %v", err)
	}

	return notificationFixture{
		SiteID:       site.ID,
		ThreadID:     thread.ID,
		AdminID:      admin.ID,
		AuthorID:     author.ID,
		ParentUserID: parentUser.ID,
		CommentID:    comment.ID,
		ParentID:     parent.ID,
	}
}

// TestHandleCreatedSendsModerationMailToAdmins 证明新评论事件在 direct 策略下
// 向管理员发送新评论通知，模板数据携带作者昵称与评论正文；同时发布的回复
// 经创建路径向父评论作者发送回复通知。
func TestHandleCreatedSendsModerationMailToAdmins(t *testing.T) {
	db, svc, mailer, renderer, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 2 {
		t.Fatalf("messages = %d, want 2 (moderation + reply)", len(mailer.messages))
	}
	if mailer.messages[0].To != "admin@example.com" {
		t.Fatalf("to = %q, want admin", mailer.messages[0].To)
	}
	if renderer.moderation == nil {
		t.Fatal("moderation template was not rendered")
	}
	if renderer.moderation.AuthorNickname != "author" {
		t.Fatalf("author nickname = %q, want author", renderer.moderation.AuthorNickname)
	}
	if renderer.moderation.CommentBody != "new comment body" {
		t.Fatalf("comment body = %q, want new comment body", renderer.moderation.CommentBody)
	}
	if renderer.moderation.AwaitingModeration {
		t.Fatal("direct moderation must set AwaitingModeration = false")
	}
	if mailer.messages[0].Subject != "新评论" {
		t.Fatalf("subject = %q, want 新评论", mailer.messages[0].Subject)
	}
	if mailer.messages[1].To != "parent@example.com" {
		t.Fatalf("reply mail to = %q, want parent", mailer.messages[1].To)
	}
	if mailer.messages[1].Subject != "您有一条新回复" {
		t.Fatalf("reply subject = %q, want 您有一条新回复", mailer.messages[1].Subject)
	}
}

// TestHandleCreatedSkipsAdminAuthorButKeepsOtherAdmins 证明管理员作者不会收到
// 自己触发的新评论通知，但其他活跃管理员与被回复者仍会收到各自通知。
func TestHandleCreatedSkipsAdminAuthorButKeepsOtherAdmins(t *testing.T) {
	db, svc, mailer, _, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	users := repository.NewUserRepo(db)
	if err := users.UpdateRoleStatus(ctx, fx.AuthorID, domain.RoleAdmin, domain.UserStatusActive); err != nil {
		t.Fatalf("promote author to admin: %v", err)
	}
	otherAdmin := &domain.User{
		Email:           "other-admin@example.com",
		EmailNormalized: "other-admin@example.com",
		Nickname:        "other admin",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
	}
	if err := users.Create(ctx, otherAdmin); err != nil {
		t.Fatalf("create other admin: %v", err)
	}

	svc.handle(ctx, domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	moderationRecipients := make(map[string]bool)
	for _, msg := range mailer.messages {
		if msg.Subject == "新评论" {
			moderationRecipients[msg.To] = true
		}
	}
	if len(moderationRecipients) != 2 || !moderationRecipients["admin@example.com"] || !moderationRecipients[otherAdmin.Email] {
		t.Fatalf("moderation recipients = %#v, want the two non-author admins", moderationRecipients)
	}
	if moderationRecipients["author@example.com"] {
		t.Fatal("comment author must not receive their own moderation mail")
	}
	if len(mailer.messages) != 3 {
		t.Fatalf("messages = %d, want 3 (two moderation + reply)", len(mailer.messages))
	}
	if mailer.messages[2].To != "parent@example.com" || mailer.messages[2].Subject != "您有一条新回复" {
		t.Fatalf("reply mail = %+v, want parent reply notification", mailer.messages[2])
	}
}

// TestHandleCreatedSkipsAdminAuthorInReviewMode 证明审核模式下管理员作者的
// 待审核根评论不会通知作者本人，但仍会通知其他活跃管理员。
func TestHandleCreatedSkipsAdminAuthorInReviewMode(t *testing.T) {
	db, svc, mailer, _, settingsSvc := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	users := repository.NewUserRepo(db)
	if err := users.UpdateRoleStatus(ctx, fx.AuthorID, domain.RoleAdmin, domain.UserStatusActive); err != nil {
		t.Fatalf("promote author to admin: %v", err)
	}
	otherAdmin := &domain.User{
		Email:           "other-admin@example.com",
		EmailNormalized: "other-admin@example.com",
		Nickname:        "other admin",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
	}
	if err := users.Create(ctx, otherAdmin); err != nil {
		t.Fatalf("create other admin: %v", err)
	}
	if _, err := settingsSvc.Patch(ctx, []setting.SettingItem{
		{Key: setting.SettingKeyModeration, Type: setting.SettingTypeString, Value: domain.ModerationReview},
	}, 1); err != nil {
		t.Fatalf("patch moderation: %v", err)
	}

	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	root := &domain.Comment{
		SiteID:       fx.SiteID,
		ThreadID:     fx.ThreadID,
		UserID:       fx.AuthorID,
		Depth:        0,
		BodyMarkdown: "pending root",
		Status:       domain.CommentStatusPending,
		IPMode:       domain.PrivacyModeNone,
		UAMode:       domain.PrivacyModeNone,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := repository.NewCommentRepo(db).Create(ctx, root); err != nil {
		t.Fatalf("create pending root: %v", err)
	}

	svc.handle(ctx, domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: root.ID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 2 {
		t.Fatalf("messages = %d, want 2 (other admins only)", len(mailer.messages))
	}
	for _, msg := range mailer.messages {
		if msg.Subject != "评论待审核" {
			t.Fatalf("message = %+v, want pending moderation mail", msg)
		}
		if msg.To == "author@example.com" {
			t.Fatal("comment author must not receive their own pending moderation mail")
		}
	}
	got := map[string]bool{mailer.messages[0].To: true, mailer.messages[1].To: true}
	if !got["admin@example.com"] || !got[otherAdmin.Email] {
		t.Fatalf("moderation recipients = %#v, want both non-author admins", got)
	}
}

// TestHandleCreatedAwaitingModeration 证明审核模式为 review 时主题与模板数据
// 切换为待审核；待审核评论不产生回复通知。
func TestHandleCreatedAwaitingModeration(t *testing.T) {
	db, svc, mailer, renderer, settingsSvc := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	if _, err := settingsSvc.Patch(context.Background(), []setting.SettingItem{
		{Key: setting.SettingKeyModeration, Type: setting.SettingTypeString, Value: domain.ModerationReview},
	}, 1); err != nil {
		t.Fatalf("patch moderation: %v", err)
	}
	// review 模式下新评论持久化为 pending，把种子状态修正为 pending 后触发创建事件。
	comments := repository.NewCommentRepo(db)
	if err := comments.UpdateStatus(context.Background(), fx.SiteID, fx.CommentID, domain.CommentStatusPending, nil, nil, nil); err != nil {
		t.Fatalf("set pending: %v", err)
	}

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (awaiting moderation only)", len(mailer.messages))
	}
	if mailer.messages[0].Subject != "评论待审核" {
		t.Fatalf("subject = %q, want 评论待审核", mailer.messages[0].Subject)
	}
	if renderer.moderation == nil || !renderer.moderation.AwaitingModeration {
		t.Fatal("AwaitingModeration must be true under review mode")
	}
}

// TestHandleCreatedSkipsModerationMailsButKeepsReplyNotifications 证明关闭
// 管理员审核通知开关只跳过审核邮件，direct 发布的回复通知仍经创建路径发送。
func TestHandleCreatedSkipsModerationMailsButKeepsReplyNotifications(t *testing.T) {
	db, svc, mailer, _, settingsSvc := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	if _, err := settingsSvc.Patch(context.Background(), []setting.SettingItem{
		{Key: setting.SettingKeyNotifications, Type: setting.SettingTypeJSON, Value: map[string]any{"moderation": false, "replies": true}},
	}, 1); err != nil {
		t.Fatalf("patch notifications: %v", err)
	}

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (reply only)", len(mailer.messages))
	}
	if mailer.messages[0].To != "parent@example.com" {
		t.Fatalf("to = %q, want parent reply", mailer.messages[0].To)
	}
	if mailer.messages[0].Subject != "您有一条新回复" {
		t.Fatalf("subject = %q, want 您有一条新回复", mailer.messages[0].Subject)
	}
}

// TestHandleCreatedDirectRootSkipsReplyNotification 证明 direct 策略下根评论
// 经创建路径只发送管理员审核通知，不进入回复通知流程。
func TestHandleCreatedDirectRootSkipsReplyNotification(t *testing.T) {
	db, svc, mailer, _, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	comments := repository.NewCommentRepo(db)

	root := &domain.Comment{
		SiteID:       fx.SiteID,
		ThreadID:     fx.ThreadID,
		UserID:       fx.AuthorID,
		Depth:        0,
		BodyMarkdown: "root comment",
		Status:       domain.CommentStatusPublished,
		IPMode:       domain.PrivacyModeNone,
		UAMode:       domain.PrivacyModeNone,
		CreatedAt:    now,
		UpdatedAt:    now,
		PublishedAt:  &now,
	}
	if err := comments.Create(ctx, root); err != nil {
		t.Fatalf("create root: %v", err)
	}

	svc.handle(ctx, domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: root.ID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (admin moderation only)", len(mailer.messages))
	}
	if mailer.messages[0].To != "admin@example.com" {
		t.Fatalf("to = %q, want admin only", mailer.messages[0].To)
	}
}

// TestHandlePublishedSendsToAuthorAndParent 证明发布事件向作者发送发布通知，
// 向父评论作者发送含退订链接的回复通知，且退订 URL 在渲染前生成。
func TestHandlePublishedSendsToAuthorAndParent(t *testing.T) {
	db, svc, mailer, renderer, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentPublished,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
		ParentID:  &fx.ParentID,
	})

	if len(mailer.messages) != 2 {
		t.Fatalf("messages = %d, want 2 (published + reply)", len(mailer.messages))
	}

	published := mailer.messages[0]
	if published.To != "author@example.com" || published.Subject != "您的评论已发布" {
		t.Fatalf("published mail = %+v", published)
	}
	if renderer.published == nil || renderer.published.AuthorNickname != "author" || renderer.published.CommentBody != "new comment body" {
		t.Fatalf("published data = %+v", renderer.published)
	}
	wantPublishedUnsub := "https://furtalk.example.com/unsubscribe?token=token-" + strconv.FormatInt(fx.AuthorID, 10) + "-moderation"
	if renderer.published.UnsubscribeURL != wantPublishedUnsub {
		t.Fatalf("published UnsubscribeURL = %q, want %q", renderer.published.UnsubscribeURL, wantPublishedUnsub)
	}
	if !strings.Contains(published.TextBody, wantPublishedUnsub) {
		t.Fatalf("published mail text must contain the same unsubscribe URL: %q", published.TextBody)
	}

	reply := mailer.messages[1]
	if reply.To != "parent@example.com" || reply.Subject != "您有一条新回复" {
		t.Fatalf("reply mail = %+v", reply)
	}
	if renderer.reply == nil {
		t.Fatal("reply template was not rendered")
	}
	if renderer.reply.ReplyAuthorNickname != "author" || renderer.reply.ParentAuthorNickname != "parent" {
		t.Fatalf("reply data = %+v", renderer.reply)
	}
	if renderer.reply.ReplyBody != "new comment body" || renderer.reply.ParentCommentBody != "parent comment body" {
		t.Fatalf("reply bodies = %+v", renderer.reply)
	}
	wantUnsub := "https://furtalk.example.com/unsubscribe?token=token-" + strconv.FormatInt(fx.ParentUserID, 10) + "-reply"
	if renderer.reply.UnsubscribeURL != wantUnsub {
		t.Fatalf("reply UnsubscribeURL = %q, want %q", renderer.reply.UnsubscribeURL, wantUnsub)
	}
	if !strings.Contains(reply.TextBody, wantUnsub) {
		t.Fatalf("reply mail text must contain the same unsubscribe URL: %q", reply.TextBody)
	}
}

// TestHandlePublishedSkipsReplyWhenParentIsSelf 证明回复自己的评论不发送回复通知。
func TestHandlePublishedSkipsReplyWhenParentIsSelf(t *testing.T) {
	db, svc, mailer, _, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	comments := repository.NewCommentRepo(db)

	// 父评论属于作者本人，子评论也属于作者：回复自己时不发回复通知。
	selfParent := &domain.Comment{
		SiteID:       fx.SiteID,
		ThreadID:     fx.ThreadID,
		UserID:       fx.AuthorID,
		Depth:        0,
		BodyMarkdown: "own comment",
		Status:       domain.CommentStatusPublished,
		IPMode:       domain.PrivacyModeNone,
		UAMode:       domain.PrivacyModeNone,
		CreatedAt:    now,
		UpdatedAt:    now,
		PublishedAt:  &now,
	}
	if err := comments.Create(ctx, selfParent); err != nil {
		t.Fatalf("create self parent: %v", err)
	}
	selfReply := &domain.Comment{
		SiteID:       fx.SiteID,
		ThreadID:     fx.ThreadID,
		UserID:       fx.AuthorID,
		ParentID:     &selfParent.ID,
		RootID:       &selfParent.ID,
		Depth:        1,
		BodyMarkdown: "self reply",
		Status:       domain.CommentStatusPublished,
		IPMode:       domain.PrivacyModeNone,
		UAMode:       domain.PrivacyModeNone,
		CreatedAt:    now,
		UpdatedAt:    now,
		PublishedAt:  &now,
	}
	if err := comments.Create(ctx, selfReply); err != nil {
		t.Fatalf("create self reply: %v", err)
	}

	svc.handle(ctx, domain.CommentEvent{
		Type:      domain.TypeCommentPublished,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: selfReply.ID,
		UserID:    fx.AuthorID,
		ParentID:  &selfParent.ID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (published only, no self reply)", len(mailer.messages))
	}
	if mailer.messages[0].To != "author@example.com" {
		t.Fatalf("only the author mail expected, got %+v", mailer.messages[0])
	}
}

// TestSendAppendsUnsubscribeHtmlOnceForReply 证明回复邮件只在模板内联退订链接，
// send 不重复追加 HTML 退订块。
func TestSendAppendsUnsubscribeHtmlOnceForReply(t *testing.T) {
	_, svc, cap, _, _ := newNotificationHarness(t)
	svc.send(context.Background(), 1, mailer.Message{
		To:       "parent@example.com",
		Subject:  "您有一条新回复",
		TextBody: "body",
		HTMLBody: "<p>reply</p>",
	}, "https://furtalk.example.com/unsubscribe?token=t", true)

	if len(cap.messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(cap.messages))
	}
	msg := cap.messages[0]
	if strings.Count(msg.HTMLBody, "unsubscribe") != 0 {
		t.Fatalf("reply HTML must not duplicate the unsubscribe block, got: %s", msg.HTMLBody)
	}
	if strings.Count(msg.TextBody, "unsubscribe") != 1 {
		t.Fatalf("reply text must contain one unsubscribe line, got: %s", msg.TextBody)
	}
}

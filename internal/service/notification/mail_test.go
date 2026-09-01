package notification

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

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
func newNotificationHarness(t *testing.T) (*gorm.DB, *Service, *captureMailer, *recordingRenderer, *fakeSettingsReader) {
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
	if err := database.AutoMigrate(db, &model.User{}, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}, &model.Comment{}, &model.CommentLike{}, &model.NotificationPreferences{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	users := repository.NewUserRepo(db)
	comments := repository.NewCommentRepo(db)
	threads := repository.NewThreadRepo(db)
	prefs := repository.NewPreferenceRepo(db)
	settings := newFakeSettingsReader()

	mailer := &captureMailer{}
	renderer := &recordingRenderer{}
	svc := NewService(users, comments, threads, prefs, nil, settings, nil, nil, nil, nil, mailer, renderer, fakeSigner{}, "https://furtalk.example.com", nil)
	return db, svc, mailer, renderer, settings
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
	pageURL := "https://example.com/blog/post?utm=1"
	pageTitle := "测试页面"
	thread, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, site.ID, "page-key", &pageURL, &pageTitle)
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

// TestHandleCreatedReadsCommittedThreadMetadata 证明消费者按评论的
// (site_id, thread_id) 读取线程元数据时，看到的是评论创建事务提交后的值
// （先 NULL 后提交 page_url），而非事务前预读的旧快照（AC4）。
func TestHandleCreatedReadsCommittedThreadMetadata(t *testing.T) {
	db, svc, _, renderer, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	if err := db.Model(&model.Thread{}).Where("id = ?", fx.ThreadID).
		Updates(map[string]any{"page_url": nil, "page_title": nil}).Error; err != nil {
		t.Fatalf("clear thread metadata: %v", err)
	}
	pageURL := "https://example.com/committed?tab=2"
	pageTitle := "提交后的页面"
	if err := db.Model(&model.Thread{}).Where("id = ?", fx.ThreadID).
		Updates(map[string]any{"page_url": pageURL, "page_title": pageTitle}).Error; err != nil {
		t.Fatalf("commit thread metadata: %v", err)
	}

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if renderer.moderation.PageTitle != pageTitle || renderer.moderation.PageURL != pageURL {
		t.Fatalf("moderation page data = %q/%q, want committed %q/%q",
			renderer.moderation.PageTitle, renderer.moderation.PageURL, pageTitle, pageURL)
	}
	if renderer.reply.PageURL != pageURL {
		t.Fatalf("reply page url = %q, want committed %q", renderer.reply.PageURL, pageURL)
	}
}

// TestHandleCreatedDeliversWithoutPageMetadata 证明线程缺少页面标题/网址时，
// 审核邮件仍正常生成，页面数据为空且不渲染页面块（R7）。
func TestHandleCreatedDeliversWithoutPageMetadata(t *testing.T) {
	db, svc, mailer, renderer, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	if err := db.Model(&model.Thread{}).Where("id = ?", fx.ThreadID).
		Updates(map[string]any{"page_url": nil, "page_title": nil}).Error; err != nil {
		t.Fatalf("clear thread metadata: %v", err)
	}

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
	if renderer.moderation.PageTitle != "" || renderer.moderation.PageURL != "" {
		t.Fatalf("moderation page data = %q/%q, want empty", renderer.moderation.PageTitle, renderer.moderation.PageURL)
	}
	if strings.Contains(mailer.messages[0].TextBody, "页面：") {
		t.Fatalf("moderation text must not contain page block: %q", mailer.messages[0].TextBody)
	}
	if renderer.reply.PageTitle != "" || renderer.reply.PageURL != "" {
		t.Fatalf("reply page data = %q/%q, want empty", renderer.reply.PageTitle, renderer.reply.PageURL)
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
	if renderer.moderation.PageTitle != "测试页面" {
		t.Fatalf("moderation page title = %q, want 测试页面", renderer.moderation.PageTitle)
	}
	if renderer.moderation.PageURL != "https://example.com/blog/post?utm=1" {
		t.Fatalf("moderation page url = %q, want page url", renderer.moderation.PageURL)
	}
	if !strings.Contains(mailer.messages[0].TextBody, "https://example.com/blog/post?utm=1") {
		t.Fatalf("moderation text must contain the page url: %q", mailer.messages[0].TextBody)
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
	if renderer.reply == nil {
		t.Fatal("reply template was not rendered")
	}
	if renderer.reply.PageTitle != "测试页面" {
		t.Fatalf("reply page title = %q, want 测试页面", renderer.reply.PageTitle)
	}
	if renderer.reply.PageURL != "https://example.com/blog/post?utm=1" {
		t.Fatalf("reply page url = %q, want page url", renderer.reply.PageURL)
	}
	if !strings.Contains(mailer.messages[1].TextBody, "https://example.com/blog/post?utm=1") {
		t.Fatalf("reply text must contain the page url: %q", mailer.messages[1].TextBody)
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
	db, svc, mailer, renderer, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
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

// TestHandleCreatedSpamWording 证明垃圾检测标记的评论按实际状态发送“垃圾”审核邮件，
// 不产生回复通知，AwaitingModeration 为 false。
func TestHandleCreatedSpamWording(t *testing.T) {
	db, svc, mailer, renderer, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	comments := repository.NewCommentRepo(db)
	if err := comments.UpdateStatus(context.Background(), fx.SiteID, fx.CommentID, domain.CommentStatusSpam, nil, nil, nil); err != nil {
		t.Fatalf("set spam: %v", err)
	}

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (spam moderation only, no reply)", len(mailer.messages))
	}
	if mailer.messages[0].Subject != "评论被标记为垃圾" {
		t.Fatalf("subject = %q, want 评论被标记为垃圾", mailer.messages[0].Subject)
	}
	if renderer.moderation == nil || renderer.moderation.AwaitingModeration {
		t.Fatal("AwaitingModeration must be false for spam")
	}
	if renderer.reply != nil {
		t.Fatal("spam comment must not trigger reply notification")
	}
}

// TestHandleCreatedSkipsModerationMailsButKeepsReplyNotifications 证明关闭
// 管理员审核通知开关只跳过审核邮件，direct 发布的回复通知仍经创建路径发送。
func TestHandleCreatedSkipsModerationMailsButKeepsReplyNotifications(t *testing.T) {
	db, svc, mailer, _, settings := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	settings.set(Settings{Moderation: false, Replies: true})

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

// TestHandleCreatedDedupesAdminParentFromModerationMail 证明直接发布的回复中，
// 父评论作者同时是活跃管理员时只收到“您有一条新回复”，不再收到同一评论的
// “新评论”管理员邮件；其他活跃管理员仍各自收到“新评论”（R1/R2）。
func TestHandleCreatedDedupesAdminParentFromModerationMail(t *testing.T) {
	db, svc, mailer, _, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	users := repository.NewUserRepo(db)
	if err := users.UpdateRoleStatus(ctx, fx.ParentUserID, domain.RoleAdmin, domain.UserStatusActive); err != nil {
		t.Fatalf("promote parent user to admin: %v", err)
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

	replyCount := 0
	moderationRecipients := make(map[string]bool)
	for _, msg := range mailer.messages {
		switch msg.Subject {
		case "您有一条新回复":
			replyCount++
			if msg.To != "parent@example.com" {
				t.Fatalf("reply mail to = %q, want parent", msg.To)
			}
		case "新评论":
			moderationRecipients[msg.To] = true
		default:
			t.Fatalf("unexpected message: %+v", msg)
		}
	}
	if replyCount != 1 {
		t.Fatalf("reply mails = %d, want 1", replyCount)
	}
	if moderationRecipients["parent@example.com"] {
		t.Fatal("parent author admin must not receive the moderation mail for the reply to their own comment")
	}
	if len(moderationRecipients) != 2 || !moderationRecipients["admin@example.com"] || !moderationRecipients[otherAdmin.Email] {
		t.Fatalf("moderation recipients = %#v, want the two non-parent admins", moderationRecipients)
	}
}

// TestHandleCreatedAdminParentReplySuppressedSkipsBothMails 证明关闭全局回复
// 开关时，父评论作者（管理员）既收不到回复邮件，也因结构性排除收不到该评论
// 的管理员新评论邮件；其他活跃管理员的新评论邮件保留（R1/R4）。
func TestHandleCreatedAdminParentReplySuppressedSkipsBothMails(t *testing.T) {
	db, svc, mailer, _, settings := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	users := repository.NewUserRepo(db)
	if err := users.UpdateRoleStatus(ctx, fx.ParentUserID, domain.RoleAdmin, domain.UserStatusActive); err != nil {
		t.Fatalf("promote parent user to admin: %v", err)
	}
	settings.set(Settings{Moderation: true, Replies: false})

	svc.handle(ctx, domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (admin moderation only)", len(mailer.messages))
	}
	if mailer.messages[0].To != "admin@example.com" || mailer.messages[0].Subject != "新评论" {
		t.Fatalf("message = %+v, want admin moderation only", mailer.messages[0])
	}
}

// TestHandleCreatedAdminParentReplyDisabledSkipsBothMails 证明父评论作者
// （管理员）关闭个人回复偏好时，既收不到回复邮件，也因结构性排除收不到该评论
// 的管理员新评论邮件（R1 边界/R5）。
func TestHandleCreatedAdminParentReplyDisabledSkipsBothMails(t *testing.T) {
	db, svc, mailer, _, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	users := repository.NewUserRepo(db)
	if err := users.UpdateRoleStatus(ctx, fx.ParentUserID, domain.RoleAdmin, domain.UserStatusActive); err != nil {
		t.Fatalf("promote parent user to admin: %v", err)
	}
	if err := repository.NewPreferenceRepo(db).Upsert(ctx, &domain.NotificationPreferences{
		UserID:            fx.ParentUserID,
		ReplyEnabled:      false,
		ModerationEnabled: true,
	}); err != nil {
		t.Fatalf("upsert preferences: %v", err)
	}

	svc.handle(ctx, domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (admin moderation only)", len(mailer.messages))
	}
	if mailer.messages[0].To != "admin@example.com" || mailer.messages[0].Subject != "新评论" {
		t.Fatalf("message = %+v, want admin moderation only", mailer.messages[0])
	}
}

// TestHandleCreatedRepliesOffSkipsReplyToNormalParent 证明关闭全局回复开关时，
// direct 模式创建路径不再向普通父评论作者发送回复邮件，管理员新评论邮件保留
// （R4）。
func TestHandleCreatedRepliesOffSkipsReplyToNormalParent(t *testing.T) {
	db, svc, mailer, _, settings := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	settings.set(Settings{Moderation: true, Replies: false})

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (moderation only)", len(mailer.messages))
	}
	if mailer.messages[0].To != "admin@example.com" || mailer.messages[0].Subject != "新评论" {
		t.Fatalf("message = %+v, want admin moderation only", mailer.messages[0])
	}
}

func TestModerationRecipientsAreCappedAfterExclusions(t *testing.T) {
	db, svc, captured, _, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	users := repository.NewUserRepo(db)
	for i := 0; i < 101; i++ {
		admin := &domain.User{
			Email:           "admin-" + strconv.Itoa(i) + "@example.com",
			EmailNormalized: "admin-" + strconv.Itoa(i) + "@example.com",
			Nickname:        "admin",
			Role:            domain.RoleAdmin,
			Status:          domain.UserStatusActive,
		}
		if err := users.Create(context.Background(), admin); err != nil {
			t.Fatalf("create admin %d: %v", i, err)
		}
	}
	var logs bytes.Buffer
	svc.log = logging.New(&logs)

	svc.handle(context.Background(), domain.CommentEvent{
		Type: domain.TypeCommentCreated, SiteID: fx.SiteID, ThreadID: fx.ThreadID,
		CommentID: fx.CommentID, UserID: fx.AuthorID,
	})

	moderationCount := 0
	for _, message := range captured.messages {
		if message.Subject == "新评论" {
			moderationCount++
		}
	}
	if moderationCount != mailRecipientLimit {
		t.Fatalf("moderation messages = %d, want %d", moderationCount, mailRecipientLimit)
	}
	if !strings.Contains(logs.String(), "moderation recipients truncated") ||
		!strings.Contains(logs.String(), "dropped_count=2") {
		t.Fatalf("truncation warning = %q", logs.String())
	}
	if strings.Contains(logs.String(), "admin-") || strings.Contains(logs.String(), "@example.com") {
		t.Fatalf("truncation warning contains recipient PII: %q", logs.String())
	}
}

// TestHandleCreatedReplyDisabledPersonalSkipsReply 证明创建路径仍遵守父评论
// 作者的个人回复偏好：reply_enabled=false 时不发送回复邮件，管理员新评论邮件
// 保留（R5）。
func TestHandleCreatedReplyDisabledPersonalSkipsReply(t *testing.T) {
	db, svc, mailer, _, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	if err := repository.NewPreferenceRepo(db).Upsert(ctx, &domain.NotificationPreferences{
		UserID:            fx.ParentUserID,
		ReplyEnabled:      false,
		ModerationEnabled: true,
	}); err != nil {
		t.Fatalf("upsert preferences: %v", err)
	}

	svc.handle(ctx, domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (moderation only)", len(mailer.messages))
	}
	if mailer.messages[0].To != "admin@example.com" || mailer.messages[0].Subject != "新评论" {
		t.Fatalf("message = %+v, want admin moderation only", mailer.messages[0])
	}
}

// TestHandlePublishedRepliesOffSkipsReplyMail 证明关闭全局回复开关时，review
// 模式发布路径仍发送发布确认邮件，但不再向父评论作者发送回复邮件（R4）。
func TestHandlePublishedRepliesOffSkipsReplyMail(t *testing.T) {
	db, svc, mailer, _, settings := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	settings.set(Settings{Moderation: true, Replies: false})

	svc.handle(context.Background(), domain.CommentEvent{
		Type:      domain.TypeCommentPublished,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
		ParentID:  &fx.ParentID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (published only)", len(mailer.messages))
	}
	if mailer.messages[0].To != "author@example.com" || mailer.messages[0].Subject != "您的评论已发布" {
		t.Fatalf("message = %+v, want published confirmation only", mailer.messages[0])
	}
}

// TestHandlePublishedReplyDisabledPersonalSkipsReply 证明发布路径仍遵守父评论
// 作者的个人回复偏好：reply_enabled=false 时不发送回复邮件，发布确认邮件保留
// （R5）。
func TestHandlePublishedReplyDisabledPersonalSkipsReply(t *testing.T) {
	db, svc, mailer, _, _ := newNotificationHarness(t)
	fx := seedNotificationData(t, db)
	ctx := context.Background()
	if err := repository.NewPreferenceRepo(db).Upsert(ctx, &domain.NotificationPreferences{
		UserID:            fx.ParentUserID,
		ReplyEnabled:      false,
		ModerationEnabled: true,
	}); err != nil {
		t.Fatalf("upsert preferences: %v", err)
	}

	svc.handle(ctx, domain.CommentEvent{
		Type:      domain.TypeCommentPublished,
		SiteID:    fx.SiteID,
		ThreadID:  fx.ThreadID,
		CommentID: fx.CommentID,
		UserID:    fx.AuthorID,
		ParentID:  &fx.ParentID,
	})

	if len(mailer.messages) != 1 {
		t.Fatalf("messages = %d, want 1 (published only)", len(mailer.messages))
	}
	if mailer.messages[0].To != "author@example.com" || mailer.messages[0].Subject != "您的评论已发布" {
		t.Fatalf("message = %+v, want published confirmation only", mailer.messages[0])
	}
}

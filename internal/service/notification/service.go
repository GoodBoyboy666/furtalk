// Package notification 消费提交后的评论事件并投递通知邮件，同时实现带签名的退订用例。
// 用户与评论读取经 repository；偏好写经 domain.PreferenceWriter 由 identity 层代写。
package notification

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/eventbus"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/urlx"
	"furtalk/internal/repository"
)

// UnsubscribeSigner 签名并验证通知邮件中嵌入的通知退订令牌。
type UnsubscribeSigner interface {
	SignUnsubscribe(userID int64, kind string, lifetime time.Duration) (string, error)
	ParseUnsubscribe(raw string) (int64, string, error)
}

// 通知种类枚举，用于退订令牌与偏好开关。
const (
	// KindReply 表示回复通知。
	KindReply = "reply"
	// KindModeration 表示审核通知。
	KindModeration = "moderation"
)

// sendTimeout 限制单次邮件投递的超时。
const sendTimeout = 30 * time.Second

// notificationTTL 限制退订令牌的有效期。
const notificationTTL = 30 * 24 * time.Hour

// Service 消费提交后的评论事件并投递通知邮件与实例级管理员通道通知，
// 同时实现带签名的退订用例。
type Service struct {
	bus        *eventbus.Bus[domain.CommentEvent]
	mailer     mailer.Mailer
	templates  mailer.TemplateRenderer
	users      *repository.UserRepo
	comments   *repository.CommentRepo
	threads    *repository.ThreadRepo
	prefs      *repository.PreferenceRepo
	sites      *repository.SiteRepo
	channels   ChannelProviderReader
	dispatcher ChannelDispatcher
	prefW      domain.PreferenceWriter
	settings   SettingsReader
	signer     UnsubscribeSigner
	baseURL    string
	log        *slog.Logger
}

// NewService 构建通知服务。
func NewService(users *repository.UserRepo, comments *repository.CommentRepo, threads *repository.ThreadRepo, prefs *repository.PreferenceRepo, prefW domain.PreferenceWriter, settings SettingsReader, sites *repository.SiteRepo, channels ChannelProviderReader, dispatcher ChannelDispatcher, bus *eventbus.Bus[domain.CommentEvent], mailer mailer.Mailer, templates mailer.TemplateRenderer, signer UnsubscribeSigner, baseURL string, log *slog.Logger) *Service {
	log = logging.Normalize(log)
	return &Service{bus: bus, mailer: mailer, templates: templates, users: users, comments: comments, threads: threads, prefs: prefs, prefW: prefW, settings: settings, sites: sites, channels: channels, dispatcher: dispatcher, signer: signer, baseURL: baseURL, log: log}
}

// Settings 是 notification 消费的最小全局通知开关快照。
type Settings struct {
	Moderation bool
	Replies    bool
}

// SettingsReader 提供通知服务读取动态设置的接口。
type SettingsReader interface {
	NotificationSettings(ctx context.Context) (Settings, error)
}

// Run 运行通知事件消费循环。
func (s *Service) Run(ctx context.Context) error {
	if s.bus == nil {
		return nil
	}
	dispatcher := newMailDispatcher(ctx, s.deliverMail)
	defer dispatcher.stop()
	return s.bus.Consume(ctx, func(ev domain.CommentEvent) {
		s.handleWithSubmitter(ctx, ev, dispatcher.submit)
	})
}

// handle 处理评论事件。
func (s *Service) handle(ctx context.Context, ev domain.CommentEvent) {
	s.handleWithSubmitter(ctx, ev, s.submitSynchronously)
}

// handleWithSubmitter 使用指定提交器处理评论事件。
func (s *Service) handleWithSubmitter(ctx context.Context, ev domain.CommentEvent, submitter mailSubmitter) {
	if submitter == nil {
		submitter = s.submitSynchronously
	}
	dropped := 0
	submit := func(job mailJob) bool {
		if job.ctx == nil {
			job.ctx = ctx
		}
		if submitter(job) {
			return true
		}
		dropped++
		return false
	}
	if ev.Type == domain.TypeCommentCreated {
		s.handleCreated(ctx, ev, submit)
	} else if ev.Type == domain.TypeCommentPublished {
		s.handlePublished(ctx, ev, submit)
	}
	if dropped > 0 {
		s.log.Warn("notifications: mail queue full; jobs dropped",
			logging.ID("site_id", ev.SiteID),
			logging.ID("comment_id", ev.CommentID),
			slog.Int("dropped_count", dropped),
			slog.Int("queue_capacity", mailQueueCapacity))
	}
}

// handleCreated 实现 CommentCreated 邮件与通道规则。
func (s *Service) handleCreated(ctx context.Context, ev domain.CommentEvent, submit mailSubmitter) {
	current, err := s.settings.NotificationSettings(ctx)
	if err != nil {
		s.log.Warn("notifications: read settings", logging.ID("site_id", ev.SiteID), logging.Error(err))
		return
	}
	comment, err := s.comments.FindBySiteAndID(ctx, ev.SiteID, ev.CommentID)
	if err != nil {
		s.log.Warn("notifications: load comment", logging.ID("site_id", ev.SiteID), logging.ID("comment_id", ev.CommentID), logging.Error(err))
		return
	}
	author, err := s.users.FindByID(ctx, comment.UserID)
	if err != nil {
		s.log.Warn("notifications: load comment author", logging.ID("site_id", ev.SiteID), logging.ID("comment_id", ev.CommentID), logging.ID("user_id", comment.UserID), logging.Error(err))
		return
	}
	if s.mailer != nil {
		if current.Moderation {
			s.sendModerationMails(ctx, comment, author, ev, submit)
		}
		if comment.Status == domain.CommentStatusPublished {
			s.sendReplyNotification(ctx, comment, author, submit)
		}
	}
	if comment.Status == domain.CommentStatusPublished || comment.Status == domain.CommentStatusPending {
		s.sendChannels(ctx, comment, author, ev)
	}
}

// sendModerationMails 提交评论审核通知邮件。
func (s *Service) sendModerationMails(ctx context.Context, comment *domain.Comment, author *domain.User, ev domain.CommentEvent, submit mailSubmitter) {
	admins, err := s.users.ListActiveAdmins(ctx)
	if err != nil {
		s.log.Warn("notifications: list admins", logging.ID("site_id", ev.SiteID), logging.Error(err))
		return
	}
	excludedParentID := s.replyParentUserID(ctx, comment)
	pageTitle, pageURL := s.threadPage(ctx, comment)
	eligible, dropped := 0, 0
	for _, admin := range admins {
		if admin.ID == comment.UserID {
			continue
		}
		if excludedParentID != 0 && admin.ID == excludedParentID {
			continue
		}
		if strings.TrimSpace(admin.Email) == "" {
			continue
		}
		eligible++
		if eligible > mailRecipientLimit {
			dropped++
			continue
		}
		msg, err := s.moderationMail(s.templates, admin.Email, comment, author.Nickname, pageTitle, pageURL)
		if err != nil {
			s.log.Warn("notifications: render moderation mail", logging.ID("site_id", ev.SiteID), logging.ID("comment_id", ev.CommentID), logging.Error(err))
			continue
		}
		submit(mailJob{ctx: ctx, userID: admin.ID, message: msg})
	}
	if dropped > 0 {
		s.log.Warn("notifications: moderation recipients truncated",
			logging.ID("site_id", ev.SiteID),
			logging.ID("comment_id", ev.CommentID),
			slog.Int("recipient_limit", mailRecipientLimit),
			slog.Int("dropped_count", dropped))
	}
}

// handlePublished 实现 CommentPublished 邮件规则：向作者发送发布确认，
func (s *Service) handlePublished(ctx context.Context, ev domain.CommentEvent, submit mailSubmitter) {
	if s.mailer == nil {
		return
	}
	author, err := s.users.FindByID(ctx, ev.UserID)
	if err != nil {
		s.log.Warn("notifications: load author", logging.ID("user_id", ev.UserID), logging.Error(err))
		return
	}
	comment, err := s.comments.FindBySiteAndID(ctx, ev.SiteID, ev.CommentID)
	if err != nil {
		s.log.Warn("notifications: load comment", logging.ID("site_id", ev.SiteID), logging.ID("comment_id", ev.CommentID), logging.Error(err))
		return
	}
	body := comment.BodyMarkdown
	if trimmed := strings.TrimSpace(body); trimmed == "" {
		body = "（无内容）"
	}

	if strings.TrimSpace(author.Email) != "" && s.notificationEnabled(ctx, author.ID, KindModeration) {
		unsub := s.unsubscribeURL(author.ID, KindModeration)
		html, err := s.templates.Published(mailer.PublishedData{
			AuthorNickname: author.Nickname,
			CommentBody:    body,
			UnsubscribeURL: unsub,
		})
		if err != nil {
			s.log.Warn("notifications: render published mail", logging.ID("user_id", ev.UserID), logging.ID("comment_id", ev.CommentID), logging.Error(err))
		} else {
			submit(mailJob{ctx: ctx, userID: author.ID, message: mailer.Message{
				To:       author.Email,
				Subject:  "您的评论已发布",
				TextBody: "您的评论已发布。",
				HTMLBody: html,
			}, unsub: unsub, htmlHasUnsub: true})
		}
	}

	s.sendReplyNotification(ctx, comment, author, submit)
}

// replyParentUserID 返回已发布回复的父评论作者 ID，供管理员通知排除收件人；
func (s *Service) replyParentUserID(ctx context.Context, comment *domain.Comment) int64 {
	if comment.ParentID == nil || comment.Status != domain.CommentStatusPublished {
		return 0
	}
	parent, err := s.comments.FindBySiteAndID(ctx, comment.SiteID, *comment.ParentID)
	if err != nil {
		s.log.Warn("notifications: load parent for recipient exclusion", logging.ID("site_id", comment.SiteID), logging.ID("comment_id", comment.ID), logging.Error(err))
		return 0
	}
	return parent.UserID
}

// sendReplyNotification 提交评论回复通知邮件。
func (s *Service) sendReplyNotification(ctx context.Context, comment *domain.Comment, author *domain.User, submit mailSubmitter) {
	if comment.ParentID == nil {
		return
	}
	current, err := s.settings.NotificationSettings(ctx)
	if err != nil {
		s.log.Warn("notifications: read settings", logging.ID("site_id", comment.SiteID), logging.ID("comment_id", comment.ID), logging.Error(err))
		return
	}
	if !current.Replies {
		return
	}
	parent, err := s.comments.FindBySiteAndID(ctx, comment.SiteID, *comment.ParentID)
	if err != nil {
		s.log.Warn("notifications: load parent comment", logging.ID("site_id", comment.SiteID), logging.ID("comment_id", comment.ID), logging.Error(err))
		return
	}
	if parent.UserID == comment.UserID {
		return
	}
	parentAuthor, err := s.users.FindByID(ctx, parent.UserID)
	if err != nil {
		s.log.Warn("notifications: load parent author", logging.ID("user_id", parent.UserID), logging.Error(err))
		return
	}
	if strings.TrimSpace(parentAuthor.Email) == "" {
		return
	}
	if !s.notificationEnabled(ctx, parentAuthor.ID, KindReply) {
		return
	}
	body := comment.BodyMarkdown
	if trimmed := strings.TrimSpace(body); trimmed == "" {
		body = "（无内容）"
	}
	parentBody := parent.BodyMarkdown
	if trimmed := strings.TrimSpace(parentBody); trimmed == "" {
		parentBody = "（无内容）"
	}
	pageTitle, pageURL := s.threadPage(ctx, comment)
	unsub := s.unsubscribeURL(parentAuthor.ID, KindReply)
	html, err := s.templates.Reply(mailer.ReplyData{
		ReplyAuthorNickname:  author.Nickname,
		ParentAuthorNickname: parentAuthor.Nickname,
		ReplyBody:            body,
		ParentCommentBody:    parentBody,
		UnsubscribeURL:       unsub,
		PageTitle:            pageTitle,
		PageURL:              pageURL,
	})
	if err != nil {
		s.log.Warn("notifications: render reply mail", logging.ID("user_id", comment.UserID), logging.ID("comment_id", comment.ID), logging.Error(err))
		return
	}
	text := "有人回复了您的评论。"
	if pageTitle != "" || pageURL != "" {
		text += "\n\n页面：" + pageTitle
		if pageURL != "" {
			if pageTitle != "" {
				text += "\n"
			}
			text += pageURL
		}
	}
	msg := mailer.Message{
		To:       parentAuthor.Email,
		Subject:  "您有一条新回复",
		TextBody: text,
		HTMLBody: html,
	}
	submit(mailJob{ctx: ctx, userID: parentAuthor.ID, message: msg, unsub: unsub, htmlHasUnsub: true})
}

// threadPage 读取评论所属线程的页面标题与网址。
func (s *Service) threadPage(ctx context.Context, comment *domain.Comment) (title, url string) {
	thread, err := s.threads.GetBySiteAndID(ctx, comment.SiteID, comment.ThreadID)
	if err != nil {
		s.log.Warn("notifications: load thread", logging.ID("site_id", comment.SiteID), logging.ID("thread_id", comment.ThreadID), logging.Error(err))
		return "", ""
	}
	if thread.PageTitle != nil {
		title = *thread.PageTitle
	}
	if thread.PageURL != nil {
		url = *thread.PageURL
	}
	return title, url
}

// moderationMail 构建管理员审核通知。
func (s *Service) moderationMail(templates mailer.TemplateRenderer, to string, comment *domain.Comment, authorNickname, pageTitle, pageURL string) (mailer.Message, error) {
	var subject, pending string
	awaiting := false
	switch comment.Status {
	case domain.CommentStatusPending:
		subject = "评论待审核"
		pending = "有一条新评论等待审核。"
		awaiting = true
	case domain.CommentStatusSpam:
		subject = "评论被标记为垃圾"
		pending = "有一条评论被自动标记为垃圾。"
	default:
		subject = "新评论"
		pending = "有新评论发表。"
	}
	body := comment.BodyMarkdown
	if trimmed := strings.TrimSpace(body); trimmed == "" {
		body = "（无内容）"
	}
	text := pending + "\n\n" + body
	if pageTitle != "" || pageURL != "" {
		text += "\n\n页面：" + pageTitle
		if pageURL != "" {
			if pageTitle != "" {
				text += "\n"
			}
			text += pageURL
		}
	}
	html, err := templates.Moderation(mailer.ModerationData{
		AuthorNickname:     authorNickname,
		CommentBody:        body,
		AwaitingModeration: awaiting,
		PageTitle:          pageTitle,
		PageURL:            pageURL,
	})
	if err != nil {
		return mailer.Message{}, err
	}
	return mailer.Message{
		To:       to,
		Subject:  subject,
		TextBody: text,
		HTMLBody: html,
	}, nil
}

// notificationEnabled 报告用户是否可接收给定的通知种类。
func (s *Service) notificationEnabled(ctx context.Context, userID int64, kind string) bool {
	prefs, err := s.prefs.GetByUserID(ctx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return true
	}
	if err != nil {
		s.log.Warn("notifications: load preferences", logging.ID("user_id", userID), logging.Error(err))
		return false
	}
	switch kind {
	case KindReply:
		return prefs.ReplyEnabled
	case KindModeration:
		return prefs.ModerationEnabled
	default:
		return false
	}
}

// unsubscribeURL 为指定用户与通知种类生成签名退订 URL。
func (s *Service) unsubscribeURL(userID int64, kind string) string {
	if s.signer == nil || s.baseURL == "" || kind == "" {
		return ""
	}
	token, err := s.signer.SignUnsubscribe(userID, kind, notificationTTL)
	if err != nil {
		s.log.Warn("notifications: sign unsubscribe token", logging.ID("user_id", userID), logging.Error(err))
		return ""
	}
	base, err := urlx.ParseHTTPBase(s.baseURL)
	if err != nil {
		return ""
	}
	u := urlx.JoinPathSegments(base, "unsubscribe")
	query := url.Values{}
	query.Set("token", token)
	u.RawQuery = query.Encode()
	return u.String()
}

// send 提交用户通知邮件。
func (s *Service) send(ctx context.Context, userID int64, msg mailer.Message, unsub string, htmlHasUnsub bool) {
	s.deliverMail(mailJob{ctx: ctx, userID: userID, message: msg, unsub: unsub, htmlHasUnsub: htmlHasUnsub})
}

// submitSynchronously 同步提交邮件任务。
func (s *Service) submitSynchronously(job mailJob) bool {
	s.deliverMail(job)
	return true
}

// deliverMail 投递邮件任务。
func (s *Service) deliverMail(job mailJob) {
	if s.mailer == nil {
		return
	}
	if job.unsub != "" {
		job.message.TextBody += "\n\n如不再想收到此类邮件，请访问：" + job.unsub
		if !job.htmlHasUnsub {
			job.message.HTMLBody += `<p><a href="` + escapeHTML(job.unsub) + `">退订</a></p>`
		}
	}
	sendCtx, cancel := context.WithTimeout(job.ctx, sendTimeout)
	defer cancel()
	if err := s.mailer.Send(sendCtx, job.message); err != nil {
		s.log.Warn("notifications: mail delivery failed", logging.ID("user_id", job.userID), logging.Error(err))
	}
}

// escapeHTML 转义 HTML 文本。
func escapeHTML(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&#34;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Unsubscribe 禁用有效签名令牌指定的通知种类。
func (s *Service) Unsubscribe(ctx context.Context, rawToken string) error {
	userID, kind, err := s.parseUnsubscribe(rawToken)
	if err != nil {
		return ErrInvalidToken
	}
	if _, err := s.users.FindByID(ctx, userID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		return err
	}
	prefs, err := s.prefs.GetByUserID(ctx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		prefs = &domain.NotificationPreferences{UserID: userID, ReplyEnabled: true, ModerationEnabled: true}
	} else if err != nil {
		return err
	}
	switch kind {
	case KindReply:
		prefs.ReplyEnabled = false
	case KindModeration:
		prefs.ModerationEnabled = false
	default:
		return ErrInvalidToken
	}
	return s.prefW.UpsertNotificationPreferences(ctx, prefs)
}

// parseUnsubscribe 解析退订令牌。
func (s *Service) parseUnsubscribe(rawToken string) (int64, string, error) {
	if s.signer == nil {
		return 0, "", ErrInvalidToken
	}
	return s.signer.ParseUnsubscribe(rawToken)
}

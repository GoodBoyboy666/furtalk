// Package notification 消费提交后的评论事件并投递通知邮件，
// 同时实现带签名的退订用例。
// 用户与评论读取经 repository；偏好写经 domain.PreferenceWriter 由 identity 层代写。
package notification

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/eventbus"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/repository"
	"furtalk/internal/service/setting"
)

// UnsubscribeSigner 签名并验证通知邮件中嵌入的通知退订令牌。
type UnsubscribeSigner interface {
	SignUnsubscribe(userID int64, kind string, lifetime time.Duration) (string, error)
	ParseUnsubscribe(raw string) (int64, string, error)
}

// sendTimeout 限制单次邮件投递的超时。
const sendTimeout = 30 * time.Second

// notificationTTL 限制退订令牌的有效期。
const notificationTTL = 30 * 24 * time.Hour

// Service 消费提交后的评论事件并投递通知邮件，同时实现带签名的退订用例。
type Service struct {
	bus       *eventbus.Bus[domain.CommentEvent]
	mailer    mailer.Mailer
	templates mailer.TemplateRenderer
	users     *repository.UserRepo
	comments  *repository.CommentRepo
	threads   *repository.ThreadRepo
	prefs     *repository.PreferenceRepo
	prefW     domain.PreferenceWriter
	settings  *setting.Service
	signer    UnsubscribeSigner
	baseURL   string
	log       *slog.Logger
}

// NewService 构建通知服务。
func NewService(users *repository.UserRepo, comments *repository.CommentRepo, threads *repository.ThreadRepo, prefs *repository.PreferenceRepo, prefW domain.PreferenceWriter, settings *setting.Service, bus *eventbus.Bus[domain.CommentEvent], mailer mailer.Mailer, templates mailer.TemplateRenderer, signer UnsubscribeSigner, baseURL string, log *slog.Logger) *Service {
	log = logging.Normalize(log)
	return &Service{bus: bus, mailer: mailer, templates: templates, users: users, comments: comments, threads: threads, prefs: prefs, prefW: prefW, settings: settings, signer: signer, baseURL: baseURL, log: log}
}

// Run 阻塞并消费评论事件，直到 ctx 取消或事件总线关闭。
func (s *Service) Run(ctx context.Context) error {
	if s.bus == nil || s.mailer == nil {
		return nil
	}
	return s.bus.Consume(ctx, func(ev domain.CommentEvent) {
		s.handle(ctx, ev)
	})
}

func (s *Service) handle(ctx context.Context, ev domain.CommentEvent) {
	if ev.Type == domain.TypeCommentCreated {
		s.handleCreated(ctx, ev)
		return
	}
	if ev.Type == domain.TypeCommentPublished {
		s.handlePublished(ctx, ev)
		return
	}
}

// handleCreated 实现 CommentCreated 邮件规则。
// 管理员新评论/待审核通知受全局通知开关控制；直接发布的回复由本路径发送
// 回复通知。两者在同一事件处理器中分别门禁，关闭审核开关不影响回复通知。
func (s *Service) handleCreated(ctx context.Context, ev domain.CommentEvent) {
	current, err := s.settings.Get(ctx)
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
	if current.Settings.Notifications.Moderation {
		s.sendModerationMails(ctx, current.Settings, comment, author, ev)
	}
	if comment.Status == domain.CommentStatusPublished {
		s.sendReplyNotification(ctx, comment, author)
	}
}

// sendModerationMails 向全部活跃管理员发送新评论/待审核通知。
func (s *Service) sendModerationMails(ctx context.Context, current domain.Settings, comment *domain.Comment, author *domain.User, ev domain.CommentEvent) {
	admins, err := s.users.ListActiveAdmins(ctx)
	if err != nil {
		s.log.Warn("notifications: list admins", logging.ID("site_id", ev.SiteID), logging.Error(err))
		return
	}
	pageTitle, pageURL := s.threadPage(ctx, comment)
	for _, admin := range admins {
		if admin.ID == comment.UserID {
			continue
		}
		if strings.TrimSpace(admin.Email) == "" {
			continue
		}
		msg, err := s.moderationMail(s.templates, current, admin.Email, comment, author.Nickname, pageTitle, pageURL)
		if err != nil {
			s.log.Warn("notifications: render moderation mail", logging.ID("site_id", ev.SiteID), logging.ID("comment_id", ev.CommentID), logging.Error(err))
			continue
		}
		s.send(ctx, admin.ID, msg, "", false)
	}
}

// handlePublished 实现 CommentPublished 邮件规则：向作者发送发布确认，
// 并在评论为回复时通过共享 helper 向父评论作者发送回复通知。
func (s *Service) handlePublished(ctx context.Context, ev domain.CommentEvent) {
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
			s.send(ctx, author.ID, mailer.Message{
				To:       author.Email,
				Subject:  "您的评论已发布",
				TextBody: "您的评论已发布。",
				HTMLBody: html,
			}, unsub, true)
		}
	}

	s.sendReplyNotification(ctx, comment, author)
}

// sendReplyNotification 向父评论作者发送回复通知。
// 由 CommentCreated（直接发布的回复）与 CommentPublished（人工审核发布的
// 回复）两条路径共用，统一遵守父评论作者、自回复排除、通知偏好与退订规则。
func (s *Service) sendReplyNotification(ctx context.Context, comment *domain.Comment, author *domain.User) {
	if comment.ParentID == nil {
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
	s.send(ctx, parentAuthor.ID, msg, unsub, true)
}

// threadPage 读取评论所属线程的页面标题与网址。
// 事件处理阶段按 (site_id, thread_id) 读取，保证看到评论创建事务提交后的
// 页面元数据；线程缺失或读取失败时返回空串，不阻塞邮件投递。
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
// HTML 正文由模板渲染器生成；主题按审核状态在代码中设置。
func (s *Service) moderationMail(templates mailer.TemplateRenderer, current domain.Settings, to string, comment *domain.Comment, authorNickname, pageTitle, pageURL string) (mailer.Message, error) {
	subject := "新评论"
	pending := "有新评论发表。"
	awaiting := false
	if current.Moderation == domain.ModerationReview {
		subject = "评论待审核"
		pending = "有一条新评论等待审核。"
		awaiting = true
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
// 签名器、baseURL 缺失或签名失败时返回空串，表示该邮件不携带退订链接。
func (s *Service) unsubscribeURL(userID int64, kind string) string {
	if s.signer == nil || s.baseURL == "" || kind == "" {
		return ""
	}
	token, err := s.signer.SignUnsubscribe(userID, kind, notificationTTL)
	if err != nil {
		s.log.Warn("notifications: sign unsubscribe token", logging.ID("user_id", userID), logging.Error(err))
		return ""
	}
	return s.baseURL + "/unsubscribe?token=" + token
}

// send 以有界超时投递一条消息。
// unsub 非空时在纯文本正文追加退订说明；htmlHasUnsub 为 false 时再向 HTML
// 正文追加退订链接。回复模板已内联该链接，htmlHasUnsub 传 true 不重复追加。
func (s *Service) send(ctx context.Context, userID int64, msg mailer.Message, unsub string, htmlHasUnsub bool) {
	if s.mailer == nil {
		return
	}
	if unsub != "" {
		msg.TextBody += "\n\n如不再想收到此类邮件，请访问：" + unsub
		if !htmlHasUnsub {
			msg.HTMLBody += `<p><a href="` + escapeHTML(unsub) + `">退订</a></p>`
		}
	}
	sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if err := s.mailer.Send(sendCtx, msg); err != nil {
		s.log.Warn("notifications: mail delivery failed", logging.ID("user_id", userID), logging.Error(err))
	}
}

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

func (s *Service) parseUnsubscribe(rawToken string) (int64, string, error) {
	if s.signer == nil {
		return 0, "", ErrInvalidToken
	}
	return s.signer.ParseUnsubscribe(rawToken)
}

// 通知种类枚举，用于退订令牌与偏好开关。
const (
	// KindReply 表示回复通知。
	KindReply = "reply"
	// KindModeration 表示审核通知。
	KindModeration = "moderation"
)

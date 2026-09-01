package notification

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/notifier"
)

// ChannelConfig 是 notification 投递消费的通道配置投影。
type ChannelConfig struct {
	BotToken           string
	ChatID             string
	WebhookURL         string
	ServerURL          string
	DeviceKey          string
	ChannelAccessToken string
	TargetID           string
	SigningSecret      *string
}

// ChannelProvider 是已启用通知通道的消费方投影。
type ChannelProvider struct {
	ProviderKey string
	Config      ChannelConfig
}

// ChannelProviderReader 读取已启用通知通道的解密配置。
// 由 setting.ProviderService 实现，通知服务通过窄接口消费，便于测试替换。
type ChannelProviderReader interface {
	EnabledNotificationProviders(ctx context.Context) ([]ChannelProvider, error)
}

// ChannelDispatcher 向单个平台通道执行一次有界的投递。
// 由 platform/notifier.Dispatcher 实现。
type ChannelDispatcher interface {
	Send(ctx context.Context, cfg notifier.Config, msg notifier.Message) error
}

// webhookBodyMaxRunes  WebHook v1 信封中评论正文的截断字符上限，
// 使整体 JSON 请求体保持在有界范围（远低于 64KiB）。
const webhookBodyMaxRunes = 1000

// webhookEnvelope 通用 WebHook v1 请求体。
// 业务 ID 全部编码为十进制字符串；缺失的父评论/标题/URL 使用 JSON null。
type webhookEnvelope struct {
	Version          string         `json:"version"`
	Event            string         `json:"event"`
	NotificationType string         `json:"notification_type"`
	EventID          string         `json:"event_id"`
	OccurredAt       string         `json:"occurred_at"`
	Site             webhookSite    `json:"site"`
	Page             webhookPage    `json:"page"`
	Comment          webhookComment `json:"comment"`
}

// webhookSite  WebHook v1 信封中的站点对象。
type webhookSite struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	CanonicalURL string `json:"canonical_url"`
}

// webhookPage  WebHook v1 信封中的页面对象；标题/URL 缺失时为 JSON null。
type webhookPage struct {
	ThreadID string  `json:"thread_id"`
	Title    *string `json:"title"`
	URL      *string `json:"url"`
}

// webhookComment  WebHook v1 信封中的评论对象；父评论缺失时为 JSON null。
type webhookComment struct {
	ID             string  `json:"id"`
	ParentID       *string `json:"parent_id"`
	Status         string  `json:"status"`
	AuthorNickname string  `json:"author_nickname"`
	BodyMarkdown   string  `json:"body_markdown"`
	BodyTruncated  bool    `json:"body_truncated"`
	CreatedAt      string  `json:"created_at"`
}

// sendChannels 向全部已启用通知通道扇出投递一条规范化消息。
// 只处理 comment.created 且持久化状态为 published/pending 的评论；
// 各通道并发执行、使用共享上下文，一个通道失败只记录日志，不取消兄弟通道。
func (s *Service) sendChannels(ctx context.Context, comment *domain.Comment, author *domain.User, ev domain.CommentEvent) {
	if s.channels == nil || s.dispatcher == nil || s.sites == nil {
		return
	}
	providers, err := s.channels.EnabledNotificationProviders(ctx)
	if err != nil {
		s.log.Warn("notifications: read channel providers", logging.ID("site_id", ev.SiteID), logging.Error(err))
		return
	}
	if len(providers) == 0 {
		return
	}
	site, err := s.sites.Get(ctx, comment.SiteID)
	if err != nil {
		s.log.Warn("notifications: load site for channels", logging.ID("site_id", comment.SiteID), logging.Error(err))
		return
	}
	msg, err := s.buildChannelMessage(ctx, comment, author, site, ev)
	if err != nil {
		s.log.Warn("notifications: build channel message", logging.ID("site_id", ev.SiteID), logging.ID("comment_id", ev.CommentID), logging.Error(err))
		return
	}
	var wg sync.WaitGroup
	for _, provider := range providers {
		wg.Add(1)
		go func(p ChannelProvider) {
			defer wg.Done()
			s.dispatchChannel(ctx, p, *msg, comment)
		}(provider)
	}
	wg.Wait()
}

// dispatchChannel 对单个通道执行一次有界投递并记录脱敏结果。
func (s *Service) dispatchChannel(ctx context.Context, provider ChannelProvider, msg notifier.Message, comment *domain.Comment) {
	cfg, err := s.channelConfig(provider)
	if err != nil {
		s.log.Warn("notifications: channel config", slog.String("provider_key", provider.ProviderKey), logging.Error(err))
		return
	}
	if err := s.dispatcher.Send(ctx, cfg, msg); err != nil {
		s.log.Warn("notifications: channel delivery failed",
			slog.String("provider_key", provider.ProviderKey),
			logging.ID("site_id", comment.SiteID),
			logging.ID("comment_id", comment.ID),
			logging.Error(err))
	}
}

// buildChannelMessage 从限定作用域的评论/作者/站点/线程读取构造
// 一条规范化管理员通道消息，同时构造通用 WebHook v1 信封的原始字节。
// 消息绝不包含邮箱、IP、UA、收件人列表或退订 token。
func (s *Service) buildChannelMessage(ctx context.Context, comment *domain.Comment, author *domain.User, site *domain.Site, ev domain.CommentEvent) (*notifier.Message, error) {
	label, _ := channelLabels(comment.Status)
	var pageTitle, pageURL string
	thread, err := s.threads.GetBySiteAndID(ctx, comment.SiteID, comment.ThreadID)
	if err == nil {
		if thread.PageTitle != nil {
			pageTitle = *thread.PageTitle
		}
		if thread.PageURL != nil {
			pageURL = *thread.PageURL
		}
	} else {
		s.log.Warn("notifications: load thread for channels", logging.ID("site_id", comment.SiteID), logging.ID("thread_id", comment.ThreadID), logging.Error(err))
	}

	var b strings.Builder
	b.WriteString("站点：")
	b.WriteString(site.Name)
	if pageTitle != "" {
		b.WriteString("\n页面：")
		b.WriteString(pageTitle)
	}
	if pageURL != "" {
		b.WriteString("\n")
		b.WriteString(pageURL)
	}
	b.WriteString("\n作者：")
	b.WriteString(author.Nickname)
	b.WriteString("\n状态：")
	b.WriteString(string(comment.Status))
	b.WriteString("\n时间：")
	b.WriteString(comment.CreatedAt.UTC().Format(time.RFC3339))
	b.WriteString("\n\n")
	body := strings.TrimSpace(comment.BodyMarkdown)
	if body == "" {
		body = "（无内容）"
	}
	b.WriteString(body)

	msg := &notifier.Message{
		Title:   label,
		Text:    b.String(),
		PageURL: pageURL,
	}
	raw, err := s.webHookEnvelope(ev, comment, author, site, pageTitle, pageURL)
	if err != nil {
		return nil, err
	}
	msg.WebHookRaw = raw
	return msg, nil
}

// webHookEnvelope 构造通用 WebHook v1 信封并序列化为原始字节。
// 事件为固定 "comment.created"；notification_type 区分新评论/待审核；
// event_id 对单次创建事件确定，接收方可据此去重。
func (s *Service) webHookEnvelope(ev domain.CommentEvent, comment *domain.Comment, author *domain.User, site *domain.Site, pageTitle, pageURL string) ([]byte, error) {
	_, notifType := channelLabels(comment.Status)
	body, truncated := notifier.TruncateRunes(comment.BodyMarkdown, webhookBodyMaxRunes)
	env := webhookEnvelope{
		Version:          "1",
		Event:            string(domain.TypeCommentCreated),
		NotificationType: notifType,
		EventID:          "comment.created:" + strconv.FormatInt(ev.SiteID, 10) + ":" + strconv.FormatInt(ev.CommentID, 10),
		OccurredAt:       comment.CreatedAt.UTC().Format(time.RFC3339),
		Site: webhookSite{
			ID:           strconv.FormatInt(site.ID, 10),
			Name:         site.Name,
			CanonicalURL: site.CanonicalURL,
		},
		Page: webhookPage{
			ThreadID: strconv.FormatInt(comment.ThreadID, 10),
		},
		Comment: webhookComment{
			ID:             strconv.FormatInt(comment.ID, 10),
			ParentID:       decimalID(comment.ParentID),
			Status:         string(comment.Status),
			AuthorNickname: author.Nickname,
			BodyMarkdown:   body,
			BodyTruncated:  truncated,
			CreatedAt:      comment.CreatedAt.UTC().Format(time.RFC3339),
		},
	}
	if pageTitle != "" {
		t := pageTitle
		env.Page.Title = &t
	}
	if pageURL != "" {
		u := pageURL
		env.Page.URL = &u
	}
	return json.Marshal(env)
}

// channelLabels 返回评论状态对应的通知标签与 WebHook notification_type。
// 仅 published / pending 会进入通道分支；其他状态不会调用本函数。
func channelLabels(status domain.CommentStatus) (label, notifType string) {
	if status == domain.CommentStatusPending {
		return "评论待审核", "pending_comment"
	}
	return "新评论", "new_comment"
}

// channelConfig 把解密后的通知配置映射为 notifier 类型化配置。
func (s *Service) channelConfig(provider ChannelProvider) (notifier.Config, error) {
	platform, err := notifier.ParsePlatform(provider.ProviderKey)
	if err != nil {
		return notifier.Config{}, err
	}
	return notifier.Config{
		Platform:           platform,
		BotToken:           provider.Config.BotToken,
		ChatID:             provider.Config.ChatID,
		WebhookURL:         provider.Config.WebhookURL,
		ServerURL:          provider.Config.ServerURL,
		DeviceKey:          provider.Config.DeviceKey,
		ChannelAccessToken: provider.Config.ChannelAccessToken,
		TargetID:           provider.Config.TargetID,
		SigningSecret:      derefString(provider.Config.SigningSecret),
	}, nil
}

// TestChannel 向指定通知通道发送一条显式标记的测试消息，供管理员测试端点使用。
// 测试允许在通道停用时执行，但要求配置完整：配置无效返回 domain.ErrValidation，
// 远程投递失败返回 domain.ErrUnavailable，错误不含目标或远程正文。
func (s *Service) TestChannel(ctx context.Context, providerKey string, cfg ChannelConfig) error {
	if s.dispatcher == nil {
		return domain.ErrUnavailable
	}
	notifCfg, err := s.channelConfig(ChannelProvider{ProviderKey: providerKey, Config: cfg})
	if err != nil {
		return domain.ErrValidation
	}
	raw, err := s.webHookTestEnvelope()
	if err != nil {
		return domain.ErrValidation
	}
	msg := notifier.Message{
		Title:      "Furtalk 通道测试",
		Text:       "这是一条由 Furtalk 管理员发起的测试消息。",
		WebHookRaw: raw,
	}
	if err := s.dispatcher.Send(ctx, notifCfg, msg); err != nil {
		if errors.Is(err, notifier.ErrConfig) {
			return domain.ErrValidation
		}
		return domain.ErrUnavailable
	}
	return nil
}

// webHookTestEnvelope 构造通用 WebHook 测试消息的 v1 信封。
// 复用与生产相同的传输与签名路径，仅事件内容不同。
func (s *Service) webHookTestEnvelope() ([]byte, error) {
	env := map[string]any{
		"version":           "1",
		"event":             "notification.test",
		"notification_type": "test",
		"event_id":          "notification.test",
		"occurred_at":       time.Now().UTC().Format(time.RFC3339),
		"test":              true,
		"message":           "这是一条由 Furtalk 管理员发起的测试消息。",
	}
	return json.Marshal(env)
}

// decimalID 把可选 int64 ID 编码为十进制字符串指针；nil 返回 nil（JSON null）。
func decimalID(id *int64) *string {
	if id == nil {
		return nil
	}
	s := strconv.FormatInt(*id, 10)
	return &s
}

// derefString 解引用可选字符串；nil 返回空串。
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

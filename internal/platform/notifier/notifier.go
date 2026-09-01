// Package notifier 提供业务无关的多通道通知出站基础设施。
// 它只依赖标准库，承载平台枚举、解密后的类型化配置、规范化消息、
// 8 个 HTTP 协议映射与有界 HTTP client；不读取数据库、不导入任何业务层。
//
// 本包负责把规范化管理员消息按各平台协议编码为一次有界的 HTTP 出站请求，
// 并在响应侧做平台级成功判定。投递策略（哪些评论、是否启用、并发扇出、
// 失败日志）属于上层 notification 服务，不在这里。
// 本包注释未人工审阅与调整
package notifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Platform 标识通知平台。
type Platform string

// 通知平台枚举。
const (
	// PlatformTelegram 表示 Telegram Bot API。
	PlatformTelegram Platform = "telegram"
	// PlatformFeishu 表示飞书自定义机器人。
	PlatformFeishu Platform = "feishu"
	// PlatformDingTalk 表示钉钉自定义机器人。
	PlatformDingTalk Platform = "dingtalk"
	// PlatformBark 表示 Bark V2 推送。
	PlatformBark Platform = "bark"
	// PlatformSlack 表示 Slack incoming webhook。
	PlatformSlack Platform = "slack"
	// PlatformLine 表示 LINE Messaging API。
	PlatformLine Platform = "line"
	// PlatformWebHook 表示通用 WebHook v1。
	PlatformWebHook Platform = "webhook"
	// PlatformDiscord 表示 Discord incoming webhook。
	PlatformDiscord Platform = "discord"
)

// ParsePlatform 把通知 provider key 的平台段解析为平台枚举。
// 例如 "notification.telegram" 返回 PlatformTelegram；未知平台返回错误。
func ParsePlatform(providerKey string) (Platform, error) {
	const prefix = "notification."
	if len(providerKey) <= len(prefix) || providerKey[:len(prefix)] != prefix {
		return "", fmt.Errorf("%w: invalid notification provider key %q", ErrConfig, providerKey)
	}
	switch Platform(providerKey[len(prefix):]) {
	case PlatformTelegram, PlatformFeishu, PlatformDingTalk, PlatformBark,
		PlatformSlack, PlatformLine, PlatformWebHook, PlatformDiscord:
		return Platform(providerKey[len(prefix):]), nil
	default:
		return "", fmt.Errorf("%w: unknown notification platform in %q", ErrConfig, providerKey)
	}
}

// Config 是解密后的类型化通知配置（含机密）。
// 平台无关字段做并集；每个平台只使用自己声明的字段。
type Config struct {
	Platform Platform
	// BotToken 是 Telegram 机器人令牌。
	BotToken string
	// ChatID 是 Telegram 目标聊天 ID。
	ChatID string
	// WebhookURL 是 Feishu/DingTalk/Slack/Discord/WebHook 的入站 webhook 地址。
	WebhookURL string
	// ServerURL 是 Bark 服务基址（官方或自托管）。
	ServerURL string
	// DeviceKey 是 Bark 设备 key。
	DeviceKey string
	// ChannelAccessToken 是 LINE Messaging API 的 channel access token。
	ChannelAccessToken string
	// TargetID 是 LINE 目标用户/群/房间 ID。
	TargetID string
	// SigningSecret 是 Feishu/DingTalk 平台签名密钥或通用 WebHook 的 HMAC 密钥。
	SigningSecret string
}

// Message 是规范化的管理员通道消息，供各平台适配器映射。
// 平台适配器只处理认证、请求格式与平台错误，不重新组装业务文本。
// WebHookRaw 是通用 WebHook v1 的原始 JSON 请求体；非 WebHook 平台忽略。
type Message struct {
	// Title 是通知类型标签（例如 新评论 / 评论待审核）。
	Title string
	// Text 是已组装的正文文本，包含站点、作者、状态、时间与正文；
	// 页面 URL 单独放在 PageURL，避免打断 mention 防护时破坏链接。
	Text string
	// PageURL 是页面 URL（可选），以明文追加，不做 @ 打断。
	PageURL string
	// WebHookRaw 是通用 WebHook v1 的原始 JSON 请求体。
	WebHookRaw []byte
}

// 出站投递的固定常量。
const (
	// requestTimeout 限制单次出站请求（含连接、TLS 与响应读取）。
	requestTimeout = 5 * time.Second
	// maxResponseBytes 限制读取的响应体大小。
	maxResponseBytes = 64 * 1024
)

var (
	// ErrConfig 标识无效的通道配置（地址形态、缺失字段等）。
	// 上层设置服务把该错误映射为验证错误。
	ErrConfig = errors.New("notifier: invalid channel config")
	// ErrDelivery 标识一次失败的出站投递（网络、超时、非 2xx 或平台拒绝）。
	// 上层设置服务把该错误映射为服务不可用。
	ErrDelivery = errors.New("notifier: delivery failed")
)

// DeliveryError 携带脱敏的失败类别与有界平台细节，便于日志诊断。
// 绝不包含请求 URL、凭据、目标 ID 或原始响应正文。
type DeliveryError struct {
	// Class 是失败类别：network / timeout / http / platform / response。
	Class string
	// Detail 是有界的脱敏细节，例如 "HTTP 403" 或平台错误码。
	Detail string
}

// Error 返回脱敏的错误文本。
func (e *DeliveryError) Error() string {
	if e == nil {
		return ErrDelivery.Error()
	}
	if e.Detail == "" {
		return ErrDelivery.Error() + ": " + e.Class
	}
	return ErrDelivery.Error() + ": " + e.Class + " (" + e.Detail + ")"
}

// Unwrap 暴露 ErrDelivery 供 errors.Is 使用。
func (e *DeliveryError) Unwrap() error { return ErrDelivery }

// Dispatcher 把规范化消息按平台协议映射为一次有界的 HTTP 出站请求。
// 每次调用最多执行一次，不做重试；错误为脱敏的 DeliveryError 或 ErrConfig。
type Dispatcher struct {
	client *http.Client
	now    func() time.Time
}

// NewDispatcher 构建一个带默认有界 HTTP client 的分发器。
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		client: newBoundedClient(),
		now:    time.Now,
	}
}

// setClock 安装确定性时钟，供测试固定 WebHook 签名时间戳。
func (d *Dispatcher) setClock(now func() time.Time) {
	if now != nil {
		d.now = now
	}
}

// setTransport 安装自定义传输，供测试拦截出站请求而不走真实网络。
func (d *Dispatcher) setTransport(rt http.RoundTripper) {
	if rt != nil {
		d.client.Transport = rt
	}
}

// Send 把规范化消息按配置的平台协议投递一次。
// 配置无效返回 ErrConfig；网络或平台失败返回 ErrDelivery（可 errors.As 到 *DeliveryError）。
func (d *Dispatcher) Send(ctx context.Context, cfg Config, msg Message) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	switch cfg.Platform {
	case PlatformTelegram:
		return d.sendTelegram(ctx, cfg, msg)
	case PlatformFeishu:
		return d.sendFeishu(ctx, cfg, msg)
	case PlatformDingTalk:
		return d.sendDingTalk(ctx, cfg, msg)
	case PlatformBark:
		return d.sendBark(ctx, cfg, msg)
	case PlatformSlack:
		return d.sendSlack(ctx, cfg, msg)
	case PlatformLine:
		return d.sendLine(ctx, cfg, msg)
	case PlatformWebHook:
		return d.sendWebHook(ctx, cfg, msg)
	case PlatformDiscord:
		return d.sendDiscord(ctx, cfg, msg)
	default:
		return fmt.Errorf("%w: unknown platform %q", ErrConfig, cfg.Platform)
	}
}

// do 执行请求并做重定向与传输错误的脱敏归一化。
func (d *Dispatcher) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	resp, err := d.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &DeliveryError{Class: "timeout"}
		}
		return nil, sanitizeTransportError(err)
	}
	return resp, nil
}

// sanitizeTransportError 把底层传输错误归一化为不泄露 URL/凭据的类别错误。
func sanitizeTransportError(err error) *DeliveryError {
	if errors.Is(err, context.DeadlineExceeded) {
		return &DeliveryError{Class: "timeout"}
	}
	if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
		return &DeliveryError{Class: "timeout"}
	}
	return &DeliveryError{Class: "network"}
}

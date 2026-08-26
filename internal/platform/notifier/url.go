package notifier

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Validate 校验解密后的配置可以发送：平台字段完整且 URL 形态合规。
// 该校验在每次投递前执行，作为持久化校验之外的防御边界。
func (cfg Config) Validate() error {
	switch cfg.Platform {
	case PlatformTelegram:
		if strings.TrimSpace(cfg.BotToken) == "" {
			return fmt.Errorf("%w: telegram bot token is required", ErrConfig)
		}
		if strings.TrimSpace(cfg.ChatID) == "" {
			return fmt.Errorf("%w: telegram chat id is required", ErrConfig)
		}
	case PlatformFeishu:
		if err := ValidateWebhookURL(PlatformFeishu, cfg.WebhookURL); err != nil {
			return err
		}
	case PlatformDingTalk:
		if err := ValidateWebhookURL(PlatformDingTalk, cfg.WebhookURL); err != nil {
			return err
		}
	case PlatformBark:
		if strings.TrimSpace(cfg.DeviceKey) == "" {
			return fmt.Errorf("%w: bark device key is required", ErrConfig)
		}
		if err := ValidateTrustedURL(cfg.ServerURL); err != nil {
			return err
		}
	case PlatformSlack:
		if err := ValidateWebhookURL(PlatformSlack, cfg.WebhookURL); err != nil {
			return err
		}
	case PlatformLine:
		if strings.TrimSpace(cfg.ChannelAccessToken) == "" {
			return fmt.Errorf("%w: line channel access token is required", ErrConfig)
		}
		if strings.TrimSpace(cfg.TargetID) == "" {
			return fmt.Errorf("%w: line target id is required", ErrConfig)
		}
	case PlatformWebHook:
		if err := ValidateTrustedURL(cfg.WebhookURL); err != nil {
			return err
		}
	case PlatformDiscord:
		if err := ValidateWebhookURL(PlatformDiscord, cfg.WebhookURL); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unknown platform %q", ErrConfig, cfg.Platform)
	}
	return nil
}

// ValidateTrustedURL 校验管理员可配置的绝对 http(s) 出站地址（Bark server_url / 通用 WebHook）。
// 有意允许 HTTP、HTTPS 与私网目标：这是受信管理员部署决策，不增加公网限制或私网阻断。
// 仍拒绝解析错误、空主机、userinfo、fragment、控制字符与非 http(s) scheme。
func ValidateTrustedURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%w: url is required", ErrConfig)
	}
	if err := rejectControlChars(trimmed); err != nil {
		return err
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: url must be an absolute http(s) url", ErrConfig)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: url scheme must be http or https", ErrConfig)
	}
	if u.User != nil {
		return fmt.Errorf("%w: url must not contain userinfo", ErrConfig)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: url must not contain a fragment", ErrConfig)
	}
	return nil
}

// ValidateWebhookURL 校验官方入站 webhook 地址的主机与路径形态。
// 要求 HTTPS、指定官方主机、路径前缀；DingTalk 要求恰好一个 access_token 查询值。
// 通用 WebHook 不是本函数的目标，使用 ValidateTrustedURL。
func ValidateWebhookURL(p Platform, raw string) error {
	switch p {
	case PlatformFeishu:
		return validateOfficialWebhookURL(raw, "open.feishu.cn", "/open-apis/bot/v2/hook/", "")
	case PlatformDingTalk:
		return validateOfficialWebhookURL(raw, "oapi.dingtalk.com", "/robot/send", "access_token")
	case PlatformSlack:
		return validateSlackWebhookURL(raw)
	case PlatformDiscord:
		return validateOfficialWebhookURL(raw, "discord.com", "/api/webhooks/", "")
	default:
		return fmt.Errorf("%w: platform %q has no configurable webhook url", ErrConfig, p)
	}
}

// validateOfficialWebhookURL 校验官方 webhook 地址形态。
func validateOfficialWebhookURL(raw, host, pathPrefix, requiredQuery string) error {
	trimmed := strings.TrimSpace(raw)
	if err := rejectControlChars(trimmed); err != nil {
		return err
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: webhook url must be an absolute https url", ErrConfig)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: webhook url must use https", ErrConfig)
	}
	if u.User != nil {
		return fmt.Errorf("%w: webhook url must not contain userinfo", ErrConfig)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: webhook url must not contain a fragment", ErrConfig)
	}
	if !strings.EqualFold(u.Hostname(), host) {
		return fmt.Errorf("%w: webhook url host is not the official endpoint", ErrConfig)
	}
	if !strings.HasPrefix(u.Path, pathPrefix) {
		return fmt.Errorf("%w: webhook url path is not the official endpoint", ErrConfig)
	}
	if requiredQuery != "" {
		values := u.Query()
		token := values.Get(requiredQuery)
		if token == "" || len(values) != 1 {
			return fmt.Errorf("%w: webhook url must carry exactly one %s query value", ErrConfig, requiredQuery)
		}
	} else if u.RawQuery != "" {
		return fmt.Errorf("%w: webhook url must not carry a query", ErrConfig)
	}
	return nil
}

// validateSlackWebhookURL 校验 Slack incoming webhook 地址。
// 支持 hooks.slack.com 与 hooks.slack-gov.com 的 /services/ 路径。
func validateSlackWebhookURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if err := rejectControlChars(trimmed); err != nil {
		return err
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: slack webhook url must be an absolute https url", ErrConfig)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: slack webhook url must use https", ErrConfig)
	}
	if u.User != nil {
		return fmt.Errorf("%w: slack webhook url must not contain userinfo", ErrConfig)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: slack webhook url must not contain a fragment", ErrConfig)
	}
	host := strings.ToLower(u.Hostname())
	if host != "hooks.slack.com" && host != "hooks.slack-gov.com" {
		return fmt.Errorf("%w: slack webhook url host is not the official endpoint", ErrConfig)
	}
	if !strings.HasPrefix(u.Path, "/services/") {
		return fmt.Errorf("%w: slack webhook url path is not the official endpoint", ErrConfig)
	}
	return nil
}

// rejectControlChars 拒绝 URL 中的控制字符，防止隐藏字符绕过主机/路径校验。
func rejectControlChars(raw string) error {
	for _, r := range raw {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: url must not contain control characters", ErrConfig)
		}
	}
	return nil
}

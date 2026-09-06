package notifier

import (
	"fmt"
	"strings"

	"furtalk/internal/platform/urlx"
)

// Validate 校验解密后的配置可以发送：平台字段完整且 URL 形态合规。
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
		if err := validateBarkBaseURL(cfg.ServerURL); err != nil {
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

// validateBarkBaseURL 校验 Bark 的 HTTP(S) 基础 URL。
func validateBarkBaseURL(raw string) error {
	if _, err := urlx.ParseHTTPBase(raw); err != nil {
		return fmt.Errorf("%w: bark server url must be an absolute http(s) base url", ErrConfig)
	}
	return nil
}

// ValidateTrustedURL 校验管理员可配置的绝对 HTTP(S) 通用 Webhook 地址。
func ValidateTrustedURL(raw string) error {
	u, err := urlx.ParseHTTP(raw)
	if err != nil {
		return fmt.Errorf("%w: url must be an absolute http(s) url", ErrConfig)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: url must not contain a fragment", ErrConfig)
	}
	return nil
}

// ValidateWebhookURL 校验官方入站 webhook 地址的主机与路径形态。
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
	u, err := urlx.ParseHTTPS(raw)
	if err != nil {
		return fmt.Errorf("%w: webhook url must be an absolute https url", ErrConfig)
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
func validateSlackWebhookURL(raw string) error {
	u, err := urlx.ParseHTTPS(raw)
	if err != nil {
		return fmt.Errorf("%w: slack webhook url must be an absolute https url", ErrConfig)
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

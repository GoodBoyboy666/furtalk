package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"unicode/utf8"
)

// discordMaxRunes 是 Discord 消息 content 的字符上限。
const discordMaxRunes = 2000

// sendDiscord 向 Discord execute webhook 端点投递。
// wait=true 强制服务端返回创建后的 Message 以获得权威结果；
// allowed_mentions.parse=[] 抑制全部用户提及；content 转义 Markdown 控制字符。
func (d *Dispatcher) sendDiscord(ctx context.Context, cfg Config, msg Message) error {
	endpoint, err := url.Parse(cfg.WebhookURL)
	if err != nil {
		return &DeliveryError{Class: "network", Detail: "request_failed"}
	}
	query := endpoint.Query()
	query.Set("wait", "true")
	endpoint.RawQuery = query.Encode()

	head := breakMentions(msg.Title) + "\n\n" + breakMentions(msg.Text)
	urlBlock := ""
	if msg.PageURL != "" {
		urlBlock = "\n\n" + msg.PageURL
	}
	// 只为用户可控文本预留空间后转义 Markdown，页面 URL 原样保留。
	head, _ = TruncateRunes(head, discordMaxRunes-utf8.RuneCountInString(urlBlock))
	text := escapeDiscordMarkdown(head) + urlBlock
	payload := map[string]any{
		"content": text,
		"allowed_mentions": map[string]any{
			"parse": []string{},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &DeliveryError{Class: "response", Detail: "encode_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return &DeliveryError{Class: "network", Detail: "request_failed"}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.do(ctx, req)
	if err != nil {
		return err
	}
	raw, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return httpStatusError(resp.StatusCode)
	}
	if !json.Valid(raw) {
		return &DeliveryError{Class: "platform", Detail: "malformed_response"}
	}
	return nil
}

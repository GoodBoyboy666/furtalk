package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// slackMaxRunes 是 Slack 顶层 text 的建议字符上限。
const slackMaxRunes = 4000

// sendSlack 向 Slack incoming webhook 投递。
func (d *Dispatcher) sendSlack(ctx context.Context, cfg Config, msg Message) error {
	text := composeText(msg.Title, msg.Text, msg.PageURL, slackMaxRunes)
	payload := map[string]any{
		"text":         text,
		"mrkdwn":       false,
		"unfurl_links": false,
		"unfurl_media": false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &DeliveryError{Class: "response", Detail: "encode_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
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
	// Slack 成功响应允许首尾空白，正文必须为 ok。
	if strings.TrimSpace(string(raw)) != "ok" {
		return &DeliveryError{Class: "platform", Detail: "unexpected_body"}
	}
	return nil
}

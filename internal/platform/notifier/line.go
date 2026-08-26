package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

// lineMaxUTF16 是 LINE 文本消息的 UTF-16 code unit 上限。
const lineMaxUTF16 = 5000

// sendLine 向 LINE Messaging API push 端点投递。
// 端点固定为 https://api.line.me/v2/bot/message/push，使用原始 text 消息对象
// （不使用 textV2，避免替代/mention 行为）；成功判定为 HTTP 200 且响应为合法 JSON。
func (d *Dispatcher) sendLine(ctx context.Context, cfg Config, msg Message) error {
	text := composeTextUTF16(msg.Title, msg.Text, msg.PageURL, lineMaxUTF16)
	payload := map[string]any{
		"to": cfg.TargetID,
		"messages": []map[string]any{
			{"type": "text", "text": text},
		},
		"notificationDisabled": false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &DeliveryError{Class: "response", Detail: "encode_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.line.me/v2/bot/message/push", bytes.NewReader(body))
	if err != nil {
		return &DeliveryError{Class: "network", Detail: "request_failed"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.ChannelAccessToken)

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

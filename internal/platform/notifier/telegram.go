package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// telegramMaxRunes 是 Telegram sendMessage text 的字符上限（1..4096）。
const telegramMaxRunes = 4096

// sendTelegram 向 Telegram Bot API sendMessage 投递。
// 固定端点嵌入令牌路径；JSON 载荷不带 parse_mode/entities，并禁用链接预览；
// 成功判定为 HTTP 2xx 且 ok==true。
func (d *Dispatcher) sendTelegram(ctx context.Context, cfg Config, msg Message) error {
	url := "https://api.telegram.org/bot" + cfg.BotToken + "/sendMessage"
	payload := map[string]any{
		"chat_id": cfg.ChatID,
		"text":    composeText(msg.Title, msg.Text, msg.PageURL, telegramMaxRunes),
		"link_preview_options": map[string]any{
			"is_disabled": true,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &DeliveryError{Class: "response", Detail: "encode_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return httpStatusError(resp.StatusCode)
	}
	var result struct {
		OK        bool `json:"ok"`
		ErrorCode int  `json:"error_code"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return &DeliveryError{Class: "platform", Detail: "malformed_response"}
	}
	if !result.OK {
		detail := "ok_false"
		if result.ErrorCode != 0 {
			detail = "telegram_error_" + strconv.Itoa(result.ErrorCode)
		}
		return &DeliveryError{Class: "platform", Detail: detail}
	}
	return nil
}

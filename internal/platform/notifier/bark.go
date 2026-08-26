package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// bark 载荷的字节预算常量。
// APNs 将单条远程通知载荷上限设为 4096 字节（含 JSON/APNs 开销），
// 这里按 UTF-8 字节预算截断正文，并限制标题字符数，保证序列化后远低于上限。
const (
	barkTitleMaxRunes = 100
	barkBodyMaxBytes  = 2500
)

// sendBark 向 Bark V2 push 端点投递。
// 端点按 {server_url}/push 拼接；成功判定为 HTTP 2xx 且 code==200。
func (d *Dispatcher) sendBark(ctx context.Context, cfg Config, msg Message) error {
	base := strings.TrimSuffix(cfg.ServerURL, "/")
	endpoint := base + "/push"
	if _, err := url.Parse(endpoint); err != nil {
		return &DeliveryError{Class: "network", Detail: "request_failed"}
	}
	title, _ := TruncateRunes(msg.Title, barkTitleMaxRunes)
	body := breakMentions(msg.Text)
	urlBlock := ""
	if msg.PageURL != "" {
		urlBlock = "\n\n" + msg.PageURL
	}
	body, _ = truncateBytes(body, barkBodyMaxBytes-len(urlBlock))
	body += urlBlock

	payload := map[string]any{
		"device_key": cfg.DeviceKey,
		"title":      title,
		"body":       body,
		"group":      "Furtalk",
	}
	if msg.PageURL != "" {
		payload["url"] = msg.PageURL
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return &DeliveryError{Class: "response", Detail: "encode_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return &DeliveryError{Class: "network", Detail: "request_failed"}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := d.do(ctx, req)
	if err != nil {
		return err
	}
	bodyRaw, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return httpStatusError(resp.StatusCode)
	}
	var result struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(bodyRaw, &result); err != nil {
		return &DeliveryError{Class: "platform", Detail: "malformed_response"}
	}
	if result.Code != 200 {
		return &DeliveryError{Class: "platform", Detail: "bark_code_not_200"}
	}
	return nil
}

package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// feishuMaxRunes 是飞书自定义机器人文本的保守字符上限，
// 使整体 JSON 请求体远低于平台约 30KB 的建议上限。
const feishuMaxRunes = 4000

// feishuSign 计算飞书自定义机器人签名：
// string_to_sign = timestamp + "\n" + secret；
// 以 string_to_sign 为 HMAC 密钥、空消息计算 SHA-256，再 Base64 编码。
// 与钉钉的 HMAC 操作数顺序和 timestamp 单位不同，不能共享签名 helper。
func feishuSign(secret string, timestamp int64) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	mac := hmac.New(sha256.New, []byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// sendFeishu 向飞书自定义机器人 webhook 投递文本消息。
// 配置签名密钥时在 JSON 顶层附带 timestamp 与 sign；
// 成功判定为 HTTP 2xx 且 code==0 或遗留 StatusCode==0。
func (d *Dispatcher) sendFeishu(ctx context.Context, cfg Config, msg Message) error {
	text, _ := TruncateRunes(breakMentions(msg.Title)+"\n\n"+breakMentions(msg.Text), feishuMaxRunes)
	if msg.PageURL != "" {
		text += "\n\n" + msg.PageURL
	}
	payload := map[string]any{
		"msg_type": "text",
		"content": map[string]any{
			"text": text,
		},
	}
	if cfg.SigningSecret != "" {
		timestamp := d.now().Unix()
		payload["timestamp"] = strconv.FormatInt(timestamp, 10)
		payload["sign"] = feishuSign(cfg.SigningSecret, timestamp)
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return httpStatusError(resp.StatusCode)
	}
	// 成功判定：显式存在的成功判别字段（code / 遗留 StatusCode）必须都为 0。
	// 缺失/未知成功字段失败关闭，避免空响应被误判为成功。
	var disc struct {
		Code       *int `json:"code"`
		StatusCode *int `json:"StatusCode"`
	}
	if err := json.Unmarshal(raw, &disc); err != nil {
		return &DeliveryError{Class: "platform", Detail: "malformed_response"}
	}
	if disc.Code == nil && disc.StatusCode == nil {
		return &DeliveryError{Class: "platform", Detail: "missing_success_field"}
	}
	if (disc.Code != nil && *disc.Code != 0) || (disc.StatusCode != nil && *disc.StatusCode != 0) {
		code := 0
		if disc.Code != nil {
			code = *disc.Code
		} else {
			code = *disc.StatusCode
		}
		return &DeliveryError{Class: "platform", Detail: "feishu_code_" + strconv.Itoa(code)}
	}
	return nil
}

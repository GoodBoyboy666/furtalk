package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
)

// WebHook v1 请求头名称。
const (
	webhookVersionHeader   = "X-FurTalk-Webhook-Version"
	webhookTimestampHeader = "X-FurTalk-Webhook-Timestamp"
	webhookSignatureHeader = "X-FurTalk-Webhook-Signature"
	webhookVersionValue    = "1"
)

// sendWebHook 向通用 WebHook 投递固定 v1 信封。
// 请求体为上层构造并序列化的原始字节（msg.WebHookRaw），签名与发送使用
// 同一字节切片，绝不重新序列化。版本与时间戳头始终存在；配置签名密钥时
// 追加 sha256 签名头：签名输入为 timestamp + "." + raw_body。
// 任何 2xx 都视为接收成功；重定向在 client 层被拒绝。
func (d *Dispatcher) sendWebHook(ctx context.Context, cfg Config, msg Message) error {
	if len(msg.WebHookRaw) == 0 {
		return &DeliveryError{Class: "response", Detail: "empty_webhook_body"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(msg.WebHookRaw))
	if err != nil {
		return &DeliveryError{Class: "network", Detail: "request_failed"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhookVersionHeader, webhookVersionValue)
	timestamp := d.now().Unix()
	req.Header.Set(webhookTimestampHeader, strconv.FormatInt(timestamp, 10))
	if cfg.SigningSecret != "" {
		req.Header.Set(webhookSignatureHeader, "sha256="+webhookSignature(cfg.SigningSecret, timestamp, msg.WebHookRaw))
	}

	resp, err := d.do(ctx, req)
	if err != nil {
		return err
	}
	if _, err := readBody(resp); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return httpStatusError(resp.StatusCode)
	}
	return nil
}

// webhookSignature 计算 WebHook HMAC-SHA256 签名：
// signed_payload = decimal_unix_seconds + "." + raw_request_body；
// 返回小写十六进制摘要，接收方应用常数时间比较。
func webhookSignature(secret string, timestamp int64, rawBody []byte) string {
	signed := append([]byte(strconv.FormatInt(timestamp, 10)+"."), rawBody...)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signed)
	return hex.EncodeToString(mac.Sum(nil))
}

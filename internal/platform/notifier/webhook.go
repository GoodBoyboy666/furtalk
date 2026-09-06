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
func webhookSignature(secret string, timestamp int64, rawBody []byte) string {
	signed := append([]byte(strconv.FormatInt(timestamp, 10)+"."), rawBody...)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signed)
	return hex.EncodeToString(mac.Sum(nil))
}

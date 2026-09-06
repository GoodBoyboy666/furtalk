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
	"net/url"
	"strconv"

	"furtalk/internal/platform/urlx"
)

// dingtalkMaxRunes 是钉钉自定义机器人文本的字符预算。
const dingtalkMaxRunes = 4000

// dingtalkSign 计算钉钉自定义机器人签名：
func dingtalkSign(secret string, timestamp int64) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	return url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

// sendDingTalk 向钉钉自定义机器人 webhook 投递文本消息。
func (d *Dispatcher) sendDingTalk(ctx context.Context, cfg Config, msg Message) error {
	endpoint, err := urlx.ParseHTTPS(cfg.WebhookURL)
	if err != nil {
		return &DeliveryError{Class: "network", Detail: "request_failed"}
	}
	if cfg.SigningSecret != "" {
		timestamp := d.now().UnixMilli()
		query := endpoint.Query()
		query.Set("timestamp", strconv.FormatInt(timestamp, 10))
		query.Set("sign", dingtalkSign(cfg.SigningSecret, timestamp))
		endpoint.RawQuery = query.Encode()
	}
	text, _ := TruncateRunes(breakMentions(msg.Title)+"\n\n"+breakMentions(msg.Text), dingtalkMaxRunes)
	if msg.PageURL != "" {
		text += "\n\n" + msg.PageURL
	}
	payload := map[string]any{
		"msgtype": "text",
		"text": map[string]any{
			"content": text,
		},
		"at": map[string]any{
			"atMobiles": []string{},
			"atUserIds": []string{},
			"isAtAll":   false,
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return httpStatusError(resp.StatusCode)
	}
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return &DeliveryError{Class: "platform", Detail: "malformed_response"}
	}
	if result.ErrCode != 0 {
		return &DeliveryError{Class: "platform", Detail: "dingtalk_code_" + strconv.Itoa(result.ErrCode)}
	}
	return nil
}

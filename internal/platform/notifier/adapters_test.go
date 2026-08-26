package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stdMsg 返回一条带页面 URL 的规范化消息。
func stdMsg() Message {
	return Message{
		Title:   "新评论",
		Text:    "站点：Example\n作者：Alice\n\nHello 评论内容",
		PageURL: "https://example.com/post",
	}
}

// bodyMap 解析捕获到的 JSON 请求体。
func bodyMap(t *testing.T, captures *[]requestCapture, i int) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal((*captures)[i].body, &m); err != nil {
		t.Fatalf("decode request body %q: %v", (*captures)[i].body, err)
	}
	return m
}

// TestTelegram 验证 Telegram sendMessage 的端点、载荷与成功判定。
func TestTelegram(t *testing.T) {
	d, captures := newTestDispatcher(t, okJSON(`{"ok":true,"result":{"message_id":1}}`))
	cfg := Config{Platform: PlatformTelegram, BotToken: "secret-token", ChatID: "123456"}
	ctx := context.Background()
	if err := d.Send(ctx, cfg, stdMsg()); err != nil {
		t.Fatalf("Send = %v, want nil", err)
	}
	if len(*captures) != 1 {
		t.Fatalf("requests = %d, want 1", len(*captures))
	}
	c := (*captures)[0]
	if c.req.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", c.req.Method)
	}
	wantURL := "https://api.telegram.org/botsecret-token/sendMessage"
	if c.req.URL.String() != wantURL {
		t.Fatalf("url = %s, want %s", c.req.URL.String(), wantURL)
	}
	body := bodyMap(t, captures, 0)
	if body["chat_id"] != "123456" {
		t.Fatalf("chat_id = %v", body["chat_id"])
	}
	text, _ := body["text"].(string)
	if !strings.Contains(text, "@\u200b") && !strings.Contains(text, "Alice") {
		t.Fatalf("text must break mentions but keep content: %q", text)
	}
	if _, ok := body["parse_mode"]; ok {
		t.Fatalf("parse_mode must be omitted")
	}
	preview, ok := body["link_preview_options"].(map[string]any)
	if !ok || preview["is_disabled"] != true {
		t.Fatalf("link_preview_options = %v, want is_disabled=true", body["link_preview_options"])
	}
}

// TestTelegramPlatformRejection 验证 ok=false 平台错误被识别为投递失败。
func TestTelegramPlatformRejection(t *testing.T) {
	d, _ := newTestDispatcher(t, okJSON(`{"ok":false,"error_code":400,"description":"Bad Request"}`))
	err := d.Send(context.Background(), Config{Platform: PlatformTelegram, BotToken: "t", ChatID: "1"}, stdMsg())
	assertDeliveryError(t, err, "platform")
	if !strings.Contains(err.Error(), "telegram_error_400") {
		t.Fatalf("error = %v, want telegram_error_400 detail", err)
	}
}

// TestTelegramHTTPError 验证非 2xx 返回 http 类别错误。
func TestTelegramHTTPError(t *testing.T) {
	d, _ := newTestDispatcher(t, func(*http.Request) (int, string) { return http.StatusInternalServerError, "boom" })
	err := d.Send(context.Background(), Config{Platform: PlatformTelegram, BotToken: "t", ChatID: "1"}, stdMsg())
	assertDeliveryError(t, err, "http")
}

// TestFeishu 验证飞书文本消息与可选签名字段。
func TestFeishu(t *testing.T) {
	cfg := Config{Platform: PlatformFeishu, WebhookURL: "https://open.feishu.cn/open-apis/bot/v2/hook/x"}
	t.Run("unsigned", func(t *testing.T) {
		d, captures := newTestDispatcher(t, okJSON(`{"code":0}`))
		if err := d.Send(context.Background(), cfg, stdMsg()); err != nil {
			t.Fatalf("Send = %v, want nil", err)
		}
		body := bodyMap(t, captures, 0)
		if body["msg_type"] != "text" {
			t.Fatalf("msg_type = %v", body["msg_type"])
		}
		if _, ok := body["timestamp"]; ok {
			t.Fatalf("unsigned request must not carry timestamp")
		}
		if _, ok := body["sign"]; ok {
			t.Fatalf("unsigned request must not carry sign")
		}
	})
	t.Run("legacy status code", func(t *testing.T) {
		d, _ := newTestDispatcher(t, okJSON(`{"StatusCode":0}`))
		if err := d.Send(context.Background(), cfg, stdMsg()); err != nil {
			t.Fatalf("legacy success = %v, want nil", err)
		}
	})
	t.Run("signed", func(t *testing.T) {
		fixed := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
		d, captures := newTestDispatcher(t, okJSON(`{"code":0}`))
		d.setClock(func() time.Time { return fixed })
		signed := cfg
		signed.SigningSecret = "sec"
		if err := d.Send(context.Background(), signed, stdMsg()); err != nil {
			t.Fatalf("Send signed = %v, want nil", err)
		}
		body := bodyMap(t, captures, 0)
		if body["timestamp"] != strconv.FormatInt(fixed.Unix(), 10) {
			t.Fatalf("timestamp = %v, want %d", body["timestamp"], fixed.Unix())
		}
		wantSign := feishuSign("sec", fixed.Unix())
		if body["sign"] != wantSign {
			t.Fatalf("sign = %v, want %s", body["sign"], wantSign)
		}
	})
	t.Run("platform error", func(t *testing.T) {
		d, _ := newTestDispatcher(t, okJSON(`{"code":19001,"msg":"invalid token"}`))
		err := d.Send(context.Background(), cfg, stdMsg())
		assertDeliveryError(t, err, "platform")
	})
}

// TestDingTalk 验证钉钉文本消息、空 mention 列表与签名查询参数。
func TestDingTalk(t *testing.T) {
	base := "https://oapi.dingtalk.com/robot/send?access_token=x"
	cfg := Config{Platform: PlatformDingTalk, WebhookURL: base}
	t.Run("unsigned", func(t *testing.T) {
		d, captures := newTestDispatcher(t, okJSON(`{"errcode":0}`))
		if err := d.Send(context.Background(), cfg, stdMsg()); err != nil {
			t.Fatalf("Send = %v, want nil", err)
		}
		c := (*captures)[0]
		if c.req.URL.Query().Get("access_token") != "x" {
			t.Fatalf("access_token missing: %s", c.req.URL.String())
		}
		if c.req.URL.Query().Get("timestamp") != "" {
			t.Fatalf("unsigned must not carry timestamp")
		}
		body := bodyMap(t, captures, 0)
		at, ok := body["at"].(map[string]any)
		if !ok {
			t.Fatalf("at field missing")
		}
		if at["isAtAll"] != false {
			t.Fatalf("isAtAll = %v, want false", at["isAtAll"])
		}
	})
	t.Run("signed", func(t *testing.T) {
		fixed := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
		d, captures := newTestDispatcher(t, okJSON(`{"errcode":0}`))
		d.setClock(func() time.Time { return fixed })
		signed := cfg
		signed.SigningSecret = "sec"
		if err := d.Send(context.Background(), signed, stdMsg()); err != nil {
			t.Fatalf("Send signed = %v, want nil", err)
		}
		q := (*captures)[0].req.URL.Query()
		ts := q.Get("timestamp")
		if ts != strconv.FormatInt(fixed.UnixMilli(), 10) {
			t.Fatalf("timestamp = %q, want unix ms %d", ts, fixed.UnixMilli())
		}
		wantSign := dingtalkSign("sec", fixed.UnixMilli())
		if q.Get("sign") != wantSign {
			t.Fatalf("sign = %q, want %q", q.Get("sign"), wantSign)
		}
	})
	t.Run("platform error", func(t *testing.T) {
		d, _ := newTestDispatcher(t, okJSON(`{"errcode":300001}`))
		err := d.Send(context.Background(), cfg, stdMsg())
		assertDeliveryError(t, err, "platform")
	})
}

// TestBark 验证 Bark V2 push 端点与 code==200 成功判定。
func TestBark(t *testing.T) {
	cfg := Config{Platform: PlatformBark, ServerURL: "https://api.day.app", DeviceKey: "device-key"}
	d, captures := newTestDispatcher(t, okJSON(`{"code":200,"message":"success"}`))
	if err := d.Send(context.Background(), cfg, stdMsg()); err != nil {
		t.Fatalf("Send = %v, want nil", err)
	}
	c := (*captures)[0]
	if c.req.URL.String() != "https://api.day.app/push" {
		t.Fatalf("url = %s, want base/push", c.req.URL.String())
	}
	body := bodyMap(t, captures, 0)
	if body["device_key"] != "device-key" || body["title"] != "新评论" || body["group"] != "Furtalk" {
		t.Fatalf("bark body = %v", body)
	}
	if body["url"] != "https://example.com/post" {
		t.Fatalf("bark url = %v", body["url"])
	}
}

// TestBarkErrorCode 验证 Bark 非 200 code 被识别为投递失败。
func TestBarkErrorCode(t *testing.T) {
	d, _ := newTestDispatcher(t, okJSON(`{"code":500,"message":"bad"}`))
	err := d.Send(context.Background(), Config{Platform: PlatformBark, ServerURL: "https://api.day.app", DeviceKey: "k"}, stdMsg())
	assertDeliveryError(t, err, "platform")
}

// TestSlack 验证 Slack incoming webhook 载荷与 "ok" 响应判定。
func TestSlack(t *testing.T) {
	cfg := Config{Platform: PlatformSlack, WebhookURL: "https://hooks.slack.com/services/T/B/X"}
	d, captures := newTestDispatcher(t, okJSON(`ok`))
	if err := d.Send(context.Background(), cfg, stdMsg()); err != nil {
		t.Fatalf("Send = %v, want nil", err)
	}
	body := bodyMap(t, captures, 0)
	if body["mrkdwn"] != false || body["unfurl_links"] != false || body["unfurl_media"] != false {
		t.Fatalf("slack body = %v, want unfurl/mrkdwn disabled", body)
	}
}

// TestSlackRejection 验证 Slack 非 "ok" 正文被识别为失败。
func TestSlackRejection(t *testing.T) {
	d, _ := newTestDispatcher(t, okJSON(`invalid_payload`))
	err := d.Send(context.Background(), Config{Platform: PlatformSlack, WebhookURL: "https://hooks.slack.com/services/T/B/X"}, stdMsg())
	assertDeliveryError(t, err, "platform")
}

// TestLine 验证 LINE push 端点、Bearer 头与载荷。
func TestLine(t *testing.T) {
	cfg := Config{Platform: PlatformLine, ChannelAccessToken: "token", TargetID: "U123"}
	d, captures := newTestDispatcher(t, okJSON(`{"sentMessages":[{"id":"1"}]}`))
	if err := d.Send(context.Background(), cfg, stdMsg()); err != nil {
		t.Fatalf("Send = %v, want nil", err)
	}
	c := (*captures)[0]
	if c.req.URL.String() != "https://api.line.me/v2/bot/message/push" {
		t.Fatalf("url = %s", c.req.URL.String())
	}
	if c.req.Header.Get("Authorization") != "Bearer token" {
		t.Fatalf("authorization = %q", c.req.Header.Get("Authorization"))
	}
	body := bodyMap(t, captures, 0)
	if body["to"] != "U123" {
		t.Fatalf("to = %v", body["to"])
	}
}

// TestDiscord 验证 Discord wait=true 与 allowed_mentions 抑制。
func TestDiscord(t *testing.T) {
	cfg := Config{Platform: PlatformDiscord, WebhookURL: "https://discord.com/api/webhooks/123/tok"}
	d, captures := newTestDispatcher(t, okJSON(`{"id":"msg1"}`))
	if err := d.Send(context.Background(), cfg, stdMsg()); err != nil {
		t.Fatalf("Send = %v, want nil", err)
	}
	c := (*captures)[0]
	if c.req.URL.Query().Get("wait") != "true" {
		t.Fatalf("wait query = %q, want true", c.req.URL.Query().Get("wait"))
	}
	body := bodyMap(t, captures, 0)
	am, ok := body["allowed_mentions"].(map[string]any)
	if !ok {
		t.Fatalf("allowed_mentions missing")
	}
	if parse, ok := am["parse"].([]any); !ok || len(parse) != 0 {
		t.Fatalf("allowed_mentions.parse = %v, want []", am["parse"])
	}
}

// TestWebHookSignatureVector 用固定时间戳/正文/密钥向量证明 HMAC 签名字节级正确性。
// 向量由独立工具（HMAC-SHA256 over "1787659200."+body, key="secret"）预计算。
func TestWebHookSignatureVector(t *testing.T) {
	fixed := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	raw := []byte(`{"version":"1","event":"comment.created"}`)
	got := webhookSignature("secret", fixed.Unix(), raw)
	want := "67192b9ff27f041632042d1ec491e25da6fbd9ed169889d52fc9aa561f4b4243"
	if got != want {
		t.Fatalf("webhookSignature = %s, want %s", got, want)
	}
}

// TestWebHookSignature 验证 WebHook v1 头与 HMAC 签名的字节级正确性。
func TestWebHookSignature(t *testing.T) {
	fixed := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	raw := []byte(`{"version":"1","event":"comment.created"}`)
	cfg := Config{Platform: PlatformWebHook, WebhookURL: "http://127.0.0.1:9000/hook", SigningSecret: "secret"}

	t.Run("signed", func(t *testing.T) {
		d, captures := newTestDispatcher(t, func(*http.Request) (int, string) { return http.StatusCreated, "{}" })
		d.setClock(func() time.Time { return fixed })
		if err := d.Send(context.Background(), cfg, Message{WebHookRaw: raw}); err != nil {
			t.Fatalf("Send = %v, want nil", err)
		}
		c := (*captures)[0]
		if c.req.Header.Get("X-FurTalk-Webhook-Version") != "1" {
			t.Fatalf("version header = %q", c.req.Header.Get("X-FurTalk-Webhook-Version"))
		}
		if c.req.Header.Get("X-FurTalk-Webhook-Timestamp") != strconv.FormatInt(fixed.Unix(), 10) {
			t.Fatalf("timestamp header = %q", c.req.Header.Get("X-FurTalk-Webhook-Timestamp"))
		}
		want := webhookSignature("secret", fixed.Unix(), raw)
		if got := c.req.Header.Get("X-FurTalk-Webhook-Signature"); got != "sha256="+want {
			t.Fatalf("signature header = %q, want sha256=%s", got, want)
		}
		// 请求体必须与签名输入完全一致。
		if string(c.body) != string(raw) {
			t.Fatalf("request body = %q, want raw %q", c.body, raw)
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		d, captures := newTestDispatcher(t, okJSON(`{}`))
		d.setClock(func() time.Time { return fixed })
		if err := d.Send(context.Background(), Config{Platform: PlatformWebHook, WebhookURL: cfg.WebhookURL}, Message{WebHookRaw: raw}); err != nil {
			t.Fatalf("Send unsigned = %v, want nil", err)
		}
		if h := (*captures)[0].req.Header.Get("X-FurTalk-Webhook-Signature"); h != "" {
			t.Fatalf("unsigned request must omit signature, got %q", h)
		}
		if (*captures)[0].req.Header.Get("X-FurTalk-Webhook-Timestamp") == "" {
			t.Fatalf("timestamp header must always be present")
		}
	})
	t.Run("empty body rejected", func(t *testing.T) {
		d, _ := newTestDispatcher(t, okJSON(`{}`))
		err := d.Send(context.Background(), cfg, Message{})
		assertDeliveryError(t, err, "response")
	})
}

// TestRedirectRefusal 验证 3xx 重定向不被跟随且被判定为失败。
func TestRedirectRefusal(t *testing.T) {
	d, captures := newTestDispatcher(t, func(*http.Request) (int, string) {
		return http.StatusFound, ""
	})
	// 自定义 302 响应携带 Location，验证 client 拒绝跟随。
	d.setTransport(fakeTransport{fn: func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		req.Body.Close()
		*captures = append(*captures, requestCapture{req: req, body: body})
		resp := &http.Response{
			StatusCode: http.StatusFound,
			Status:     "302 Found",
			Header:     http.Header{"Location": []string{"https://evil.example.com/"}},
			Body:       http.NoBody,
			Request:    req,
		}
		return resp, nil
	}})
	err := d.Send(context.Background(), Config{Platform: PlatformWebHook, WebhookURL: "http://127.0.0.1:9000/hook"}, Message{WebHookRaw: []byte(`{}`)})
	assertDeliveryError(t, err, "http")
	if len(*captures) != 1 {
		t.Fatalf("transport called %d times, want 1 (no redirect follow)", len(*captures))
	}
}

// TestResponseBodyTooLarge 验证超限响应体被拒绝。
func TestResponseBodyTooLarge(t *testing.T) {
	d := NewDispatcher()
	d.setTransport(fakeTransport{fn: func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        make(http.Header),
			Body:          http.NoBody,
			ContentLength: maxResponseBytes + 1,
			Request:       req,
		}, nil
	}})
	err := d.Send(context.Background(), Config{Platform: PlatformWebHook, WebhookURL: "http://127.0.0.1:9000/hook"}, Message{WebHookRaw: []byte(`{}`)})
	assertDeliveryError(t, err, "response")
}

// TestUnknownPlatform 验证未知平台返回配置错误。
func TestUnknownPlatform(t *testing.T) {
	d := NewDispatcher()
	err := d.Send(context.Background(), Config{Platform: Platform("nope")}, stdMsg())
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("error = %v, want ErrConfig", err)
	}
}

// TestConfigInvalidRejected 验证无效配置在发送前被拒绝。
func TestConfigInvalidRejected(t *testing.T) {
	d := NewDispatcher()
	err := d.Send(context.Background(), Config{Platform: PlatformTelegram, BotToken: "t"}, stdMsg())
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("error = %v, want ErrConfig", err)
	}
}

// TestDingTalkSignedURLParses 辅助验证带签名查询参数的 URL 仍可解析。
func TestDingTalkSignedURLParses(t *testing.T) {
	u, err := url.Parse("https://oapi.dingtalk.com/robot/send?access_token=x&timestamp=1&sign=abc%2Bdef")
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("sign") != "abc+def" {
		t.Fatalf("sign query = %q", u.Query().Get("sign"))
	}
}

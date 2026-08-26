package notifier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// requestCapture 记录一次出站请求的原始信息。
type requestCapture struct {
	req  *http.Request
	body []byte
}

// fakeTransport 用可编程 responder 拦截全部出站请求。
type fakeTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (t fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.fn(req)
}

// newTestDispatcher 构建带 fake transport 的分发器，返回已捕获请求的指针。
func newTestDispatcher(t *testing.T, responder func(*http.Request) (int, string)) (*Dispatcher, *[]requestCapture) {
	t.Helper()
	d := NewDispatcher()
	var captures []requestCapture
	d.setTransport(fakeTransport{fn: func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		req.Body.Close()
		captures = append(captures, requestCapture{req: req, body: body})
		status, respBody := responder(req)
		return &http.Response{
			StatusCode:    status,
			Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(respBody)),
			ContentLength: int64(len(respBody)),
			Request:       req,
		}, nil
	}})
	return d, &captures
}

// okJSON 返回给定 JSON 的 200 响应。
func okJSON(body string) func(*http.Request) (int, string) {
	return func(*http.Request) (int, string) { return http.StatusOK, body }
}

// assertDeliveryError 断言错误是 DeliveryError 且类别匹配。
func assertDeliveryError(t *testing.T, err error, class string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want delivery error of class %q, got nil", class)
	}
	if !errors.Is(err, ErrDelivery) {
		t.Fatalf("error = %v, want ErrDelivery", err)
	}
	var de *DeliveryError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeliveryError", err)
	}
	if de.Class != class {
		t.Fatalf("error class = %q, want %q (detail=%q)", de.Class, class, de.Detail)
	}
}

// TestParsePlatform 验证 provider key 与平台枚举的映射。
func TestParsePlatform(t *testing.T) {
	valid := map[string]Platform{
		"notification.telegram": PlatformTelegram,
		"notification.feishu":   PlatformFeishu,
		"notification.dingtalk": PlatformDingTalk,
		"notification.bark":     PlatformBark,
		"notification.slack":    PlatformSlack,
		"notification.line":     PlatformLine,
		"notification.webhook":  PlatformWebHook,
		"notification.discord":  PlatformDiscord,
	}
	for key, want := range valid {
		got, err := ParsePlatform(key)
		if err != nil || got != want {
			t.Fatalf("ParsePlatform(%q) = %q, %v; want %q", key, got, err, want)
		}
	}
	for _, bad := range []string{"telegram", "notification.foo", "", "notification."} {
		if _, err := ParsePlatform(bad); !errors.Is(err, ErrConfig) {
			t.Fatalf("ParsePlatform(%q) error = %v, want ErrConfig", bad, err)
		}
	}
}

// TestConfigValidate 验证各平台解密配置的完整性校验。
func TestConfigValidate(t *testing.T) {
	base := Config{}
	valid := []Config{
		{Platform: PlatformTelegram, BotToken: "t", ChatID: "1"},
		{Platform: PlatformFeishu, WebhookURL: "https://open.feishu.cn/open-apis/bot/v2/hook/x"},
		{Platform: PlatformDingTalk, WebhookURL: "https://oapi.dingtalk.com/robot/send?access_token=x"},
		{Platform: PlatformBark, ServerURL: "https://api.day.app", DeviceKey: "k"},
		{Platform: PlatformSlack, WebhookURL: "https://hooks.slack.com/services/T/B/X"},
		{Platform: PlatformLine, ChannelAccessToken: "a", TargetID: "U1"},
		{Platform: PlatformWebHook, WebhookURL: "http://10.0.0.1:8080/hook"},
		{Platform: PlatformDiscord, WebhookURL: "https://discord.com/api/webhooks/1/2"},
	}
	for _, cfg := range valid {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate(%s) = %v, want nil", cfg.Platform, err)
		}
	}
	invalid := []Config{
		{Platform: PlatformTelegram, BotToken: "t"},
		{Platform: PlatformFeishu, WebhookURL: "https://evil.com/hook"},
		{Platform: PlatformDingTalk, WebhookURL: "https://oapi.dingtalk.com/robot/send"},
		{Platform: PlatformBark, ServerURL: "https://api.day.app"},
		{Platform: PlatformLine, ChannelAccessToken: "a"},
		{Platform: PlatformDiscord, WebhookURL: "https://discord.com/not/webhooks/1"},
	}
	for _, cfg := range invalid {
		if err := cfg.Validate(); !errors.Is(err, ErrConfig) {
			t.Fatalf("Validate(%s) error = %v, want ErrConfig", cfg.Platform, err)
		}
	}
	base = Config{} // unknown platform
	if err := base.Validate(); !errors.Is(err, ErrConfig) {
		t.Fatalf("Validate(empty) error = %v, want ErrConfig", err)
	}
}

// TestValidateTrustedURL 验证 Bark/WebHook 的出站地址策略：
// 允许 HTTP/HTTPS 与私网目标，拒绝 userinfo/fragment/控制字符/非法 URL。
func TestValidateTrustedURL(t *testing.T) {
	valid := []string{
		"https://api.day.app",
		"http://10.0.0.1:8080/hook",
		"http://127.0.0.1:9000/push",
		"https://192.168.1.5/webhook",
		"http://[::1]:8080/hook",
	}
	for _, raw := range valid {
		if err := ValidateTrustedURL(raw); err != nil {
			t.Fatalf("ValidateTrustedURL(%q) = %v, want nil", raw, err)
		}
	}
	invalid := []string{
		"", "not-a-url", "ftp://example.com/x", "//host/path",
		"https://user:pass@example.com/x", "https://example.com/x#frag",
		"https://example.com/\x00", "https://", "://missing-scheme",
	}
	for _, raw := range invalid {
		if err := ValidateTrustedURL(raw); !errors.Is(err, ErrConfig) {
			t.Fatalf("ValidateTrustedURL(%q) error = %v, want ErrConfig", raw, err)
		}
	}
}

// TestValidateWebhookURL 验证官方 webhook 地址的主机/路径形态。
func TestValidateWebhookURL(t *testing.T) {
	valid := []struct {
		platform Platform
		url      string
	}{
		{PlatformFeishu, "https://open.feishu.cn/open-apis/bot/v2/hook/abc"},
		{PlatformDingTalk, "https://oapi.dingtalk.com/robot/send?access_token=abc"},
		{PlatformSlack, "https://hooks.slack.com/services/T000/B000/X"},
		{PlatformSlack, "https://hooks.slack-gov.com/services/T/B/X"},
		{PlatformDiscord, "https://discord.com/api/webhooks/123/tok"},
	}
	for _, tc := range valid {
		if err := ValidateWebhookURL(tc.platform, tc.url); err != nil {
			t.Fatalf("ValidateWebhookURL(%s, %q) = %v, want nil", tc.platform, tc.url, err)
		}
	}
	invalid := []struct {
		platform Platform
		url      string
	}{
		{PlatformFeishu, "https://open.feishu.cn/other"},
		{PlatformFeishu, "http://open.feishu.cn/open-apis/bot/v2/hook/x"},
		{PlatformDingTalk, "https://oapi.dingtalk.com/robot/send"},
		{PlatformDingTalk, "https://oapi.dingtalk.com/robot/send?access_token=a&extra=b"},
		{PlatformSlack, "https://evil.com/services/T/B/X"},
		{PlatformDiscord, "https://discord.com/not-api/webhooks/1"},
	}
	for _, tc := range invalid {
		if err := ValidateWebhookURL(tc.platform, tc.url); !errors.Is(err, ErrConfig) {
			t.Fatalf("ValidateWebhookURL(%s, %q) error = %v, want ErrConfig", tc.platform, tc.url, err)
		}
	}
}

// TestTruncation 验证 Unicode 安全的截断逻辑：CJK、组合字符与四字节 emoji。
func TestTruncation(t *testing.T) {
	cjk := "中文评论内容测试"
	got, truncated := TruncateRunes(cjk, 4)
	if !truncated || got != "中文评…" {
		t.Fatalf("TruncateRunes(cjk,4) = %q, %v; want 中文评…, true", got, truncated)
	}

	emoji := "😀😀😀😀"
	got, truncated = TruncateRunes(emoji, 3)
	if !truncated || got != "😀😀…" {
		t.Fatalf("TruncateRunes(emoji,3) = %q, %v; want 😀😀…, true", got, truncated)
	}

	// UTF-16：emoji 计 2 单位。
	if n := utf16Count("a😀b"); n != 4 {
		t.Fatalf("utf16Count(a😀b) = %d, want 4", n)
	}
	line, truncated := truncateUTF16("a😀😀b", 4)
	if !truncated || utf16Count(line) > 4 {
		t.Fatalf("truncateUTF16 = %q (%d units), want <=4", line, utf16Count(line))
	}

	// UTF-8 字节预算（Bark）。
	barkBody, truncated := truncateBytes(strings.Repeat("汉", 1000), 100)
	if !truncated || len(barkBody) > 100+len("…") {
		t.Fatalf("truncateBytes len=%d, want <= 100+ellipsis", len(barkBody))
	}

	// mention 打断与 Discord 转义。
	if got := breakMentions("@user"); got != "@\u200buser" {
		t.Fatalf("breakMentions = %q", got)
	}
	if got := escapeDiscordMarkdown("a*b`c"); got != `a\*b\`+"`"+`c` {
		t.Fatalf("escapeDiscordMarkdown = %q", got)
	}
}

// timeoutNetError 模拟实现 net.Error 的传输超时错误。
type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

// TestComposeTextPreservesURL 验证长文本截断时为页面 URL 预留空间。
func TestComposeTextPreservesURL(t *testing.T) {
	long := strings.Repeat("很长的评论内容", 2000)
	got := composeText("标题", long, "https://example.com/post", 1000)
	if !strings.Contains(got, "https://example.com/post") {
		t.Fatalf("composeText dropped the page url")
	}
	if utf8.RuneCountInString(got) > 1000 {
		t.Fatalf("composeText exceeded budget: %d", utf8.RuneCountInString(got))
	}
	got2 := composeTextUTF16("标题", long, "https://example.com/post", 1000)
	if !strings.Contains(got2, "https://example.com/post") {
		t.Fatalf("composeTextUTF16 dropped the page url")
	}
	if utf16Count(got2) > 1000 {
		t.Fatalf("composeTextUTF16 exceeded budget: %d", utf16Count(got2))
	}
}

// TestTimeoutSanitization 验证传输错误被归一化为不泄露 URL 的类别错误。
func TestTimeoutSanitization(t *testing.T) {
	// 直接测试 sanitizeTransportError 的分支。
	if err := sanitizeTransportError(context.DeadlineExceeded); err.Class != "timeout" {
		t.Fatalf("timeout class = %q, want timeout", err.Class)
	}
	if err := sanitizeTransportError(timeoutNetError{}); err.Class != "timeout" {
		t.Fatalf("net timeout class = %q, want timeout", err.Class)
	}
	if err := sanitizeTransportError(errors.New("boom")); err.Class != "network" {
		t.Fatalf("generic error class = %q, want network", err.Class)
	}
}

// TestClientBounded 验证出站 client 带 5 秒超时并拒绝重定向。
func TestClientBounded(t *testing.T) {
	d := NewDispatcher()
	if d.client.Timeout != 5*time.Second {
		t.Fatalf("client timeout = %v, want 5s", d.client.Timeout)
	}
	err := d.client.CheckRedirect(nil, nil)
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

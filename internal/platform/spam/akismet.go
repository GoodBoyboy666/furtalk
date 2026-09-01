package spam

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// akismetEndpointHost 是 Akismet comment-check 的固定端点主机。
const akismetEndpointHost = "rest.akismet.com"

// AkismetConfig 是 Akismet 检测器的配置。
type AkismetConfig struct {
	// APIKey 是 Akismet API key。
	APIKey string
}

// Akismet 调用 Akismet comment-check 端点，响应严格按 true/false 解析。
// 站点 URL 取自每次送检的 Input.BlogURL。
type Akismet struct {
	client *http.Client
	cfg    AkismetConfig
}

// NewAkismet 构建 Akismet 检测器。
// client 必须携带有界超时。
func NewAkismet(client *http.Client, cfg AkismetConfig) *Akismet {
	if client == nil {
		client = defaultClient()
	}
	return &Akismet{client: client, cfg: cfg}
}

// Check 送检完整评论上下文并按响应判定：
// true 表示垃圾（Block），false 表示通过（Pass）；其他响应、非成功状态或网络错误为 unknown。
func (a *Akismet) Check(ctx context.Context, input Input) (Result, error) {
	form := url.Values{}
	form.Set("blog", input.BlogURL)
	form.Set("user_ip", input.IP)
	form.Set("user_agent", input.UserAgent)
	form.Set("referrer", input.Permalink)
	form.Set("permalink", input.Permalink)
	form.Set("comment_type", input.CommentType)
	form.Set("comment_author", input.Nickname)
	form.Set("comment_author_email", input.Email)
	form.Set("comment_author_url", input.AuthorURL)
	form.Set("comment_content", input.Body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return ResultPass, fmt.Errorf("%w: request construction failed", ErrUnavailable)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		// The request URL contains the provider API key in its hostname. Do not
		// wrap the standard-library error because it may retain that URL.
		return ResultPass, fmt.Errorf("%w: transport failure", ErrUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ResultPass, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ResultPass, fmt.Errorf("%w: response read failed", ErrUnavailable)
	}
	switch strings.TrimSpace(string(body)) {
	case "true":
		return ResultBlock, nil
	case "false":
		return ResultPass, nil
	default:
		return ResultPass, fmt.Errorf("%w: unexpected response body", ErrUnavailable)
	}
}

// endpoint 返回带 API key 的 comment-check HTTPS 端点。
func (a *Akismet) endpoint() string {
	return "https://" + strings.TrimSpace(a.cfg.APIKey) + "." + akismetEndpointHost + "/1.1/comment-check"
}

package oauth

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxOAuthResponseBytes 是所有 OAuth/OIDC 响应共用的硬字节上限。
// 它与现有 CAPTCHA、Spam 预算及 x/oauth2 token 响应上限保持一致。
const maxOAuthResponseBytes int64 = 1 << 20

// ErrResponseTooLarge 表示 OAuth/OIDC provider 响应超过 maxOAuthResponseBytes。
// sentinel 不携带 endpoint 或 body，调用方可分类错误而不会泄露 provider 细节。
var ErrResponseTooLarge = errors.New("oauth: provider response too large")

// isResponseTooLarge 即使依赖使用 %v 格式化而非包装 sentinel，也能识别该类别。
// fallback 只匹配固定文本，不包含请求控制的数据。
func isResponseTooLarge(err error) bool {
	return err != nil && (errors.Is(err, ErrResponseTooLarge) || strings.Contains(err.Error(), ErrResponseTooLarge.Error()))
}

// IsResponseTooLarge 判断 adapter 或依赖是否传播了响应超限类别，
// 也覆盖依赖仅格式化错误文本的情况。
func IsResponseTooLarge(err error) bool {
	return isResponseTooLarge(err)
}

// preserveProviderError 保留响应超限类别，其余 provider 错误继续归一为身份错误。
func preserveProviderError(err error) error {
	if isResponseTooLarge(err) {
		return ErrResponseTooLarge
	}
	return ErrIdentity
}

// boundedTransport 预读并缓存未超限响应，使直接 decoder 与第三方 OIDC 代码获得
// 相同且可重放的 body；超大 body 在到达这些消费者前即被拒绝。
type boundedTransport struct {
	base http.RoundTripper
}

func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.ContentLength > maxOAuthResponseBytes {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, ErrResponseTooLarge
	}
	if resp.Body == nil {
		return resp, nil
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(body)) > maxOAuthResponseBytes {
		return nil, ErrResponseTooLarge
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	return resp, nil
}

// boundedClient 克隆选定的 client，保留 transport、重定向策略、Jar 等设置，
// 同时应用配置的 timeout 与共享有界响应 transport。
func boundedClient(base *http.Client, timeout time.Duration) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	if timeout > 0 {
		client.Timeout = timeout
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = &boundedTransport{base: transport}
	return &client
}

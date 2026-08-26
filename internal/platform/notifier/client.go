package notifier

import (
	"io"
	"net/http"
)

// newBoundedClient 构建带 5 秒整体超时、禁止跟随重定向的 HTTP client。
// 禁止重定向是为了避免把携带凭据/签名的请求转发到非预期地址，
// 也避免绕过配置时的 URL 校验（见 url.go）。
func newBoundedClient() *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// readBody 读取有界响应体；超限或读取失败返回脱敏错误。
func readBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	if resp.ContentLength > maxResponseBytes {
		return nil, &DeliveryError{Class: "response", Detail: "body_too_large"}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, &DeliveryError{Class: "response", Detail: "read_failed"}
	}
	if len(body) > maxResponseBytes {
		return nil, &DeliveryError{Class: "response", Detail: "body_too_large"}
	}
	return body, nil
}

// httpStatusError 把非预期 HTTP 状态码归一化为脱敏错误。
func httpStatusError(status int) *DeliveryError {
	return &DeliveryError{Class: "http", Detail: "HTTP " + http.StatusText(status)}
}

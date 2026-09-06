package spam

import (
	"net"
	"net/http"
	"time"
)

// defaultTimeout 外部渠道单次请求的默认超时。
const defaultTimeout = 3 * time.Second

// defaultClient 返回携带超时的 HTTP 客户端，供外部渠道复用。
func defaultClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: defaultTimeout}).DialContext,
		},
	}
}

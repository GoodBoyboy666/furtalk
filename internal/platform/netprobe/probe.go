// Package netprobe 提供外部 URL 连通性检查。
// 只判断端点是否可达，不会做任何业务决策。
package netprobe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"furtalk/internal/platform/urlx"
)

// ProbeURL 对 URL 执行 GET，并接受任何 HTTP 响应作为可达性证明。
func ProbeURL(ctx context.Context, rawURL string, timeout time.Duration) error {
	u, err := urlx.ParseHTTP(rawURL)
	if err != nil || u.Fragment != "" {
		return fmt.Errorf("netprobe: invalid url %q", rawURL)
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return nil
}

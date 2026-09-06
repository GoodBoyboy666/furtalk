// Package captcha 实现 Turnstile、reCAPTCHA、hCaptcha 与 CAP 的 CAPTCHA 适配器。
package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"furtalk/internal/platform/urlx"
)

var (
	// ErrUnavailable 验证无法到达Provider，或Provider返回非 200/无法解析的响应。
	ErrUnavailable = errors.New("captcha: provider unavailable")
	// ErrFailed Provider报告验证失败（success=false、hostname/action 不匹配）。
	ErrFailed = errors.New("captcha: verification failed")
	// ErrUnsupported Provider名称没有对应适配器。
	ErrUnsupported = errors.New("captcha: unsupported provider")
	// ErrRequired 策略要求 CAPTCHA 但未提供令牌。
	ErrRequired = errors.New("captcha: token required")
)

// defaultTimeout 默认单个 siteverify 请求超时。
const defaultTimeout = 5 * time.Second

// Verifier CAPTCHA 验证接口。
type Verifier interface {
	Verify(ctx context.Context, action, token string) error
}

// Config 携带 CAPTCHA provider 的静态配置。
type Config struct {
	Provider  string
	SiteKey   string
	SecretKey string
	Endpoint  string
	Hostname  string
	Timeout   time.Duration
}

// New 根据配置创建 CAPTCHA 验证器。
func New(cfg Config, client *http.Client) (Verifier, error) {
	endpoint, err := siteVerifyURL(cfg)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, fmt.Errorf("%w: secret key is required", ErrUnavailable)
	}
	if client == nil {
		client = http.DefaultClient
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &verifier{cfg: cfg, http: client, endpoint: endpoint, timeout: timeout}, nil
}

// siteVerifyURL 解析Provider的 siteverify Endpoint。
func siteVerifyURL(cfg Config) (string, error) {
	switch cfg.Provider {
	case "turnstile":
		return validatedOverrideOrDefault(cfg.Endpoint, "https://challenges.cloudflare.com/turnstile/v0/siteverify")
	case "recaptcha":
		return validatedOverrideOrDefault(cfg.Endpoint, "https://www.google.com/recaptcha/api/siteverify")
	case "hcaptcha":
		return validatedOverrideOrDefault(cfg.Endpoint, "https://hcaptcha.com/siteverify")
	case "cap":
		if strings.TrimSpace(cfg.Endpoint) == "" {
			return "", fmt.Errorf("%w: cap endpoint is required", ErrUnavailable)
		}
		base, err := urlx.ParseHTTPBase(cfg.Endpoint)
		if err != nil {
			return "", fmt.Errorf("%w: invalid cap endpoint: %v", ErrUnavailable, err)
		}
		return urlx.JoinPathSegments(base, cfg.SiteKey, "siteverify").String(), nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupported, cfg.Provider)
	}
}

// validatedOverrideOrDefault 校验覆盖地址并在未设置时返回默认地址。
func validatedOverrideOrDefault(override, fallback string) (string, error) {
	if strings.TrimSpace(override) == "" {
		return fallback, nil
	}
	u, err := urlx.ParseHTTPBase(override)
	if err != nil {
		return "", fmt.Errorf("%w: invalid endpoint: %v", ErrUnavailable, err)
	}
	return u.String(), nil
}

// WidgetAPIURL 给浏览器控件使用的公共 API Endpoint。
func WidgetAPIURL(cfg Config) string {
	if cfg.Provider != "cap" || strings.TrimSpace(cfg.Endpoint) == "" {
		return ""
	}
	base, err := urlx.ParseHTTPBase(cfg.Endpoint)
	if err != nil {
		return ""
	}
	return urlx.JoinPathDirectory(base, cfg.SiteKey).String()
}

type verifier struct {
	cfg      Config
	http     *http.Client
	endpoint string
	timeout  time.Duration
}

// siteVerifyResponse 各Provider共享的响应结构。
type siteVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
}

// Verify 验证。
func (c *verifier) Verify(ctx context.Context, action, token string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("%w: empty token", ErrFailed)
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var body io.Reader
	if c.cfg.Provider == "cap" {
		payload, err := json.Marshal(map[string]string{"secret": c.cfg.SecretKey, "response": token})
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		body = bytes.NewReader(payload)
	} else {
		form := url.Values{}
		form.Set("secret", c.cfg.SecretKey)
		form.Set("response", token)
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint, body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if c.cfg.Provider == "cap" {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("%w: http status %d", ErrUnavailable, resp.StatusCode)
	}
	var out siteVerifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !out.Success {
		return fmt.Errorf("%w: %v", ErrFailed, out.ErrorCodes)
	}
	if c.cfg.Hostname != "" && out.Hostname != "" && out.Hostname != c.cfg.Hostname {
		return fmt.Errorf("%w: hostname mismatch", ErrFailed)
	}
	// 响应包含 action 时，非空的期望 action 必须匹配。
	if action != "" && out.Action != "" && out.Action != action {
		return fmt.Errorf("%w: action mismatch", ErrFailed)
	}
	return nil
}

// Probe 不提交 token 的情况下对Provider的 siteverify Endpoint执行连通性检查。
func Probe(ctx context.Context, cfg Config, client *http.Client) error {
	v, err := New(cfg, client)
	if err != nil {
		return err
	}
	c, ok := v.(*verifier)
	if !ok {
		return fmt.Errorf("%w: unexpected verifier", ErrUnavailable)
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return nil
}

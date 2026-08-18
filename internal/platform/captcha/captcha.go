// Package captcha 实现 CAPTCHA 提供方适配器（Turnstile、reCAPTCHA、hCaptcha 与 CAP），
// 统一暴露 Verifier 接口。
// 各适配器在提供方的 siteverify 端点校验 token；
// 网络错误、提供方错误响应、hostname/action 不匹配与配置缺失都返回错误。
// 服务只消费 Verifier 接口，不接触 HTTP 细节。
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
)

var (
	// ErrUnavailable 在验证无法到达提供方，或提供方返回非 200/无法解析的响应时返回。
	// 映射为 HTTP 503。
	ErrUnavailable = errors.New("captcha: provider unavailable")
	// ErrFailed 在提供方报告验证失败（success=false、hostname/action 不匹配）时返回。
	// 映射为 HTTP 403。
	ErrFailed = errors.New("captcha: verification failed")
	// ErrUnsupported 在提供方名称没有对应适配器时返回。
	ErrUnsupported = errors.New("captcha: unsupported provider")
	// ErrRequired 在策略要求 CAPTCHA 但未提供令牌时返回。
	ErrRequired = errors.New("captcha: token required")
)

// defaultTimeout 是 Config.Timeout 为零时的单个 siteverify 请求超时。
const defaultTimeout = 5 * time.Second

// Verifier 是评论与 widget 服务消费的 CAPTCHA 验证边界。
// 实现必须在所有错误路径上默认拒绝，不静默放行。
type Verifier interface {
	Verify(ctx context.Context, action, token string) error
}

// Config 携带解密后的提供方配置与可选的覆盖项。
// Endpoint 覆盖提供方的默认 siteverify URL（供测试与连通性探针使用）；
// Hostname 设置后要求提供方上报的 hostname 完全匹配。
type Config struct {
	Provider  string
	SiteKey   string
	SecretKey string
	Endpoint  string
	Hostname  string
	Timeout   time.Duration
}

// New 为给定的提供方构建适配器。
// 返回的 Verifier 在结构上满足评论/widget 的 CaptchaVerifier 接口。
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

// siteVerifyURL 解析提供方的 siteverify 端点。
// 非 CAP 提供方使用已知固定端点，可被 Config.Endpoint 覆盖（供测试与探针使用）；
// CAP 由管理员配置的实例基址与 site key 派生，不使用占位默认值。
func siteVerifyURL(cfg Config) (string, error) {
	switch cfg.Provider {
	case "turnstile":
		return overrideOrDefault(cfg.Endpoint, "https://challenges.cloudflare.com/turnstile/v0/siteverify"), nil
	case "recaptcha":
		return overrideOrDefault(cfg.Endpoint, "https://www.google.com/recaptcha/api/siteverify"), nil
	case "hcaptcha":
		return overrideOrDefault(cfg.Endpoint, "https://hcaptcha.com/siteverify"), nil
	case "cap":
		if strings.TrimSpace(cfg.Endpoint) == "" {
			return "", fmt.Errorf("%w: cap endpoint is required", ErrUnavailable)
		}
		base, err := normalizeBaseURL(cfg.Endpoint)
		if err != nil {
			return "", err
		}
		return base + "/" + cfg.SiteKey + "/siteverify", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupported, cfg.Provider)
	}
}

// overrideOrDefault 在端点覆盖为空时回落到提供方的固定默认值。
func overrideOrDefault(override, fallback string) string {
	if strings.TrimSpace(override) == "" {
		return fallback
	}
	return override
}

// WidgetAPIURL 返回提供方给浏览器控件使用的公共 API 端点。
// 仅 CAP 需要管理员配置的外部 Standalone 基址派生；其他提供方返回空串。
func WidgetAPIURL(cfg Config) string {
	if cfg.Provider != "cap" || strings.TrimSpace(cfg.Endpoint) == "" {
		return ""
	}
	base, err := normalizeBaseURL(cfg.Endpoint)
	if err != nil {
		return ""
	}
	return base + "/" + cfg.SiteKey + "/"
}

// normalizeBaseURL 校验并规范化绝对 http(s) 实例 URL，供 CAP 派生端点。
// 去除尾部斜杠与查询/片段，不改动主机与协议。
func normalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("%w: invalid endpoint", ErrUnavailable)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String(), nil
}

type verifier struct {
	cfg      Config
	http     *http.Client
	endpoint string
	timeout  time.Duration
}

// siteVerifyResponse 是各提供方共享的响应结构。
// 提供方未返回的字段为空，校验时跳过这些字段。
type siteVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
}

// Verify 把 secret 和 token 提交到提供方的 siteverify 端点。
// CAP 使用官方 JSON 协议；其余提供方沿用 form-urlencoded 协议。
// 仅当提供方确认成功，且上报的 action 与 hostname 匹配时返回 nil，否则返回错误。
// 网络错误、非 200 响应和解析失败都返回 ErrUnavailable。
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
	if action != "" && out.Action != "" && out.Action != action {
		return fmt.Errorf("%w: action mismatch", ErrFailed)
	}
	return nil
}

// Probe 在不提交 token 的情况下对提供方的 siteverify 端点执行有界连通性检查。
// 任何 HTTP 响应（2xx 或 4xx）都证明可达；传输错误或缺少提供方配置则返回错误。
// admin 的 captcha 类型 provider-test 端点依赖此探针。
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

// PolicyCheck 对单个 action 执行策略。
// 策略不要求该 action 时直接放行；否则验证器缺失或不可用返回 ErrUnavailable，
// 缺少令牌返回 ErrRequired，被拒绝的令牌返回 ErrFailed。
// 服务层据此映射为各自 feature 的语义错误。
func PolicyCheck(ctx context.Context, verifier Verifier, policy map[string]bool, action, token string) error {
	if !policy[action] {
		return nil
	}
	if verifier == nil {
		return ErrUnavailable
	}
	if strings.TrimSpace(token) == "" {
		return ErrRequired
	}
	return verifier.Verify(ctx, action, token)
}

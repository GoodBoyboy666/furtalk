package spam

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// tencentTMSEndpoint 腾讯云 TMS TextModeration Endpoint。
const tencentTMSEndpoint = "tms.tencentcloudapi.com"

// TencentConfig 腾讯云内容安全检测器的配置。
type TencentConfig struct {
	// Region 必填区域，例如 ap-guangzhou。
	Region string
	// 腾讯云 API 凭据。
	SecretID  string
	SecretKey string
	// BizType 可选的策略编号。
	BizType string
}

// Tencent 调用腾讯云 TMS TextModeration 接口，提交 Base64 后的评论正文。
type Tencent struct {
	client *http.Client
	cfg    TencentConfig
}

// NewTencent 构建腾讯云内容安全检测器。
// client 为 nil 时使用携带超时的默认客户端。
func NewTencent(client *http.Client, cfg TencentConfig) *Tencent {
	if client == nil {
		client = defaultClient()
	}
	return &Tencent{client: client, cfg: cfg}
}

// Check 提交正文并按 Suggestion 判定：
// Pass 继续、Review 映射可疑、Block 映射垃圾；API 错误或建议未知为 unknown。
func (t *Tencent) Check(ctx context.Context, input Input) (Result, error) {
	payload, err := t.buildRequest(input.Body)
	if err != nil {
		return ResultPass, fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+tencentTMSEndpoint, strings.NewReader(string(payload)))
	if err != nil {
		return ResultPass, fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	t.signTC3(req, payload)
	resp, err := t.client.Do(req)
	if err != nil {
		return ResultPass, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ResultPass, fmt.Errorf("%w: read response: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return ResultPass, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, resp.StatusCode)
	}
	var parsed struct {
		Response struct {
			Suggestion *string `json:"Suggestion"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ResultPass, fmt.Errorf("%w: parse response: %v", ErrUnavailable, err)
	}
	if parsed.Response.Suggestion == nil {
		return ResultPass, fmt.Errorf("%w: missing suggestion", ErrUnavailable)
	}
	switch *parsed.Response.Suggestion {
	case "Pass":
		return ResultPass, nil
	case "Review":
		return ResultReview, nil
	case "Block":
		return ResultBlock, nil
	default:
		return ResultPass, fmt.Errorf("%w: unexpected suggestion", ErrUnavailable)
	}
}

// buildRequest 构造 TextModeration 请求体，只包含 Base64 正文；
// BizType 仅在非空时提交。
func (t *Tencent) buildRequest(body string) ([]byte, error) {
	values := map[string]string{
		"Content": base64.StdEncoding.EncodeToString([]byte(body)),
	}
	if t.cfg.BizType != "" {
		values["BizType"] = t.cfg.BizType
	}
	return json.Marshal(values)
}

// signTC3 按腾讯云 TC3-HMAC-SHA256 签名算法设置请求头与 authorization。
func (t *Tencent) signTC3(req *http.Request, body []byte) {
	host := tencentTMSEndpoint
	service := "tms"
	now := time.Now().UTC()
	timestamp := now.Unix()
	date := now.Format("2006-01-02")
	hashedPayload := sha256Hex(body)
	req.Header.Set("Host", host)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-TC-Action", "TextModeration")
	req.Header.Set("X-TC-Version", "2020-12-29")
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-TC-Region", t.cfg.Region)
	req.Header.Set("X-TC-RequestClient", "furtalk")

	canonicalHeaders := "content-type:" + req.Header.Get("Content-Type") + "\nhost:" + host + "\n"
	signedHeaders := "content-type;host"
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + hashedPayload
	credentialScope := date + "/" + service + "/tc3_request"
	stringToSign := "TC3-HMAC-SHA256\n" + strconv.FormatInt(timestamp, 10) + "\n" + credentialScope + "\n" + sha256Hex([]byte(canonicalRequest))

	secretDate := hmacSHA256([]byte("TC3"+t.cfg.SecretKey), date)
	secretService := hmacSHA256(secretDate, service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	authorization := "TC3-HMAC-SHA256 Credential=" + t.cfg.SecretID + "/" + credentialScope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	req.Header.Set("Authorization", authorization)
}

// sha256Hex 返回内容的 SHA-256 十六进制摘要。
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hmacSHA256 返回 HMAC-SHA256 摘要。
func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

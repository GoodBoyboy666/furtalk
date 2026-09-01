package spam

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AlibabaConfig 阿里云内容安全检测器的配置。
type AlibabaConfig struct {
	// Region 文档支持的区域，例如 cn-shanghai。
	Region string
	// 阿里云凭据。
	AccessKeyID     string
	AccessKeySecret string
	// BizType 是可选的业务策略编号。
	BizType string
}

// Alibaba 调用阿里云 Green TextScan 接口，只提交评论正文。
type Alibaba struct {
	client *http.Client
	cfg    AlibabaConfig
}

// NewAlibaba 构建阿里云内容安全检测器。
// client 为 nil 时使用携带超时的默认客户端。
func NewAlibaba(client *http.Client, cfg AlibabaConfig) *Alibaba {
	if client == nil {
		client = defaultClient()
	}
	return &Alibaba{client: client, cfg: cfg}
}

// Check 提交正文并按 suggestion 判定：
// pass 继续、review 映射可疑、block 映射垃圾；task/API 非成功或建议未知为 unknown。
func (a *Alibaba) Check(ctx context.Context, input Input) (Result, error) {
	payload, err := a.buildRequest(input.Body)
	if err != nil {
		return ResultPass, fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	host := "green." + a.cfg.Region + ".aliyuncs.com"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/green/text/scan", strings.NewReader(string(payload)))
	if err != nil {
		return ResultPass, fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	a.signROA(req, host, payload)
	resp, err := a.client.Do(req)
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
		Code int `json:"code"`
		Data []struct {
			Code    int `json:"code"`
			Results []struct {
				Scene      string `json:"scene"`
				Suggestion string `json:"suggestion"`
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ResultPass, fmt.Errorf("%w: parse response: %v", ErrUnavailable, err)
	}
	if parsed.Code != 200 || len(parsed.Data) == 0 || parsed.Data[0].Code != 200 {
		return ResultPass, fmt.Errorf("%w: task not successful", ErrUnavailable)
	}
	for _, result := range parsed.Data[0].Results {
		if result.Scene != "antispam" {
			continue
		}
		switch result.Suggestion {
		case "pass":
			return ResultPass, nil
		case "review":
			return ResultReview, nil
		case "block":
			return ResultBlock, nil
		default:
			return ResultPass, fmt.Errorf("%w: unexpected suggestion", ErrUnavailable)
		}
	}
	return ResultPass, fmt.Errorf("%w: missing antispam result", ErrUnavailable)
}

// buildRequest 构造 TextScan 请求体，只包含正文与固定 antispam 场景。
func (a *Alibaba) buildRequest(body string) ([]byte, error) {
	taskID, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"tasks":  []map[string]string{{"dataId": taskID, "content": body}},
		"scenes": []string{"antispam"},
	}
	if a.cfg.BizType != "" {
		payload["bizType"] = a.cfg.BizType
	}
	return json.Marshal(payload)
}

// signROA 按阿里云 ROA v1.0 签名算法设置请求头与 authorization。
func (a *Alibaba) signROA(req *http.Request, host string, body []byte) {
	date := time.Now().UTC().Format(http.TimeFormat)
	nonce, _ := randomToken(16)
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json; charset=utf-8")
	req.Header.Set("date", date)
	req.Header.Set("host", host)
	req.Header.Set("x-acs-signature-nonce", nonce)
	req.Header.Set("x-acs-signature-method", "HMAC-SHA1")
	req.Header.Set("x-acs-signature-version", "1.0")
	req.Header.Set("x-acs-version", "2018-05-09")
	req.Header.Set("x-acs-action", "TextScan")
	req.Header.Set("user-agent", "furtalk")
	stringToSign := roaStringToSign(req, host)
	signature := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(a.cfg.AccessKeySecret), []byte(stringToSign)))
	req.Header.Set("authorization", "acs "+a.cfg.AccessKeyID+":"+signature)
}

// roaStringToSign 构造 ROA 签名字符串。
func roaStringToSign(req *http.Request, host string) string {
	resource := req.URL.Path
	canonicalHeaders := canonicalACSKHeaders(req)
	return req.Method + "\n" +
		req.Header.Get("accept") + "\n" +
		"" + "\n" + // content-md5（无 body 摘要字段时为空）
		req.Header.Get("content-type") + "\n" +
		req.Header.Get("date") + "\n" +
		canonicalHeaders +
		resource
}

// canonicalACSKHeaders 拼接排序后的 x-acs-* 请求头为 key:value\n。
func canonicalACSKHeaders(req *http.Request) string {
	temp := map[string]string{}
	for key := range req.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-acs-") {
			temp[strings.ToLower(key)] = req.Header.Get(key)
		}
	}
	keys := make([]string, 0, len(temp))
	for key := range temp {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString(":")
		b.WriteString(temp[key])
		b.WriteString("\n")
	}
	return b.String()
}

// hmacSHA1 返回 HMAC-SHA1 摘要。
func hmacSHA1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// randomToken 返回 n 字节随机数的十六进制编码。
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

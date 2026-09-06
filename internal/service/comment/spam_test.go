package comment

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/logging"
)

type spamErrorTransport struct {
	err error
}

func (t spamErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}

// fakeSpamReader 返回固定的已启用垃圾检测 provider 配置。
type fakeSpamReader struct {
	providers []SpamProviderConfig
	err       error
}

func (f fakeSpamReader) EnabledSpamProviders(ctx context.Context) ([]SpamProviderConfig, error) {
	return f.providers, f.err
}

// recordingTransport 记录每次请求的 host 顺序与计数，供调用顺序与短路断言。
type recordingTransport struct {
	mu    sync.Mutex
	order []string
	count map[string]int
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	host := req.URL.Host
	r.order = append(r.order, host)
	if r.count == nil {
		r.count = map[string]int{}
	}
	r.count[host]++
	r.mu.Unlock()
	return &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(okExternalBody(req))),
	}, nil
}

// okExternalBody 按 host 返回各渠道的通过响应。
func okExternalBody(req *http.Request) string {
	switch {
	case strings.Contains(req.URL.Host, "rest.akismet.com"):
		return "false"
	case strings.Contains(req.URL.Host, "aliyuncs.com"):
		return `{"code":200,"data":[{"code":200,"results":[{"scene":"antispam","suggestion":"pass"}]}]}`
	case strings.Contains(req.URL.Host, "tencentcloudapi.com"):
		return `{"Response":{"Suggestion":"Pass"}}`
	default:
		return ""
	}
}

// blockedExternalTransport 对所有外部请求返回命中（阻塞）响应。
type blockedExternalTransport struct{}

func (blockedExternalTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body string
	switch {
	case strings.Contains(req.URL.Host, "rest.akismet.com"):
		body = "true"
	case strings.Contains(req.URL.Host, "aliyuncs.com"):
		body = `{"code":200,"data":[{"code":200,"results":[{"scene":"antispam","suggestion":"block"}]}]}`
	default:
		body = `{"Response":{"Suggestion":"Block"}}`
	}
	return &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

// writeLocalFile 写入临时词库文件。
func writeLocalFile(t *testing.T, keywords string) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "configs", "spam", "keywords.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create keyword directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(keywords), 0o644); err != nil {
		t.Fatalf("write keyword file: %v", err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	return path
}

// localConfig 构造命中指定关键词的本地渠道配置。
func localConfig(t *testing.T, keywords, action string) SpamProviderConfig {
	writeLocalFile(t, keywords)
	return SpamProviderConfig{
		ProviderKey: "spam.local",
		Enabled:     true,
		Configured:  true,
		Action:      action,
	}
}

// newGateway 构建使用给定 provider 配置与外部 transport 的 SpamGateway。
func newGateway(transport http.RoundTripper, providers ...SpamProviderConfig) *SpamGateway {
	g := NewSpamGateway(fakeSpamReader{providers: providers}, nil)
	if transport != nil {
		g.httpClient = &http.Client{Transport: transport}
	}
	return g
}

// checkSpam 执行一次检测并返回状态覆盖。
func checkSpam(g *SpamGateway, body string) *domain.CommentStatus {
	return g.Check(context.Background(), SpamInput{
		BlogURL: "https://example.com", Permalink: "https://example.com/post",
		CommentType: "comment", Body: body,
		Nickname: "nick", Email: "e@example.com",
		IP: net.ParseIP("1.2.3.4"), UserAgent: "UA",
	})
}

// TestSpamGatewayNoProviders 验证未配置任何渠道时返回 nil。
func TestSpamGatewayNoProviders(t *testing.T) {
	g := newGateway(nil)
	if got := checkSpam(g, "hello"); got != nil {
		t.Fatalf("override = %v, want nil", got)
	}
}

// TestSpamGatewayReaderError 验证 provider 读取失败按 unknown 降级返回 nil。
func TestSpamGatewayReaderError(t *testing.T) {
	g := NewSpamGateway(fakeSpamReader{err: context.DeadlineExceeded}, nil)
	if got := checkSpam(g, "hello"); got != nil {
		t.Fatalf("override = %v, want nil", got)
	}
}

// TestSpamGatewayLocalAction 验证本地命中的二元动作投影为 pending/spam。
func TestSpamGatewayLocalAction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
		want   domain.CommentStatus
	}{
		{name: "pending action", action: "pending", want: domain.CommentStatusPending},
		{name: "spam action", action: "spam", want: domain.CommentStatusSpam},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGateway(nil, localConfig(t, "广告\n", tc.action))
			got := checkSpam(g, "这里有广告")
			if got == nil || *got != tc.want {
				t.Fatalf("override = %v, want %s", got, tc.want)
			}
		})
	}
}

// TestSpamGatewayPassOrder 验证全部渠道通过时返回 nil，且外部渠道按固定顺序调用。
func TestSpamGatewayPassOrder(t *testing.T) {
	tr := &recordingTransport{}
	g := newGateway(tr,
		localConfig(t, "不存在的词\n", "spam"),
		SpamProviderConfig{ProviderKey: "spam.akismet", Enabled: true, Action: "spam", APIKey: "k"},
		SpamProviderConfig{ProviderKey: "spam.aliyun", Enabled: true, Region: "cn-shanghai", AccessKeyID: "i", AccessKeySecret: "s"},
		SpamProviderConfig{ProviderKey: "spam.tencent", Enabled: true, Region: "ap-guangzhou", SecretID: "i", SecretKey: "s"},
	)
	if got := checkSpam(g, "普通内容"); got != nil {
		t.Fatalf("override = %v, want nil", got)
	}
	want := []string{
		"k.rest.akismet.com",
		"green.cn-shanghai.aliyuncs.com",
		"tms.tencentcloudapi.com",
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.order) != len(want) {
		t.Fatalf("external call order = %v, want %v", tr.order, want)
	}
	for i, host := range want {
		if !strings.Contains(tr.order[i], host) && tr.order[i] != host {
			t.Fatalf("call %d host = %q, want containing %q", i, tr.order[i], host)
		}
	}
}

// TestSpamGatewayShortCircuit 验证首个 pending/spam 结果使后续渠道零调用。
func TestSpamGatewayShortCircuit(t *testing.T) {
	// 本地命中 pending：外部渠道不应被调用。
	tr := &recordingTransport{}
	g := newGateway(tr,
		localConfig(t, "广告\n", "pending"),
		SpamProviderConfig{ProviderKey: "spam.aliyun", Enabled: true, Region: "cn-shanghai", AccessKeyID: "i", AccessKeySecret: "s"},
		SpamProviderConfig{ProviderKey: "spam.tencent", Enabled: true, Region: "ap-guangzhou", SecretID: "i", SecretKey: "s"},
	)
	got := checkSpam(g, "有广告")
	if got == nil || *got != domain.CommentStatusPending {
		t.Fatalf("override = %v, want pending", got)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.order) != 0 {
		t.Fatalf("external calls = %v, want zero after local hit", tr.order)
	}

	// Akismet 命中 spam：云渠道不应被调用。
	tr2 := &recordingTransport{}
	g2 := newGateway(tr2,
		localConfig(t, "不存在的词\n", "pending"),
		SpamProviderConfig{ProviderKey: "spam.akismet", Enabled: true, Action: "spam", APIKey: "k"},
		SpamProviderConfig{ProviderKey: "spam.aliyun", Enabled: true, Region: "cn-shanghai", AccessKeyID: "i", AccessKeySecret: "s"},
	)
	// akismet 需要真实命中：改用 blocked transport 覆盖 Akismet 响应。
	g2.httpClient = &http.Client{Transport: blockedExternalTransport{}}
	got2 := checkSpam(g2, "hello")
	if got2 == nil || *got2 != domain.CommentStatusSpam {
		t.Fatalf("akismet override = %v, want spam", got2)
	}
}

// TestSpamGatewayCloudTernary 验证云渠道的 review/block 映射。
func TestSpamGatewayCloudTernary(t *testing.T) {
	cases := []struct {
		name string
		body string
		want domain.CommentStatus
	}{
		{name: "aliyun review", body: `{"code":200,"data":[{"code":200,"results":[{"scene":"antispam","suggestion":"review"}]}]}`, want: domain.CommentStatusPending},
		{name: "aliyun block", body: `{"code":200,"data":[{"code":200,"results":[{"scene":"antispam","suggestion":"block"}]}]}`, want: domain.CommentStatusSpam},
		{name: "tencent review", body: `{"Response":{"Suggestion":"Review"}}`, want: domain.CommentStatusPending},
		{name: "tencent block", body: `{"Response":{"Suggestion":"Block"}}`, want: domain.CommentStatusSpam},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var provider SpamProviderConfig
			var host string
			if strings.HasPrefix(tc.name, "aliyun") {
				provider = SpamProviderConfig{ProviderKey: "spam.aliyun", Enabled: true, Region: "cn-shanghai", AccessKeyID: "i", AccessKeySecret: "s"}
				host = "green.cn-shanghai.aliyuncs.com"
			} else {
				provider = SpamProviderConfig{ProviderKey: "spam.tencent", Enabled: true, Region: "ap-guangzhou", SecretID: "i", SecretKey: "s"}
				host = "tms.tencentcloudapi.com"
			}
			tr := &fixedTransport{host: host, body: tc.body}
			g := newGateway(tr, provider)
			got := checkSpam(g, "hello")
			if got == nil || *got != tc.want {
				t.Fatalf("override = %v, want %s", got, tc.want)
			}
		})
	}
}

// fixedTransport 对匹配 host 的请求返回固定 body。
type fixedTransport struct {
	host string
	body string
}

func (f *fixedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := f.body
	if !strings.Contains(req.URL.Host, f.host) {
		body = okExternalBody(req)
	}
	return &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

// TestSpamGatewayUnknownContinues 验证本地 unknown 继续执行后续渠道。
func TestSpamGatewayUnknownContinues(t *testing.T) {
	tr := &recordingTransport{}
	g := newGateway(tr,
		SpamProviderConfig{ProviderKey: "spam.local", Enabled: true, Configured: true, Action: "spam"},
		SpamProviderConfig{ProviderKey: "spam.akismet", Enabled: true, Action: "spam", APIKey: "k"},
	)
	if got := checkSpam(g, "普通内容"); got != nil {
		t.Fatalf("override = %v, want nil (all unknown)", got)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.order) != 1 {
		t.Fatalf("external calls = %v, want 1 (akismet only)", tr.order)
	}
}

// TestSpamGatewayOrderDoesNotDependOnReader 验证 reader 乱序返回时仍按固定顺序执行。
func TestSpamGatewayOrderDoesNotDependOnReader(t *testing.T) {
	writeLocalFile(t, "广告\n")
	g := NewSpamGateway(fakeSpamReader{providers: []SpamProviderConfig{
		{ProviderKey: "spam.tencent", Enabled: true, Region: "ap-guangzhou", SecretID: "i", SecretKey: "s"},
		{ProviderKey: "spam.aliyun", Enabled: true, Region: "cn-shanghai", AccessKeyID: "i", AccessKeySecret: "s"},
		{ProviderKey: "spam.local", Enabled: true, Action: "pending"},
	}}, nil)
	got := checkSpam(g, "有广告")
	if got == nil || *got != domain.CommentStatusPending {
		t.Fatalf("override = %v, want pending", got)
	}
}

// TestSpamGatewayFingerprint 验证配置指纹变化产生不同检测器、相同指纹复用。
func TestSpamGatewayFingerprint(t *testing.T) {
	g := newGateway(nil)
	cfgA := SpamProviderConfig{ProviderKey: "spam.akismet", Enabled: true, Action: "spam", APIKey: "key-a"}
	cfgB := SpamProviderConfig{ProviderKey: "spam.akismet", Enabled: true, Action: "spam", APIKey: "key-b"}
	dA, err := g.detectorFor(cfgA)
	if err != nil {
		t.Fatalf("detectorFor a: %v", err)
	}
	dB, err := g.detectorFor(cfgB)
	if err != nil {
		t.Fatalf("detectorFor b: %v", err)
	}
	dA2, _ := g.detectorFor(cfgA)
	if dA2 != dA {
		t.Fatal("same fingerprint must reuse detector")
	}
	if dA == dB {
		t.Fatal("different fingerprint must build a new detector")
	}
}

func TestSpamGatewayAkismetTransportLogHidesAPIKeyAndURL(t *testing.T) {
	apiKey := "ak-secret"
	rawURL := "https://" + apiKey + ".rest.akismet.com/1.1/comment-check"
	var logs bytes.Buffer
	g := NewSpamGateway(fakeSpamReader{providers: []SpamProviderConfig{
		{ProviderKey: "spam.akismet", Enabled: true, Action: "spam", APIKey: apiKey},
	}}, logging.New(&logs))
	g.httpClient = &http.Client{Transport: spamErrorTransport{err: fmt.Errorf("dial tcp %s: connect: refused", rawURL)}}
	if got := checkSpam(g, "hello"); got != nil {
		t.Fatalf("override = %v, want nil on provider outage", got)
	}
	if strings.Contains(logs.String(), apiKey) || strings.Contains(logs.String(), rawURL) {
		t.Fatalf("spam log leaks API key or URL: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "detector check failed") || !strings.Contains(logs.String(), "unavailable") {
		t.Fatalf("spam log missing sanitized diagnostic: %s", logs.String())
	}
}

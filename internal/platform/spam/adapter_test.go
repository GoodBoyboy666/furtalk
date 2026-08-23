package spam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fakeTransport 返回固定响应并记录请求，供外部渠道适配器测试。
type fakeTransport struct {
	status int
	body   string
	req    *http.Request
	raw    []byte
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.req = req
	if req.Body != nil {
		f.raw, _ = io.ReadAll(req.Body)
	}
	return &http.Response{
		StatusCode: f.status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(f.body)),
	}, nil
}

func clientWith(t *fakeTransport) *http.Client {
	return &http.Client{Transport: t}
}

// TestAkismetResultMapping 验证 Akismet 严格按 true/false 响应判定。
func TestAkismetResultMapping(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		status  int
		want    Result
		wantErr bool
	}{
		{name: "true spam", body: "true", status: 200, want: ResultBlock},
		{name: "false ham", body: "false", status: 200, want: ResultPass},
		{name: "unexpected body", body: "maybe", status: 200, wantErr: true},
		{name: "non ok status", body: "true", status: 500, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &fakeTransport{status: tc.status, body: tc.body}
			adapter := NewAkismet(clientWith(tr), AkismetConfig{APIKey: "key"})
			got, err := adapter.Check(context.Background(), Input{Body: "hello", IP: "1.2.3.4", BlogURL: "https://example.com"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("check = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if got != tc.want {
				t.Fatalf("result = %v, want %v", got, tc.want)
			}
			if tr.req == nil || !strings.Contains(tr.req.URL.Host, "key.rest.akismet.com") {
				t.Fatalf("request host = %v, want key.rest.akismet.com", tr.req)
			}
		})
	}
}

// TestAkismetSendsFullContext 验证送检字段包含完整评论上下文。
func TestAkismetSendsFullContext(t *testing.T) {
	tr := &fakeTransport{status: 200, body: "false"}
	adapter := NewAkismet(clientWith(tr), AkismetConfig{APIKey: "key"})
	input := Input{
		BlogURL: "https://example.com", Permalink: "https://example.com/post#c1",
		CommentType: "comment", Body: "hello", Nickname: "n", Email: "e@example.com",
		AuthorURL: "https://a.example", IP: "1.2.3.4", UserAgent: "UA",
	}
	if _, err := adapter.Check(context.Background(), input); err != nil {
		t.Fatalf("check: %v", err)
	}
	form := tr.raw
	for _, want := range []string{
		"blog=https%3A%2F%2Fexample.com", "user_ip=1.2.3.4", "user_agent=UA",
		"permalink=https%3A%2F%2Fexample.com%2Fpost%23c1", "comment_type=comment",
		"comment_author=n", "comment_author_email=e%40example.com",
		"comment_author_url=https%3A%2F%2Fa.example", "comment_content=hello",
	} {
		if !strings.Contains(string(form), want) {
			t.Fatalf("form missing %q in %s", want, form)
		}
	}
}

// TestAlibabaResultMapping 验证阿里云 suggestion 映射与故障降级。
func TestAlibabaResultMapping(t *testing.T) {
	okBody := func(suggestion string) string {
		payload, _ := json.Marshal(map[string]any{
			"code": 200,
			"data": []map[string]any{{
				"code": 200,
				"results": []map[string]string{{
					"scene": "antispam", "suggestion": suggestion,
				}},
			}},
		})
		return string(payload)
	}
	cases := []struct {
		name    string
		body    string
		status  int
		want    Result
		wantErr bool
	}{
		{name: "pass", body: okBody("pass"), status: 200, want: ResultPass},
		{name: "review", body: okBody("review"), status: 200, want: ResultReview},
		{name: "block", body: okBody("block"), status: 200, want: ResultBlock},
		{name: "unexpected suggestion", body: okBody("ban"), status: 200, wantErr: true},
		{name: "top level error", body: `{"code":500,"msg":"err"}`, status: 200, wantErr: true},
		{name: "non ok status", body: `{}`, status: 500, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &fakeTransport{status: tc.status, body: tc.body}
			adapter := NewAlibaba(clientWith(tr), AlibabaConfig{Region: "cn-shanghai", AccessKeyID: "id", AccessKeySecret: "secret"})
			got, err := adapter.Check(context.Background(), Input{Body: "hello"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("check = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if got != tc.want {
				t.Fatalf("result = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAlibabaSendsBodyOnly 验证阿里云请求体只包含正文与 antispam 场景，不含身份字段。
func TestAlibabaSendsBodyOnly(t *testing.T) {
	tr := &fakeTransport{status: 200, body: `{"code":200,"data":[{"code":200,"results":[{"scene":"antispam","suggestion":"pass"}]}]}`}
	adapter := NewAlibaba(clientWith(tr), AlibabaConfig{Region: "cn-shanghai", AccessKeyID: "id", AccessKeySecret: "secret", BizType: "biz1"})
	input := Input{Body: "hello", Nickname: "nickname-user", Email: "e@example.com", IP: "1.2.3.4", UserAgent: "UA", AuthorURL: "https://a.example"}
	if _, err := adapter.Check(context.Background(), input); err != nil {
		t.Fatalf("check: %v", err)
	}
	if tr.req == nil || tr.req.Header.Get("authorization") == "" {
		t.Fatalf("request not signed: %+v", tr.req)
	}
	var payload map[string]any
	if err := json.Unmarshal(tr.raw, &payload); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	rawBody, _ := json.Marshal(payload)
	for _, leaked := range []string{"nickname-user", "e@example.com", "1.2.3.4", "UA", "a.example"} {
		if strings.Contains(string(rawBody), leaked) {
			t.Fatalf("body leaks %q: %s", leaked, rawBody)
		}
	}
	scenes, _ := json.Marshal(payload["scenes"])
	if !strings.Contains(string(scenes), "antispam") {
		t.Fatalf("scenes = %s, want antispam", scenes)
	}
	if payload["bizType"] != "biz1" {
		t.Fatalf("bizType = %v, want biz1", payload["bizType"])
	}
}

// TestTencentResultMapping 验证腾讯云 Suggestion 映射与故障降级。
func TestTencentResultMapping(t *testing.T) {
	okBody := func(suggestion string) string {
		payload, _ := json.Marshal(map[string]any{
			"Response": map[string]any{"Suggestion": suggestion},
		})
		return string(payload)
	}
	cases := []struct {
		name    string
		body    string
		status  int
		want    Result
		wantErr bool
	}{
		{name: "pass", body: okBody("Pass"), status: 200, want: ResultPass},
		{name: "review", body: okBody("Review"), status: 200, want: ResultReview},
		{name: "block", body: okBody("Block"), status: 200, want: ResultBlock},
		{name: "unexpected suggestion", body: okBody("Ban"), status: 200, wantErr: true},
		{name: "missing suggestion", body: `{"Response":{}}`, status: 200, wantErr: true},
		{name: "non ok status", body: `{}`, status: 500, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &fakeTransport{status: tc.status, body: tc.body}
			adapter := NewTencent(clientWith(tr), TencentConfig{Region: "ap-guangzhou", SecretID: "id", SecretKey: "key"})
			got, err := adapter.Check(context.Background(), Input{Body: "hello"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("check = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if got != tc.want {
				t.Fatalf("result = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTencentSendsBase64BodyOnly 验证腾讯云请求体只含 Base64 正文与可选 BizType，
// 且签名头存在。
func TestTencentSendsBase64BodyOnly(t *testing.T) {
	tr := &fakeTransport{status: 200, body: `{"Response":{"Suggestion":"Pass"}}`}
	adapter := NewTencent(clientWith(tr), TencentConfig{Region: "ap-guangzhou", SecretID: "id", SecretKey: "key"})
	input := Input{Body: "hello", Nickname: "nickname-user", Email: "e@example.com", IP: "1.2.3.4", UserAgent: "UA"}
	if _, err := adapter.Check(context.Background(), input); err != nil {
		t.Fatalf("check: %v", err)
	}
	if tr.req == nil || tr.req.Header.Get("Authorization") == "" {
		t.Fatalf("request not signed: %+v", tr.req)
	}
	var payload map[string]any
	if err := json.Unmarshal(tr.raw, &payload); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if payload["Content"] != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Fatalf("content = %v, want base64(hello)", payload["Content"])
	}
	rawBody, _ := json.Marshal(payload)
	for _, leaked := range []string{"nickname-user", "e@example.com", "1.2.3.4", "UA", "hello"} {
		if strings.Contains(string(rawBody), leaked) {
			t.Fatalf("body leaks plaintext %q: %s", leaked, rawBody)
		}
	}
}

// TestExternalErrorsHideSecrets 验证外部渠道错误不包含凭据或正文。
func TestExternalErrorsHideSecrets(t *testing.T) {
	tr := &fakeTransport{status: 500, body: "boom"}
	adapters := []Detector{
		NewAkismet(clientWith(tr), AkismetConfig{APIKey: "ak-secret"}),
		NewAlibaba(clientWith(tr), AlibabaConfig{Region: "cn-shanghai", AccessKeyID: "ak-id", AccessKeySecret: "ak-secret"}),
		NewTencent(clientWith(tr), TencentConfig{Region: "ap-guangzhou", SecretID: "sk-id", SecretKey: "sk-secret"}),
	}
	input := Input{Body: "secret-body-content", Email: "e@example.com", IP: "1.2.3.4", UserAgent: "UA"}
	for _, adapter := range adapters {
		_, err := adapter.Check(context.Background(), input)
		if err == nil {
			t.Fatalf("expected error from %T", adapter)
		}
		for _, secret := range []string{"ak-secret", "ak-id", "sk-secret", "sk-id", "secret-body-content", "e@example.com", "1.2.3.4"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("%T error leaks %q: %v", adapter, secret, err)
			}
		}
	}
}

package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// roundTripRecorder 捕获请求的方法、路径与 body。
type roundTripRecorder struct {
	method string
	path   string
	ctype  string
	body   string
}

// testServer 记录一次请求并按 success 返回固定响应。
func testServer(t *testing.T, success bool) (*httptest.Server, *roundTripRecorder) {
	t.Helper()
	rec := &roundTripRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.ctype = r.Header.Get("Content-Type")
		raw := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(raw)
		rec.body = string(raw)
		w.Header().Set("Content-Type", "application/json")
		if success {
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	t.Cleanup(server.Close)
	return server, rec
}

// TestCAPUsesJSONProtocolAndDerivedURL 验证 CAP 向派生 siteverify URL 发送 JSON。
func TestCAPUsesJSONProtocolAndDerivedURL(t *testing.T) {
	server, rec := testServer(t, true)
	v, err := New(Config{
		Provider:  "cap",
		SiteKey:   "cap-site",
		SecretKey: "cap-secret",
		Endpoint:  strings.TrimSuffix(server.URL, "/") + "/standalone/",
		Timeout:   5 * time.Second,
	}, server.Client())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := v.Verify(context.Background(), "password_login", "tok123"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rec.path != "/standalone/cap-site/siteverify" {
		t.Fatalf("path = %q, want /standalone/cap-site/siteverify", rec.path)
	}
	if rec.ctype != "application/json" {
		t.Fatalf("content-type = %q, want application/json", rec.ctype)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(rec.body), &payload); err != nil {
		t.Fatalf("body %q is not valid json: %v", rec.body, err)
	}
	if payload["secret"] != "cap-secret" || payload["response"] != "tok123" {
		t.Fatalf("payload = %v, want secret+response", payload)
	}
}

// TestTurnstileKeepsFormURLEncoded 验证非 CAP 提供方沿用 form-urlencoded 协议与固定端点。
func TestTurnstileKeepsFormURLEncoded(t *testing.T) {
	server, rec := testServer(t, true)
	v, err := New(Config{
		Provider:  "turnstile",
		SiteKey:   "ts-site",
		SecretKey: "ts-secret",
		Endpoint:  server.URL + "/siteverify",
		Timeout:   5 * time.Second,
	}, server.Client())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := v.Verify(context.Background(), "comment", "tok456"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rec.path != "/siteverify" {
		t.Fatalf("path = %q, want /siteverify", rec.path)
	}
	if rec.ctype != "application/x-www-form-urlencoded" {
		t.Fatalf("content-type = %q, want form-urlencoded", rec.ctype)
	}
	if !strings.Contains(rec.body, "secret=ts-secret") || !strings.Contains(rec.body, "response=tok456") {
		t.Fatalf("body = %q, want secret+response form fields", rec.body)
	}
}

// TestCAPRejectedToken 验证 CAP 被提供方拒绝时返回 ErrFailed。
func TestCAPRejectedToken(t *testing.T) {
	server, _ := testServer(t, false)
	v, err := New(Config{
		Provider:  "cap",
		SiteKey:   "cap-site",
		SecretKey: "cap-secret",
		Endpoint:  server.URL,
		Timeout:   5 * time.Second,
	}, server.Client())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := v.Verify(context.Background(), "password_login", "bad-token"); !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("verify error = %v, want ErrFailed", err)
	}
}

// TestCAPMissingEndpoint 验证 CAP 缺少 endpoint 时无法构建适配器。
func TestCAPMissingEndpoint(t *testing.T) {
	if _, err := New(Config{Provider: "cap", SiteKey: "s", SecretKey: "k"}, nil); err == nil {
		t.Fatal("New error = nil, want rejection for missing cap endpoint")
	}
}

func TestCAPRejectsAmbiguousEndpointComponents(t *testing.T) {
	for _, raw := range []string{
		"https://cap.example.com?tenant=one",
		"https://cap.example.com#siteverify",
		"https://user:pass@cap.example.com",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := New(Config{Provider: "cap", SiteKey: "s", SecretKey: "k", Endpoint: raw}, nil); err == nil {
				t.Fatalf("New accepted ambiguous endpoint %q", raw)
			}
		})
	}
}

func TestCustomCaptchaEndpointRejectsAmbiguousComponents(t *testing.T) {
	for _, raw := range []string{
		"https://proxy.example.com/siteverify?tenant=one",
		"https://proxy.example.com/siteverify#fragment",
		"https://user:pass@proxy.example.com/siteverify",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := New(Config{Provider: "turnstile", SiteKey: "s", SecretKey: "k", Endpoint: raw}, nil); err == nil {
				t.Fatalf("New accepted ambiguous custom endpoint %q", raw)
			}
		})
	}
}

// TestCAPMalformedResponse 验证 CAP 返回畸形响应时映射为不可用。
func TestCAPMalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	}))
	t.Cleanup(server.Close)
	v, err := New(Config{
		Provider:  "cap",
		SiteKey:   "s",
		SecretKey: "k",
		Endpoint:  server.URL,
		Timeout:   time.Second,
	}, server.Client())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := v.Verify(context.Background(), "password_login", "tok"); !strings.Contains(err.Error(), "provider unavailable") {
		t.Fatalf("verify error = %v, want ErrUnavailable", err)
	}
}

// TestWidgetAPIURL 验证 CAP 派生官方 widget 端点，非 CAP 返回空。
func TestWidgetAPIURL(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "cap plain", cfg: Config{Provider: "cap", SiteKey: "sk", Endpoint: "https://cap.example.com"}, want: "https://cap.example.com/sk/"},
		{name: "cap with path and slash", cfg: Config{Provider: "cap", SiteKey: "sk", Endpoint: "https://cap.example.com/standalone/"}, want: "https://cap.example.com/standalone/sk/"},
		{name: "cap missing endpoint", cfg: Config{Provider: "cap", SiteKey: "sk"}, want: ""},
		{name: "turnstile", cfg: Config{Provider: "turnstile", SiteKey: "sk", Endpoint: "https://x.example.com"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WidgetAPIURL(tc.cfg); got != tc.want {
				t.Fatalf("WidgetAPIURL = %q, want %q", got, tc.want)
			}
		})
	}
}

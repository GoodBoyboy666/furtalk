package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"furtalk/internal/platform/httpx"

	"github.com/gin-gonic/gin"
)

// TestOAuthCallbackBridgeFormPost 验证 Apple form_post 桥：从表单读取 state/code，
// 创建 handoff，303 重定向到带 ?handoff= 的同一页面，且 no-store。
func TestOAuthCallbackBridgeFormPost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var gotProvider, gotState, gotCode, gotErr string
	engine := gin.New()
	RegisterOAuthCallbackBridgeWithAdmission(engine, func(_ context.Context, provider, state, code, errMsg string) (string, error) {
		gotProvider, gotState, gotCode, gotErr = provider, state, code, errMsg
		return "handoff-token", nil
	}, nil)

	form := url.Values{"state": {"state-1"}, "code": {"code-1"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/callback/apple", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/oauth/callback/apple?handoff=handoff-token" {
		t.Fatalf("Location = %q", loc)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if gotProvider != "apple" || gotState != "state-1" || gotCode != "code-1" || gotErr != "" {
		t.Fatalf("handoff args = %q/%q/%q/%q", gotProvider, gotState, gotCode, gotErr)
	}
}

// TestOAuthCallbackBridgeRejectsInvalid 验证缺失/超大字段被拒绝且不创建 handoff。
func TestOAuthCallbackBridgeRejectsInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	calls := 0
	engine := gin.New()
	RegisterOAuthCallbackBridgeWithAdmission(engine, func(context.Context, string, string, string, string) (string, error) {
		calls++
		return "handoff-token", nil
	}, nil)

	tests := []struct {
		name string
		form url.Values
	}{
		{name: "missing state", form: url.Values{"code": {"code-1"}}},
		{name: "oversized state", form: url.Values{"state": {strings.Repeat("s", oauthBridgeStateLimit+1)}, "code": {"code-1"}}},
		{name: "oversized code", form: url.Values{"state": {"state-1"}, "code": {strings.Repeat("c", oauthBridgeCodeLimit+1)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/oauth/callback/apple", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			engine.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("handoff created %d times, want 0", calls)
	}
}

func TestOAuthCallbackBridgeRejectsNonAppleProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)
	calls := 0
	engine := gin.New()
	RegisterOAuthCallbackBridgeWithAdmission(engine, func(context.Context, string, string, string, string) (string, error) {
		calls++
		return "handoff-token", nil
	}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/callback/github", strings.NewReader("state=s&code=c"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if calls != 0 {
		t.Fatalf("handoff calls = %d, want 0", calls)
	}
}

func TestOAuthCallbackBridgeAdmissionDeniesBeforeHandoff(t *testing.T) {
	gin.SetMode(gin.TestMode)
	admission := &recordingAdmission{}
	calls := 0
	engine := gin.New()
	engine.Use(httpx.ClientIP(nil))
	RegisterOAuthCallbackBridgeWithAdmission(engine, func(context.Context, string, string, string, string) (string, error) {
		calls++
		return "handoff-token", nil
	}, admission)

	req := httptest.NewRequest(http.MethodPost, "/oauth/callback/apple", strings.NewReader("state=s&code=c"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.9:1234"
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if calls != 0 {
		t.Fatalf("handoff calls = %d, want 0", calls)
	}
	if admission.policy != PolicyOAuthHandoff || admission.subject != "192.0.2.9" {
		t.Fatalf("admission = %q/%q", admission.policy, admission.subject)
	}
}

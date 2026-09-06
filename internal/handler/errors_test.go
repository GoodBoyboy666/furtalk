package handler

import (
	"fmt"
	"net/http"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/notification"
)

func TestComposedErrorTranslatorCompatibility(t *testing.T) {
	t.Parallel()
	translator, err := NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		err     error
		status  int
		code    string
		message string
	}{
		{name: "protocol", err: httpx.ErrMalformedBody, status: http.StatusBadRequest, code: "invalid_request_body", message: "请求体格式错误"},
		{name: "identity", err: domain.ErrInvalidCredentials, status: http.StatusUnauthorized, code: "invalid_credentials", message: "账号或密码错误"},
		{name: "rate limited", err: domain.ErrRateLimited, status: http.StatusTooManyRequests, code: "rate_limited", message: "请求过于频繁"},
		{name: "disabled", err: domain.ErrDisabled, status: http.StatusForbidden, code: "forbidden", message: "账号已被禁用"},
		{name: "comment wrapped", err: fmt.Errorf("create: %w", domain.ErrParentNotFound), status: http.StatusNotFound, code: "not_found", message: "父评论不存在"},
		{name: "site", err: domain.ErrConfirmationRequired, status: http.StatusUnprocessableEntity, code: "invalid_input", message: "破坏性操作需要显式确认"},
		{name: "bootstrap", err: domain.ErrAlreadyInitialized, status: http.StatusGone, code: "bootstrap_unavailable", message: "初始化已不可用"},
		{name: "notification", err: notification.ErrInvalidToken, status: http.StatusBadRequest, code: "invalid_unsubscribe_token", message: "退订令牌无效"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mapping, ok := translator.Translate(tt.err)
			if !ok {
				t.Fatalf("Translate(%v) did not match", tt.err)
			}
			if mapping.Status != tt.status || mapping.Code != tt.code || mapping.Message != tt.message {
				t.Fatalf("mapping = %#v, want status=%d code=%q message=%q", mapping, tt.status, tt.code, tt.message)
			}
		})
	}
}

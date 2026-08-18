package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

// authPolicyReader 返回公开注册开启与认证模式的实例策略。
type authPolicyReader struct{}

func (authPolicyReader) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}

func (authPolicyReader) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, nil, "https://www.gravatar.com/avatar", nil
}

// authPrincipalStore 把任意用户 id 解析为活跃的普通用户主体。
type authPrincipalStore struct{}

func (authPrincipalStore) Resolve(context.Context, int64) (domain.Principal, error) {
	return domain.Principal{UserID: 1, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 1}, nil
}

// newAuthCaptchaRouter 装配带真实 JWT/principal 解析与翻译器的认证路由。
func newAuthCaptchaRouter(t *testing.T, policy map[string]bool, verifier identity.CaptchaVerifier) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	svc := identity.NewService(identity.Dependencies{
		Cache:         emailCodeCacheStore{},
		Policy:        authPolicyReader{},
		CaptchaPolicy: emailCodePolicy{policy},
		Captcha:       verifier,
		Mailer:        emailCodeMailer{},
	})
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: time.Hour,
	})
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	router.Use(middleware.JWTVerification(signer))
	router.Use(middleware.PrincipalResolution(authPrincipalStore{}))
	RegisterAuth(router.Group("/api/v1"), svc)
	return router
}

// postJSON 向 path 发起携带 body 与可选登录 cookie 的 POST 请求。
func postJSON(router *gin.Engine, path, body string, login *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if login != nil {
		request.AddCookie(login)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestEmailCodeLoginCaptchaHTTPMatrix(t *testing.T) {
	tests := []struct {
		name     string
		policy   map[string]bool
		verifier identity.CaptchaVerifier
		body     string
		wantCode int
	}{
		{
			name:     "policy off stays compatible with 401",
			policy:   map[string]bool{},
			verifier: &emailCodeVerifier{},
			body:     `{"email":"user@example.com","code":"123456"}`,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "missing token maps to 422",
			policy:   map[string]bool{identity.EmailCodeLoginAction: true},
			verifier: &emailCodeVerifier{},
			body:     `{"email":"user@example.com","code":"123456"}`,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "verifier failure maps to 403 and token passes through",
			policy:   map[string]bool{identity.EmailCodeLoginAction: true},
			verifier: &emailCodeVerifier{err: domain.ErrCaptchaFailed},
			body:     `{"email":"user@example.com","code":"123456","captcha_token":"abc"}`,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "provider unavailable maps to 503",
			policy:   map[string]bool{identity.EmailCodeLoginAction: true},
			verifier: &emailCodeVerifier{err: domain.ErrCaptchaUnavailable},
			body:     `{"email":"user@example.com","code":"123456","captcha_token":"abc"}`,
			wantCode: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := tt.verifier
			router := newAuthCaptchaRouter(t, tt.policy, verifier)
			rec := postJSON(router, "/api/v1/auth/email-code/login", tt.body, nil)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantCode == http.StatusForbidden {
				if v, ok := verifier.(*emailCodeVerifier); !ok || v.token != "abc" {
					t.Fatalf("verifier token = %+v, want abc passed through", v)
				}
			}
		})
	}
}

func TestPasswordLoginCaptchaHTTPMatrix(t *testing.T) {
	tests := []struct {
		name     string
		policy   map[string]bool
		verifier identity.CaptchaVerifier
		body     string
		wantCode int
	}{
		{
			name:     "missing token maps to 422",
			policy:   map[string]bool{identity.PasswordLoginAction: true},
			verifier: &emailCodeVerifier{},
			body:     `{"email":"user@example.com","password":"correct-horse-1"}`,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "verifier failure maps to 403 and token passes through",
			policy:   map[string]bool{identity.PasswordLoginAction: true},
			verifier: &emailCodeVerifier{err: domain.ErrCaptchaFailed},
			body:     `{"email":"user@example.com","password":"correct-horse-1","captcha_token":"abc"}`,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "provider unavailable maps to 503",
			policy:   map[string]bool{identity.PasswordLoginAction: true},
			verifier: &emailCodeVerifier{err: domain.ErrCaptchaUnavailable},
			body:     `{"email":"user@example.com","password":"correct-horse-1","captcha_token":"abc"}`,
			wantCode: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := tt.verifier
			router := newAuthCaptchaRouter(t, tt.policy, verifier)
			rec := postJSON(router, "/api/v1/auth/password/login", tt.body, nil)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantCode == http.StatusForbidden {
				if v, ok := verifier.(*emailCodeVerifier); !ok || v.token != "abc" {
					t.Fatalf("verifier token = %+v, want abc passed through", v)
				}
			}
		})
	}
}

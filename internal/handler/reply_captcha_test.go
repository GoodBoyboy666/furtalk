package handler

import (
	"context"
	"net/http"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/captcha"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

// replyCaptchaSettings 返回开启 comment action 的评论策略。
type replyCaptchaSettings struct {
	policy map[string]bool
}

func (r replyCaptchaSettings) CommentPolicy(context.Context) (domain.CommentPolicy, error) {
	return domain.CommentPolicy{
		Mode:          domain.CommentModeAuthenticated,
		Moderation:    domain.ModerationDirect,
		MaxReplyDepth: 5,
		CaptchaPolicy: r.policy,
		Privacy:       domain.PrivacyPolicy{IPMode: "none", UAMode: "none"},
		CommentSort:   string(domain.CommentSortAsc),
	}, nil
}

// replyCaptchaVerifier 返回固定的 platform CAPTCHA 错误并记录 token。
type replyCaptchaVerifier struct {
	err   error
	token string
}

func (v *replyCaptchaVerifier) Verify(ctx context.Context, action, token string) error {
	v.token = token
	return v.err
}

// newReplyCaptchaRouter 装配带真实 JWT/principal 解析与翻译器的第一方评论路由。
func newReplyCaptchaRouter(t *testing.T, policy map[string]bool, verifier comment.CaptchaVerifier) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	svc := comment.NewService(comment.Dependencies{
		Settings: replyCaptchaSettings{policy},
		Captcha:  verifier,
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
	RegisterFirstParty(router.Group("/api/v1"), svc, testUserGate{})
	return router
}

func TestFirstPartyReplyCaptchaHTTPMatrix(t *testing.T) {
	tests := []struct {
		name     string
		policy   map[string]bool
		verifier comment.CaptchaVerifier
		body     string
		wantCode int
	}{
		{
			name:     "missing token maps to 422",
			policy:   map[string]bool{comment.CommentAction: true},
			verifier: &replyCaptchaVerifier{},
			body:     `{"body":"a reply"}`,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "verifier failure maps to 403 and token passes through",
			policy:   map[string]bool{comment.CommentAction: true},
			verifier: &replyCaptchaVerifier{err: captcha.ErrFailed},
			body:     `{"body":"a reply","captcha_token":"abc"}`,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "provider unavailable maps to 503",
			policy:   map[string]bool{comment.CommentAction: true},
			verifier: &replyCaptchaVerifier{err: captcha.ErrUnavailable},
			body:     `{"body":"a reply","captcha_token":"abc"}`,
			wantCode: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := tt.verifier
			router := newReplyCaptchaRouter(t, tt.policy, verifier)
			login := firstPartyCookie(t)
			rec := postJSON(router, "/api/v1/comments/1/replies", tt.body, login)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantCode == http.StatusForbidden {
				if v, ok := verifier.(*replyCaptchaVerifier); !ok || v.token != "abc" {
					t.Fatalf("verifier token = %+v, want abc passed through", v)
				}
			}
		})
	}
}

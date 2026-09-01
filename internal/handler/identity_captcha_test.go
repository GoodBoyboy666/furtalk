package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

// emailCodeCacheStore 是邮箱验证码端点的缓存替身。
type emailCodeCacheStore struct{}

func (emailCodeCacheStore) Get(ctx context.Context, key string, out any) error {
	return cache.ErrNotFound
}
func (emailCodeCacheStore) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return nil
}
func (emailCodeCacheStore) Delete(ctx context.Context, key string) error { return nil }
func (emailCodeCacheStore) AtomicConsume(ctx context.Context, key string) (string, error) {
	return "", cache.ErrNotFound
}
func (emailCodeCacheStore) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	return nil
}

// emailCodeMailer 是邮箱验证码端点的邮件替身。
type emailCodeMailer struct{}

func (emailCodeMailer) Send(ctx context.Context, msg mailer.Message) error { return nil }

// emailCodeRenderer 是邮箱验证码端点的模板渲染替身。
type emailCodeRenderer struct{}

func (emailCodeRenderer) LoginCode(mailer.LoginCodeData) (string, error) { return "<p>code</p>", nil }

func (emailCodeRenderer) PasswordResetCode(mailer.PasswordResetCodeData) (string, error) {
	return "<p>code</p>", nil
}

func (emailCodeRenderer) Moderation(mailer.ModerationData) (string, error) { return "", nil }
func (emailCodeRenderer) Published(mailer.PublishedData) (string, error)   { return "", nil }
func (emailCodeRenderer) Reply(mailer.ReplyData) (string, error)           { return "", nil }

// emailCodePolicy 返回固定的 CAPTCHA action 策略。
type emailCodePolicy struct {
	policy map[string]bool
}

func (p emailCodePolicy) CaptchaPolicy(ctx context.Context) (map[string]bool, error) {
	return p.policy, nil
}

// emailCodeVerifier 记录收到的 token 并返回固定错误。
type emailCodeVerifier struct {
	err   error
	token string
}

func (v *emailCodeVerifier) Verify(ctx context.Context, action, token string) error {
	v.token = token
	return v.err
}

// emailCodeRouter 装配含翻译器的邮箱验证码路由。
func emailCodeRouter(t *testing.T, svc *identity.Service) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	translator, err := NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	RegisterAuthWithAdmission(router.Group("/api/v1"), svc, nil)
	return router
}

func newEmailCodeService(t *testing.T, policy map[string]bool, verifier identity.CaptchaVerifier) *identity.Service {
	t.Helper()
	return newEmailCodeServiceWithPolicy(t, authPolicyReader{}, policy, verifier)
}

// domainGatePolicy 返回公开注册开启与认证模式，以及可配置的邮箱域名名单。
type domainGatePolicy struct {
	blacklist []string
}

func (p domainGatePolicy) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}

func (p domainGatePolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, p.blacklist, "https://www.gravatar.com/avatar", nil
}

// newEmailCodeServiceWithPolicy 使用指定 PolicyReader 与 CAPTCHA 策略构建服务。
func newEmailCodeServiceWithPolicy(t *testing.T, policy identity.PolicyReader, captchaPolicy map[string]bool, verifier identity.CaptchaVerifier) *identity.Service {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "handler-email-code-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return identity.NewService(identity.Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         repository.NewUserRepo(db),
		Cache:         emailCodeCacheStore{},
		Policy:        policy,
		CaptchaPolicy: emailCodePolicy{captchaPolicy},
		Captcha:       verifier,
		Mailer:        emailCodeMailer{},
		Templates:     emailCodeRenderer{},
	})
}

// TestEmailCodesRejectsDisallowedDomain 证明未知邮箱域名被名单拒绝时返回
// 422 email_domain_not_allowed 与清晰提示，不泄露邮箱是否存在。
func TestEmailCodesRejectsDisallowedDomain(t *testing.T) {
	svc := newEmailCodeServiceWithPolicy(t, domainGatePolicy{blacklist: []string{"blocked.com"}}, map[string]bool{}, &emailCodeVerifier{})
	router := emailCodeRouter(t, svc)

	body := `{"email":"user@blocked.com"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email-codes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "email_domain_not_allowed") {
		t.Fatalf("body = %s, want email_domain_not_allowed code", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "该邮箱域名不允许注册") {
		t.Fatalf("body = %s, want actionable message", rec.Body.String())
	}
}

// TestEmailCodesAcceptsCaptchaToken 证明 captcha_token 可从 JSON 请求传入，
// 校验成功后返回 204 且 token 被透传给验证器。
func TestEmailCodesAcceptsCaptchaToken(t *testing.T) {
	verifier := &emailCodeVerifier{}
	svc := newEmailCodeService(t, map[string]bool{identity.EmailCodeAction: true}, verifier)
	router := emailCodeRouter(t, svc)

	body := `{"email":"user@example.com","captcha_token":"abc123"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email-codes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if verifier.token != "abc123" {
		t.Fatalf("verifier token = %q, want %q", verifier.token, "abc123")
	}
}

// TestEmailCodesRequiresCaptchaToken 证明策略开启且缺 token 时沿用现有 translator
// 返回 422 invalid_input，不泄露邮箱是否存在。
func TestEmailCodesRequiresCaptchaToken(t *testing.T) {
	svc := newEmailCodeService(t, map[string]bool{identity.EmailCodeAction: true}, &emailCodeVerifier{})
	router := emailCodeRouter(t, svc)

	body := `{"email":"user@example.com"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email-codes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_input") {
		t.Fatalf("body = %s, want invalid_input code", rec.Body.String())
	}
}

// TestEmailCodesCaptchaFailed 证明 token 校验失败映射为 403 forbidden。
func TestEmailCodesCaptchaFailed(t *testing.T) {
	svc := newEmailCodeService(t, map[string]bool{identity.EmailCodeAction: true}, &emailCodeVerifier{err: domain.ErrCaptchaFailed})
	router := emailCodeRouter(t, svc)

	body := `{"email":"user@example.com","captcha_token":"bad"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email-codes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestEmailCodesCaptchaUnavailable 证明 provider 不可用映射为 503 service_unavailable。
func TestEmailCodesCaptchaUnavailable(t *testing.T) {
	svc := newEmailCodeService(t, map[string]bool{identity.EmailCodeAction: true}, &emailCodeVerifier{err: domain.ErrCaptchaUnavailable})
	router := emailCodeRouter(t, svc)

	body := `{"email":"user@example.com","captcha_token":"token"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email-codes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

// TestEmailCodesSkipsCaptchaWhenPolicyDisabled 证明策略关闭时旧客户端行为不变，返回 204。
func TestEmailCodesSkipsCaptchaWhenPolicyDisabled(t *testing.T) {
	verifier := &emailCodeVerifier{}
	svc := newEmailCodeService(t, map[string]bool{}, verifier)
	router := emailCodeRouter(t, svc)

	body := `{"email":"user@example.com"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email-codes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if verifier.token != "" {
		t.Fatalf("verifier token = %q, want empty when policy disabled", verifier.token)
	}
}

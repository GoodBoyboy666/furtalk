package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"furtalk/internal/middleware"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

// newCommentAuthzRouter 构建挂载 /api/v1/comment-authorizations 的测试引擎：
// 真实 JWT 验证 + principal 解析通过 RequireUser，随后执行传入的 csrf 中间件。
func newCommentAuthzRouter(t *testing.T, csrf ...gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	service, _, _, principals, userGate, _ := buildWidgetTestService(t)
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: time.Hour,
	})
	router := gin.New()
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router.Use(httpx.ErrorWriter(translator))
	router.Use(middleware.JWTVerification(signer))
	router.Use(middleware.PrincipalResolution(principals))
	RegisterFirstPartyCommentAuthorization(
		router.Group("/api/v1"),
		service, userGate,
		csrf...,
	)
	return router
}

// firstPartyCookie 签发合法的 FP 登录 cookie，使 RequireUser 通过。
func firstPartyCookie(t *testing.T) *http.Cookie {
	t.Helper()
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: time.Hour,
	})
	token, err := signer.SignFirstParty(1, 1)
	if err != nil {
		t.Fatalf("sign first-party token: %v", err)
	}
	return &http.Cookie{Name: middleware.FirstPartyCookieName, Value: token}
}

// postAuthorization 向 /api/v1/comment-authorizations 发起 POST 并返回 recorder。
func postAuthorization(router *gin.Engine, login *http.Cookie, csrfCookie, csrfHeader string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/comment-authorizations", strings.NewReader(``))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(login)
	if csrfCookie != "" {
		request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfCookie})
	}
	if csrfHeader != "" {
		request.Header.Set(middleware.CSRFHeaderName, csrfHeader)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

// TestCommentAuthorizationsAppliesCSRF 验证 /api/v1/comment-authorizations 挂载
// CSRF 保护后：无 token 被拒，有效 token 通过并进入 handler（空 body → 400）。
func TestCommentAuthorizationsAppliesCSRF(t *testing.T) {
	router := newCommentAuthzRouter(t, middleware.CSRFProtection())
	login := firstPartyCookie(t)
	token := strings.Repeat("a", 43)

	denied := postAuthorization(router, login, "", "")
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), `"code":"invalid_csrf_token"`) {
		t.Fatalf("POST without CSRF = %d %s, want 403 invalid_csrf_token", denied.Code, denied.Body.String())
	}

	passed := postAuthorization(router, login, token, token)
	if passed.Code != http.StatusBadRequest {
		t.Fatalf("POST with valid CSRF = %d %s, want 400 from empty body (CSRF passed)", passed.Code, passed.Body.String())
	}
}

// TestCommentAuthorizationsWithoutCSRFMiddleware 对照验证：未传入 csrf 时
// 无 token 的 POST 不被 CSRF 拦截，证明 csrf 参数确实挂载到了该端点。
func TestCommentAuthorizationsWithoutCSRFMiddleware(t *testing.T) {
	router := newCommentAuthzRouter(t)
	login := firstPartyCookie(t)

	recorder := postAuthorization(router, login, "", "")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("POST without CSRF middleware = %d %s, want 400 from empty body (no CSRF gate)", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"code":"invalid_csrf_token"`) {
		t.Fatalf("POST unexpectedly CSRF-rejected: %s", recorder.Body.String())
	}
}

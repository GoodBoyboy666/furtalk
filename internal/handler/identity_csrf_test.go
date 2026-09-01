package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

func TestAuthRoutesApplyCSRFOnlyToSessionWrites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterAuthWithAdmission(router.Group("/api/v1"), &identity.Service{}, nil, middleware.CSRFProtection())

	for _, path := range []string{
		"/api/v1/auth/logout",
	} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"code":"invalid_csrf_token"`) {
			t.Fatalf("POST %s = %d %s, want CSRF denial", path, recorder.Code, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", strings.NewReader(`{`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code == http.StatusForbidden && strings.Contains(recorder.Body.String(), `"code":"invalid_csrf_token"`) {
		t.Fatalf("public login was incorrectly CSRF-protected: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestLogoutClearsSessionAndCSRFCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterAuthWithAdmission(router.Group("/api/v1"), &identity.Service{}, nil, middleware.CSRFProtection())
	token := strings.Repeat("a", 43)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: token})
	request.Header.Set(middleware.CSRFHeaderName, token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d; body=%s", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("logout cookie count = %d, want 2", len(cookies))
	}
	cleared := map[string]bool{}
	for _, cookie := range cookies {
		if cookie.MaxAge != -1 || cookie.Value != "" {
			t.Errorf("logout cookie was not expired: %+v", cookie)
		}
		cleared[cookie.Name] = true
	}
	if !cleared[middleware.FirstPartyCookieName] || !cleared[middleware.CSRFCookieName] {
		t.Fatalf("logout cleared cookies = %v", cleared)
	}
}

// TestLegacyPasswordRegisterRemoved 验证遗留密码注册端点不再注册（返回 404），
// 而 /me/password 保持注册且仍受 CSRF 保护。
func TestLegacyPasswordRegisterRemoved(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	userGate := stubUserGate{}
	RegisterAuthWithAdmission(router.Group("/api/v1"), &identity.Service{}, nil, middleware.CSRFProtection())
	RegisterMeWithAdmission(router.Group("/api/v1"), &identity.Service{}, userGate, nil, middleware.CSRFProtection())

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/register", strings.NewReader(`{"password":"x"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /api/v1/auth/password/register = %d, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/me/password", strings.NewReader(`{"new_password":"correct-horse-1"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/me/password without principal = %d %s, want 401 (route still registered)", rec.Code, rec.Body.String())
	}
}

// stubUserGate 接受任意已解析主体。
type stubUserGate struct{}

func (stubUserGate) RequireUser(context.Context, domain.Principal) error { return nil }

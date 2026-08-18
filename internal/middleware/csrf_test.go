package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestCSRFProtection(t *testing.T) {
	validToken := strings.Repeat("a", csrfTokenLength)
	otherToken := strings.Repeat("b", csrfTokenLength)

	for _, test := range []struct {
		name       string
		method     string
		cookie     string
		header     string
		wantStatus int
		wantCalls  int
	}{
		{name: "GET is safe", method: http.MethodGet, wantStatus: http.StatusNoContent, wantCalls: 1},
		{name: "HEAD is safe", method: http.MethodHead, wantStatus: http.StatusNoContent, wantCalls: 1},
		{name: "OPTIONS is safe", method: http.MethodOptions, wantStatus: http.StatusNoContent, wantCalls: 1},
		{name: "missing cookie and header", method: http.MethodPost, wantStatus: http.StatusForbidden},
		{name: "missing header", method: http.MethodPatch, cookie: validToken, wantStatus: http.StatusForbidden},
		{name: "missing cookie", method: http.MethodDelete, header: validToken, wantStatus: http.StatusForbidden},
		{name: "matching invalid length", method: http.MethodPost, cookie: "short", header: "short", wantStatus: http.StatusForbidden},
		{name: "mismatch", method: http.MethodPut, cookie: validToken, header: otherToken, wantStatus: http.StatusForbidden},
		{name: "match", method: http.MethodPost, cookie: validToken, header: validToken, wantStatus: http.StatusNoContent, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			calls := 0
			router := gin.New()
			router.Any("/protected", CSRFProtection(), func(c *gin.Context) {
				calls++
				c.Status(http.StatusNoContent)
			})

			request := httptest.NewRequest(test.method, "/protected", nil)
			if test.cookie != "" {
				request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: test.cookie})
			}
			if test.header != "" {
				request.Header.Set(CSRFHeaderName, test.header)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if calls != test.wantCalls {
				t.Fatalf("handler calls = %d, want %d", calls, test.wantCalls)
			}
			if test.wantStatus == http.StatusForbidden && !strings.Contains(recorder.Body.String(), `"code":"invalid_csrf_token"`) {
				t.Fatalf("body = %s, want invalid_csrf_token", recorder.Body.String())
			}
		})
	}
}

func TestFirstPartyCookiesUseHostOnlySecurityAttributes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	SetFirstPartyCookie(context, "session", time.Hour)
	SetCSRFCookie(context, "csrf", time.Hour)

	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookie count = %d, want 2", len(cookies))
	}
	byName := map[string]*http.Cookie{}
	for _, cookie := range cookies {
		byName[cookie.Name] = cookie
	}

	session := byName[FirstPartyCookieName]
	csrf := byName[CSRFCookieName]
	if session == nil || csrf == nil {
		t.Fatalf("cookies = %v, want %s and %s", cookies, FirstPartyCookieName, CSRFCookieName)
	}
	for _, cookie := range []*http.Cookie{session, csrf} {
		if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 3600 {
			t.Errorf("cookie %s attributes = %+v", cookie.Name, cookie)
		}
	}
	if !session.HttpOnly {
		t.Error("first-party session cookie must be HttpOnly")
	}
	if csrf.HttpOnly {
		t.Error("CSRF cookie must be readable by the same-origin frontend")
	}
}

func TestFirstPartyCookiesDoNotTurnSubsecondTTLIntoSessionCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	SetFirstPartyCookie(context, "session", 500*time.Millisecond)
	SetCSRFCookie(context, "csrf", 500*time.Millisecond)

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge != -1 {
			t.Errorf("subsecond TTL cookie became non-expiring: %+v", cookie)
		}
	}
}

func TestClearFirstPartyCookieClearsSessionAndCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	ClearFirstPartyCookie(context)

	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookie count = %d, want 2", len(cookies))
	}
	for _, cookie := range cookies {
		if cookie.MaxAge != -1 || cookie.Value != "" || cookie.Path != "/" || !cookie.Secure || cookie.Domain != "" {
			t.Errorf("cleared cookie attributes = %+v", cookie)
		}
	}
}

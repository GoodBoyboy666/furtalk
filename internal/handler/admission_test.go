package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/ratelimit"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

type recordingAdmission struct {
	allow   bool
	policy  string
	subject string
}

func (a *recordingAdmission) Allow(policy, subject string) bool {
	a.policy, a.subject = policy, subject
	return a.allow
}

func TestFlowAdmissionDenialPrecedesStateHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	admission := &recordingAdmission{}
	router := gin.New()
	router.Use(httpx.ClientIP(nil))
	calls := 0
	router.POST("/state", flowAdmission(admission, "test", clientIPSubject), func(c *gin.Context) {
		calls++
		c.Status(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodPost, "/state", nil)
	req.RemoteAddr = "192.0.2.7:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if calls != 0 {
		t.Fatalf("state handler calls = %d, want 0", calls)
	}
	if admission.policy != "test" || admission.subject != "192.0.2.7" {
		t.Fatalf("admission = %q/%q", admission.policy, admission.subject)
	}
}

func TestFlowAdmissionMissingSubjectUsesUnknownBucket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	admission := &recordingAdmission{}
	router := gin.New()
	router.POST("/state", flowAdmission(admission, "test", clientIPSubject), func(c *gin.Context) {})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/state", nil))
	if admission.subject != "unknown" {
		t.Fatalf("missing subject = %q, want unknown", admission.subject)
	}
}

func TestAuthStateRoutesDenyBeforeServiceAllocation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	admission := &recordingAdmission{}
	router := gin.New()
	router.Use(httpx.ClientIP(nil))
	RegisterAuthWithAdmission(router.Group("/api/v1"), (*identity.Service)(nil), admission)

	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "passkey", method: http.MethodPost, path: "/api/v1/auth/passkeys/login/options"},
		{name: "oauth", method: http.MethodGet, path: "/api/v1/auth/oauth/apple/start"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.0.2.8:1234"
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", rec.Code)
			}
		})
	}
	if admission.policy != ratelimit.PolicyOAuthStart {
		t.Fatalf("last admission policy = %q, want %q", admission.policy, ratelimit.PolicyOAuthStart)
	}
}

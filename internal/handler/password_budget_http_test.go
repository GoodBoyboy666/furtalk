package handler

import (
	"net/http"
	"strings"
	"testing"

	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

func TestPasswordLoginBudgetHTTPMapsTo429(t *testing.T) {
	gin.SetMode(gin.TestMode)
	admission := &recordingAdmission{}
	svc := identity.NewService(identity.Dependencies{
		Cache:         emailCodeCacheStore{},
		Policy:        authPolicyReader{},
		CaptchaPolicy: emailCodePolicy{},
		Admission:     admission,
	})
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator), httpx.ClientIP(nil))
	RegisterAuthWithAdmission(router.Group("/api/v1"), svc, nil)

	rec := postJSON(router, "/api/v1/auth/password/login", `{"email":"user@example.com","password":"password"}`, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Fatalf("body = %s, want rate_limited", rec.Body.String())
	}
	if admission.policy == "" || admission.subject == "" {
		t.Fatalf("admission = %q/%q, want password policy and subject", admission.policy, admission.subject)
	}
}

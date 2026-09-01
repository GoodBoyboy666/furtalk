package handler

import (
	"net/http"
	"strconv"

	"furtalk/internal/middleware"
	"furtalk/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

// FlowAdmission is the narrow HTTP boundary for a named temporary-state budget.
// Implementations must be safe for concurrent requests and must not expose
// request secrets in their keys or logs.
type FlowAdmission interface {
	Allow(policy, subject string) bool
}

// HTTP 边界拥有的固定流程预算名称。
const (
	PolicyPasskeyLoginOptions        = "passkey_login_options"
	PolicyOAuthStart                 = "oauth_start"
	PolicyOAuthHandoff               = "oauth_handoff"
	PolicyPasskeyRegistrationOptions = "passkey_registration_options"
	PolicyWidgetAuthCode             = "widget_auth_code"
)

// flowAdmission rejects a request before the handler can allocate ephemeral
// state. Missing subjects use one stable fail-closed bucket.
func flowAdmission(admission FlowAdmission, policy string, subject func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if admission == nil {
			c.Next()
			return
		}
		key := "unknown"
		if subject != nil {
			if candidate := subject(c); candidate != "" {
				key = candidate
			}
		}
		if !admission.Allow(policy, key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, httpx.Response(c, "rate_limited", "too many requests"))
			return
		}
		c.Next()
	}
}

func clientIPSubject(c *gin.Context) string {
	return c.GetString(httpx.ClientIPKey)
}

func principalSubject(c *gin.Context) string {
	principal, ok := middleware.CurrentPrincipal(c)
	if !ok || principal.UserID <= 0 {
		return ""
	}
	return "user:" + strconv.FormatInt(principal.UserID, 10)
}

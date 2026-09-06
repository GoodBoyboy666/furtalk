package handler

import (
	"net/http"
	"strconv"

	"furtalk/internal/middleware"
	"furtalk/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

// FlowAdmission 定义按流程名称和主体标识执行临时状态预算的 HTTP 边界。
type FlowAdmission interface {
	Allow(policy, subject string) bool
}

// 以下常量标识 HTTP 边界使用的固定流程预算。
const (
	PolicyPasskeyLoginOptions        = "passkey_login_options"
	PolicyOAuthStart                 = "oauth_start"
	PolicyOAuthHandoff               = "oauth_handoff"
	PolicyPasskeyRegistrationOptions = "passkey_registration_options"
	PolicyWidgetAuthCode             = "widget_auth_code"
)

// flowAdmission 在 HTTP 处理器前执行流程准入预算检查。
func flowAdmission(admission FlowAdmission, policy string, subject func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if admission == nil {
			c.Next()
			return
		}
		// 无法解析主体时共用 unknown 预算桶，仍按预算结果处理请求。
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

// clientIPSubject 返回请求的客户端 IP 主体标识。
func clientIPSubject(c *gin.Context) string {
	return c.GetString(httpx.ClientIPKey)
}

// principalSubject 返回当前认证主体的预算标识。
func principalSubject(c *gin.Context) string {
	principal, ok := middleware.CurrentPrincipal(c)
	if !ok || principal.UserID <= 0 {
		return ""
	}
	return "user:" + strconv.FormatInt(principal.UserID, 10)
}

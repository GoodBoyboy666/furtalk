package router

import (
	"context"
	"net/http"
	"net/url"

	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/ratelimit"
	"github.com/gin-gonic/gin"
)

// oauthBridgeFieldLimit 是 Apple form_post 桥接受的单字段上限，防止超大载荷。
const (
	oauthBridgeStateLimit = 512
	oauthBridgeCodeLimit  = 4096
	oauthBridgeErrLimit   = 512
)

// CreateOAuthHandoff 由组合根注入的 Apple handoff 创建函数签名。
type CreateOAuthHandoff func(ctx context.Context, providerKey, state, code, errMsg string) (string, error)

// FlowAdmission is the narrow route-level budget boundary. The router does not
// depend on a concrete limiter implementation.
type FlowAdmission interface {
	Allow(policy, subject string) bool
}

// RegisterOAuthCallbackBridge 在 Gin engine 根路径注册 Apple form_post 桥。
// 该桥只接受 Apple 回发到 /oauth/callback/:provider 的表单，创建短时一次性
// handoff 后 303 到同一页面的 ?handoff=<opaque>，绝不把授权码放进 URL。
// 必须在 SPA NoRoute 回退安装之前注册；任意其他前端 POST 仍被回退拒绝。
func RegisterOAuthCallbackBridge(engine *gin.Engine, createHandoff CreateOAuthHandoff) {
	RegisterOAuthCallbackBridgeWithAdmission(engine, createHandoff, nil)
}

// RegisterOAuthCallbackBridgeWithAdmission adds the Apple bridge with a
// process-local flow admission budget before handoff allocation.
func RegisterOAuthCallbackBridgeWithAdmission(engine *gin.Engine, createHandoff CreateOAuthHandoff, admission FlowAdmission) {
	engine.POST("/oauth/callback/:provider", flowAdmission(admission, ratelimit.PolicyOAuthHandoff), oauthCallbackBridge(createHandoff))
}

func flowAdmission(admission FlowAdmission, policy string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if admission == nil {
			c.Next()
			return
		}
		subject := c.GetString(httpx.ClientIPKey)
		if subject == "" {
			subject = "unknown"
		}
		if !admission.Allow(policy, subject) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, httpx.Response(c, "rate_limited", "too many requests"))
			return
		}
		c.Next()
	}
}

func oauthCallbackBridge(createHandoff CreateOAuthHandoff) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		providerKey := c.Param("provider")
		if providerKey != "apple" {
			c.Status(http.StatusBadRequest)
			return
		}
		state := c.PostForm("state")
		code := c.PostForm("code")
		errMsg := c.PostForm("error")
		if providerKey == "" || state == "" ||
			len(state) > oauthBridgeStateLimit ||
			len(code) > oauthBridgeCodeLimit ||
			len(errMsg) > oauthBridgeErrLimit {
			c.Status(http.StatusBadRequest)
			return
		}
		token, err := createHandoff(c.Request.Context(), providerKey, state, code, errMsg)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		c.Redirect(http.StatusSeeOther, "/oauth/callback/"+url.PathEscape(providerKey)+"?handoff="+token)
	}
}

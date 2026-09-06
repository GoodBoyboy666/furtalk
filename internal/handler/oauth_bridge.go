package handler

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// Apple form_post 桥接受的单字段上限。
const (
	oauthBridgeStateLimit = 512
	oauthBridgeCodeLimit  = 4096
	oauthBridgeErrLimit   = 512
)

// CreateOAuthHandoff 由依赖组装入口注入的 Apple handoff 创建函数签名。
type CreateOAuthHandoff func(ctx context.Context, providerKey, state, code, errMsg string) (string, error)

// RegisterOAuthCallbackBridgeWithAdmission 注册 HTTP 路由。
func RegisterOAuthCallbackBridgeWithAdmission(engine *gin.Engine, createHandoff CreateOAuthHandoff, admission FlowAdmission) {
	engine.POST("/oauth/callback/:provider", flowAdmission(admission, PolicyOAuthHandoff, clientIPSubject), oauthCallbackBridge(createHandoff))
}

// oauthCallbackBridge 处理 OAuth form_post 回调并创建 handoff。
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
		if state == "" ||
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

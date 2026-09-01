package handler

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// Apple form_post 桥接受的单字段上限，防止超大载荷。
const (
	oauthBridgeStateLimit = 512
	oauthBridgeCodeLimit  = 4096
	oauthBridgeErrLimit   = 512
)

// CreateOAuthHandoff 由组合根注入的 Apple handoff 创建函数签名。
type CreateOAuthHandoff func(ctx context.Context, providerKey, state, code, errMsg string) (string, error)

// RegisterOAuthCallbackBridgeWithAdmission 在 Gin engine 根路径注册 Apple form_post 桥。
// 该桥只接受 Apple 回发到 /oauth/callback/:provider 的表单，创建短时一次性
// handoff 后 303 到同一页面的 ?handoff=<opaque>，绝不把授权码放进 URL。
// 必须在 SPA NoRoute 回退安装之前注册；任意其他前端 POST 仍被回退拒绝。
func RegisterOAuthCallbackBridgeWithAdmission(engine *gin.Engine, createHandoff CreateOAuthHandoff, admission FlowAdmission) {
	engine.POST("/oauth/callback/:provider", flowAdmission(admission, PolicyOAuthHandoff, clientIPSubject), oauthCallbackBridge(createHandoff))
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

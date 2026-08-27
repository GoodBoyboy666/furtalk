package handler

import (
	"net/http"
	"strconv"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

// RegisterAuth 挂载认证端点。
func RegisterAuth(api *gin.RouterGroup, service *identity.Service, csrf ...gin.HandlerFunc) {
	auth := api.Group("/auth")
	auth.POST("/email-codes", sendEmailCode(service))
	auth.POST("/email-code/login", emailCodeLogin(service))
	auth.POST("/password/login", passwordLogin(service))
	auth.POST("/password/reset-codes", passwordResetCode(service))
	auth.POST("/password/reset", passwordResetConfirm(service))
	auth.POST("/logout", append(csrf, logout(service))...)
	auth.POST("/passkeys/login/options", passkeyLoginOptions(service))
	auth.POST("/passkeys/login/verify", passkeyLoginVerify(service))
	auth.GET("/providers", listProviders(service))
	auth.GET("/oauth/:provider/start", oauthStart(service))
	auth.POST("/oauth/:provider/complete", oauthComplete(service))
}

// RegisterMe 挂载 /me 子路由，并挂载用户门禁。
func RegisterMe(api *gin.RouterGroup, service *identity.Service, userGate middleware.UserGate, csrf ...gin.HandlerFunc) {
	middlewares := append([]gin.HandlerFunc{middleware.RequireUser(userGate)}, csrf...)
	me := api.Group("/me", middlewares...)
	me.GET("", meGet(service))
	me.PATCH("", meUpdate(service))
	me.PATCH("/notification-preferences", meUpdateNotificationPreferences(service))
	me.POST("/password", meSetPassword(service))
	me.POST("/sessions/revoke", meRevokeAllSessions(service))
	me.POST("/passkeys/options", mePasskeyRegistrationOptions(service))
	me.POST("/passkeys", meFinishPasskeyRegistration(service))
	me.PATCH("/passkeys/:passkey_id", meRenamePasskey(service))
	me.DELETE("/passkeys/:passkey_id", meDeletePasskey(service))
	me.GET("/identities", meListIdentities(service))
	me.DELETE("/identities/:identity_id", meDeleteIdentity(service))
}

// RegisterAdminUsers 挂载管理端用户管理子路由。
func RegisterAdminUsers(admin *gin.RouterGroup, service *identity.Service) {
	admin.GET("/users", adminUsersList(service))
	admin.POST("/users", adminUsersCreate(service))
	// 静态 batch 路由必须在 /users/:user_id 之前注册。
	admin.POST("/users/batch", adminUsersBatch(service))
	admin.GET("/users/:user_id", adminUsersGet(service))
	admin.PATCH("/users/:user_id", adminUsersUpdate(service))
	admin.POST("/users/:user_id/password", adminUsersResetPassword(service))
	admin.DELETE("/users/:user_id", adminUsersDelete(service))
	admin.POST("/users/:user_id/restore", adminUsersRestore(service))
}

// @Summary 请求发送邮箱验证码
// @Tags auth
// @Accept json
// @Param body body EmailCodeRequest true "目标邮箱（可附带 CAPTCHA token）"
// @Success 204 "验证码已发送"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 403 {object} httpx.ErrorResponse "验证码验证失败"
// @Failure 422 {object} httpx.ErrorResponse "请求参数无效或缺少验证码"
// @Failure 503 {object} httpx.ErrorResponse "验证码服务或邮件服务暂不可用"
// @Router /api/v1/auth/email-codes [post]
func sendEmailCode(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req EmailCodeRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if err := service.SendEmailCode(c.Request.Context(), req.Email, req.CaptchaToken); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 使用邮箱验证码登录
// @Tags auth
// @Accept json
// @Param body body EmailCodeLoginRequest true "邮箱与验证码（可附带 CAPTCHA token）"
// @Success 204 "已写入会话 Cookie"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "验证码错误"
// @Failure 403 {object} httpx.ErrorResponse "验证码验证失败"
// @Failure 422 {object} httpx.ErrorResponse "缺少验证码"
// @Failure 503 {object} httpx.ErrorResponse "验证码服务暂不可用"
// @Router /api/v1/auth/email-code/login [post]
func emailCodeLogin(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req EmailCodeLoginRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		session, err := service.LoginWithEmailCode(c.Request.Context(), identity.EmailCodeLoginInput{
			Email:        req.Email,
			Code:         req.Code,
			CaptchaToken: req.CaptchaToken,
		})
		if err != nil {
			writeError(c, err)
			return
		}
		setSessionCookie(c, session)
		c.Status(http.StatusNoContent)
	}
}

// @Summary 使用邮箱密码登录
// @Tags auth
// @Accept json
// @Param body body PasswordLoginRequest true "邮箱与密码（可附带 CAPTCHA token）"
// @Success 204 "已写入会话 Cookie"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "账号或密码错误"
// @Failure 403 {object} httpx.ErrorResponse "账号已被禁用或验证码验证失败"
// @Failure 422 {object} httpx.ErrorResponse "缺少验证码"
// @Failure 503 {object} httpx.ErrorResponse "验证码服务暂不可用"
// @Router /api/v1/auth/password/login [post]
func passwordLogin(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req PasswordLoginRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		session, err := service.LoginWithPassword(c.Request.Context(), req.Email, req.Password, req.CaptchaToken)
		if err != nil {
			writeError(c, err)
			return
		}
		setSessionCookie(c, session)
		c.Status(http.StatusNoContent)
	}
}

// @Summary 请求发送密码重置验证码
// @Tags auth
// @Accept json
// @Param body body PasswordResetCodeRequest true "目标邮箱（可附带 CAPTCHA token）"
// @Success 204 "验证码已发送（未知邮箱也返回相同的公开成功）"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 403 {object} httpx.ErrorResponse "验证码验证失败"
// @Failure 422 {object} httpx.ErrorResponse "请求参数无效或缺少验证码"
// @Failure 503 {object} httpx.ErrorResponse "验证码服务暂不可用"
// @Router /api/v1/auth/password/reset-codes [post]
func passwordResetCode(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req PasswordResetCodeRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if err := service.RequestPasswordReset(c.Request.Context(), req.Email, req.CaptchaToken); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 使用验证码与新密码完成密码重置
// @Tags auth
// @Accept json
// @Param body body PasswordResetConfirmRequest true "邮箱、验证码与新密码"
// @Success 204 "密码已重置（不签发会话 Cookie）"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "验证码错误"
// @Failure 422 {object} httpx.ErrorResponse "密码不符合要求"
// @Router /api/v1/auth/password/reset [post]
func passwordResetConfirm(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req PasswordResetConfirmRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if err := service.ResetPasswordWithCode(c.Request.Context(), req.Email, req.Code, req.NewPassword); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 退出登录
// @Tags auth
// @Success 204 "已清除会话 Cookie"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/auth/logout [post]
func logout(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		if err := service.Logout(c.Request.Context()); err != nil {
			writeError(c, err)
			return
		}
		middleware.ClearFirstPartyCookie(c)
		c.Status(http.StatusNoContent)
	}
}

// @Summary 开始 passkey 登录仪式
// @Tags auth
// @Accept json
// @Produce json
// @Param body body PasskeyLoginOptionsRequest true "用户句柄（可选）"
// @Success 200 {object} PasskeyLoginOptionsResponse "断言选项"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 404 {object} httpx.ErrorResponse "用户不存在"
// @Router /api/v1/auth/passkeys/login/options [post]
func passkeyLoginOptions(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req PasskeyLoginOptionsRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		options, err := service.BeginPasskeyLogin(c.Request.Context(), req.UserHandle)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, PasskeyLoginOptionsResponse{Challenge: options.Challenge, Options: options.Options})
	}
}

// @Summary 校验 passkey 断言并登录
// @Tags auth
// @Accept json
// @Param body body PasskeyFinishRequest true "断言结果"
// @Success 204 "已写入会话 Cookie"
// @Failure 400 {object} httpx.ErrorResponse "断言无效"
// @Failure 401 {object} httpx.ErrorResponse "校验失败"
// @Router /api/v1/auth/passkeys/login/verify [post]
func passkeyLoginVerify(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req PasskeyFinishRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		session, err := service.VerifyPasskeyLogin(c.Request.Context(), req.Challenge, rawMessage(req.Response))
		if err != nil {
			writeError(c, err)
			return
		}
		setSessionCookie(c, session)
		c.Status(http.StatusNoContent)
	}
}

// @Summary 列出可用的 OAuth/OIDC 提供商
// @Tags auth
// @Produce json
// @Success 200 {object} AuthProvidersResponse "提供商列表"
// @Router /api/v1/auth/providers [get]
func listProviders(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		metas, err := service.OAuthProviders(c.Request.Context())
		if err != nil {
			writeError(c, err)
			return
		}
		out := make([]AuthProviderMetadata, 0, len(metas))
		for _, meta := range metas {
			out = append(out, AuthProviderMetadata{Key: meta.Key, Kind: meta.Kind, Name: meta.Name})
		}
		c.JSON(http.StatusOK, AuthProvidersResponse{Providers: out})
	}
}

// @Summary 开始 OAuth 授权流程
// @Tags auth
// @Produce json
// @Param provider path string true "提供商 key"
// @Param purpose query string false "login | bind（默认 login）"
// @Param redirect query string false "授权完成后的回跳地址"
// @Success 200 {object} OAuthStartResponse "授权 URL"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "bind 场景需要登录"
// @Failure 404 {object} httpx.ErrorResponse "提供商不存在或未启用"
// @Router /api/v1/auth/oauth/{provider}/start [get]
func oauthStart(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		providerKey := c.Param("provider")
		purpose := c.DefaultQuery("purpose", "login")
		redirect := c.Query("redirect")
		var userID int64
		if purpose == "bind" {
			principal, ok := requirePrincipal(c)
			if !ok {
				return
			}
			userID = principal.UserID
		}
		start, err := service.BeginOAuth(c.Request.Context(), providerKey, purpose, userID, redirect)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, OAuthStartResponse{AuthURL: start.AuthURL})
	}
}

// @Summary 完成 OAuth 登录
// @Tags auth
// @Accept json
// @Produce json
// @Param provider path string true "提供商 key"
// @Param body body OAuthCompleteRequest true "直接回调参数或 Apple handoff token"
// @Success 200 {object} OAuthCompleteResponse "已写入会话 Cookie，返回站内回跳地址"
// @Failure 400 {object} httpx.ErrorResponse "回调参数无效、state/handoff 无效或授权码校验失败"
// @Router /api/v1/auth/oauth/{provider}/complete [post]
func oauthComplete(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		providerKey := c.Param("provider")
		var req OAuthCompleteRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if req.Handoff != "" {
			// handoff 与直接回调参数互斥；Apple 授权码绝不在 URL 中出现。
			if req.State != "" || req.Code != "" || req.Error != "" {
				c.JSON(http.StatusBadRequest, errorResponse(c, "invalid_request", "cannot mix handoff with direct callback parameters"))
				return
			}
			handoff, err := service.ConsumeOAuthHandoff(c.Request.Context(), req.Handoff)
			if err != nil {
				writeOAuthError(c, err, "")
				return
			}
			if handoff.Provider != providerKey {
				writeOAuthError(c, domain.ErrOAuthCallbackInvalid, "")
				return
			}
			if handoff.Error != "" {
				completeOAuthError(c, service, providerKey, handoff.State)
				return
			}
			if handoff.State == "" || handoff.Code == "" {
				c.JSON(http.StatusBadRequest, errorResponse(c, "invalid_request", "missing state or code"))
				return
			}
			completeOAuth(c, service, providerKey, handoff.State, handoff.Code)
			return
		}
		// 直接回调参数：提供方以 error 拒绝授权时只消费 state 并返回取消错误。
		if req.Error != "" {
			if req.State == "" {
				c.JSON(http.StatusBadRequest, errorResponse(c, "invalid_request", "missing state"))
				return
			}
			completeOAuthError(c, service, providerKey, req.State)
			return
		}
		if req.State == "" || req.Code == "" {
			c.JSON(http.StatusBadRequest, errorResponse(c, "invalid_request", "missing state or code"))
			return
		}
		completeOAuth(c, service, providerKey, req.State, req.Code)
	}
}

// completeOAuth 消费 state 完成登录，成功时写入会话 Cookie 并返回回跳地址。
func completeOAuth(c *gin.Context, service *identity.Service, providerKey, state, code string) {
	session, redirect, err := service.FinishOAuth(c.Request.Context(), providerKey, state, code)
	if err != nil {
		writeOAuthError(c, err, redirect)
		return
	}
	setSessionCookie(c, session)
	c.JSON(http.StatusOK, OAuthCompleteResponse{Redirect: redirect})
}

// completeOAuthError 处理用户取消授权：消费 state 并返回 access-denied 错误。
func completeOAuthError(c *gin.Context, service *identity.Service, providerKey, state string) {
	redirect, err := service.OAuthAccessDenied(c.Request.Context(), providerKey, state)
	writeOAuthError(c, err, redirect)
}

// writeOAuthError 以标准错误信封写出 OAuth 回调错误，并在 state 有效时
// 于 details.redirect 携带已净化的站内回跳地址，供前端提供返回操作。
func writeOAuthError(c *gin.Context, err error, redirect string) {
	details := map[string]any{}
	if redirect != "" {
		details["redirect"] = redirect
	}
	httpx.WriteErrorWithDetails(c, err, details)
}

// setSessionCookie 以与令牌生命周期匹配的 Max-Age 写入 FP Cookie。
func setSessionCookie(c *gin.Context, session *identity.Session) {
	lifetime := time.Until(session.ExpiresAt)
	if lifetime <= 0 {
		middleware.ClearFirstPartyCookie(c)
		return
	}
	middleware.SetFirstPartyCookie(c, session.Token, lifetime)
	middleware.SetCSRFCookie(c, session.CSRFToken, lifetime)
}

// @Summary 获取当前用户资料
// @Tags me
// @Produce json
// @Success 200 {object} MeResponse "当前用户资料"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Router /api/v1/me [get]
func meGet(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		profile, err := service.Get(c.Request.Context(), userID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toMeResponse(*profile))
	}
}

// @Summary 更新当前用户资料
// @Tags me
// @Accept json
// @Produce json
// @Param body body MeUpdateRequest true "可更新的资料字段"
// @Success 200 {object} MeResponse "更新后的资料"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 409 {object} httpx.ErrorResponse "邮箱冲突"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me [patch]
func meUpdate(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		var req MeUpdateRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		nickname := ""
		if req.Nickname != nil {
			nickname = *req.Nickname
		}
		profile, err := service.UpdateProfile(c.Request.Context(), userID, nickname, req.WebsiteURL)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toMeResponse(*profile))
	}
}

// @Summary 更新当前用户通知偏好
// @Tags me
// @Accept json
// @Produce json
// @Param body body NotificationPreferencesRequest true "通知开关"
// @Success 200 {object} NotificationPreferencesResponse "更新后的偏好"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me/notification-preferences [patch]
func meUpdateNotificationPreferences(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		var req NotificationPreferencesRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		prefs, err := service.UpdateNotificationPreferences(c.Request.Context(), userID, req.ReplyEnabled, req.ModerationEnabled)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, NotificationPreferencesResponse{
			ReplyEnabled:      prefs.ReplyEnabled,
			ModerationEnabled: prefs.ModerationEnabled,
		})
	}
}

// @Summary 设置或修改当前用户密码
// @Tags me
// @Accept json
// @Param body body MePasswordRequest true "当前密码（已有密码时必填）与新密码"
// @Success 204 "密码已更新，并重签当前浏览器会话 Cookie"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录或当前密码错误"
// @Failure 422 {object} httpx.ErrorResponse "密码不符合要求"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me/password [post]
func meSetPassword(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		var req MePasswordRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		session, err := service.ChangePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword)
		if err != nil {
			writeError(c, err)
			return
		}
		setSessionCookie(c, session)
		c.Status(http.StatusNoContent)
	}
}

// @Summary 注销当前用户全部设备
// @Tags me
// @Success 204 "全部会话已失效，当前设备已退出"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me/sessions/revoke [post]
func meRevokeAllSessions(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		if err := service.RevokeAllSessions(c.Request.Context(), userID); err != nil {
			writeError(c, err)
			return
		}
		middleware.ClearFirstPartyCookie(c)
		c.Status(http.StatusNoContent)
	}
}

// @Summary 获取 passkey 注册选项
// @Tags me
// @Produce json
// @Success 200 {object} PasskeyRegistrationOptionsResponse "注册选项"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me/passkeys/options [post]
func mePasskeyRegistrationOptions(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		options, err := service.BeginPasskeyRegistration(c.Request.Context(), userID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, PasskeyRegistrationOptionsResponse{Challenge: options.Challenge, Options: options.Options})
	}
}

// @Summary 完成 passkey 注册
// @Tags me
// @Accept json
// @Param body body PasskeyFinishRequest true "注册结果"
// @Success 204 "注册完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 409 {object} httpx.ErrorResponse "凭证冲突"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me/passkeys [post]
func meFinishPasskeyRegistration(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		var req PasskeyFinishRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if err := service.FinishPasskeyRegistration(c.Request.Context(), userID, req.Challenge, rawMessage(req.Response)); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 重命名自己的 passkey
// @Tags me
// @Accept json
// @Param passkey_id path integer true "passkey ID（十进制字符串）"
// @Param body body PasskeyRenameRequest true "新的 passkey 名称（1–100 字符）"
// @Success 204 "重命名完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 404 {object} httpx.ErrorResponse "passkey 不存在"
// @Failure 422 {object} httpx.ErrorResponse "名称不符合要求"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me/passkeys/{passkey_id} [patch]
func meRenamePasskey(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		passkeyID, err := httpx.ParseIDParam(c, "passkey_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req PasskeyRenameRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if err := service.RenamePasskey(c.Request.Context(), userID, passkeyID, req.Name); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 删除自己的 passkey
// @Tags me
// @Param passkey_id path integer true "passkey ID（十进制字符串）"
// @Success 204 "删除完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 404 {object} httpx.ErrorResponse "passkey 不存在"
// @Failure 409 {object} httpx.ErrorResponse "不能移除最后一个登录方式"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me/passkeys/{passkey_id} [delete]
func meDeletePasskey(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		passkeyID, err := httpx.ParseIDParam(c, "passkey_id")
		if err != nil {
			writeError(c, err)
			return
		}
		if err := service.DeletePasskey(c.Request.Context(), userID, passkeyID); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 列出当前用户的登录方式
// @Tags me
// @Produce json
// @Success 200 {object} IdentitiesResponse "登录方式列表"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Router /api/v1/me/identities [get]
func meListIdentities(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		identities, err := service.ListIdentities(c.Request.Context(), userID)
		if err != nil {
			writeError(c, err)
			return
		}
		out := make([]IdentityMetadata, 0, len(identities))
		for _, item := range identities {
			meta := IdentityMetadata{
				Kind:       item.Kind,
				Name:       item.Name,
				Provider:   item.Provider,
				CreatedAt:  item.CreatedAt,
				LastUsedAt: item.LastUsedAt,
			}
			if item.ID > 0 {
				meta.ID = strconv.FormatInt(item.ID, 10)
			}
			out = append(out, meta)
		}
		c.JSON(http.StatusOK, IdentitiesResponse{Identities: out})
	}
}

// @Summary 解绑外部登录方式
// @Tags me
// @Param identity_id path integer true "登录方式 ID（十进制字符串）"
// @Success 204 "解绑完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 404 {object} httpx.ErrorResponse "登录方式不存在"
// @Failure 409 {object} httpx.ErrorResponse "不能移除最后一个登录方式"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/me/identities/{identity_id} [delete]
func meDeleteIdentity(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			return
		}
		identityID, err := httpx.ParseIDParam(c, "identity_id")
		if err != nil {
			writeError(c, err)
			return
		}
		if err := service.DeleteExternalIdentity(c.Request.Context(), userID, identityID); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 批量管理用户
// @Tags admin-users
// @Accept json
// @Produce json
// @Param body body AdminBatchRequest true "用户批量命令"
// @Success 200 {object} AdminBatchResponse "批量操作计数"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "不能删除当前操作者或权限不足"
// @Failure 404 {object} httpx.ErrorResponse "用户不存在"
// @Failure 409 {object} httpx.ErrorResponse "生命周期冲突或不能移除最后一个管理员"
// @Failure 422 {object} httpx.ErrorResponse "请求参数无效或缺少破坏性操作确认"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/users/batch [post]
func adminUsersBatch(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		input, err := decodeUserBatchRequest(c)
		if err != nil {
			writeBatchError(c, err)
			return
		}
		input.ActingID = actingUserID(c)
		if input.ActingID <= 0 {
			return
		}
		result, err := service.AdminBatchUsers(c.Request.Context(), input)
		if err != nil {
			writeBatchError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminBatchResponse(*result))
	}
}

// @Summary 按关键字分页列出用户
// @Tags admin-users
// @Produce json
// @Param q query string false "邮箱/昵称搜索关键字"
// @Param sort query string false "排序方向：asc（最早优先）或 desc（最新优先，默认）"
// @Param page query integer false "页码（从 1 开始，默认 1）"
// @Param limit query integer false "每页数量（默认 50）"
// @Success 200 {object} AdminUserListResponse "用户列表与真实总数"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Router /api/v1/admin/users [get]
func adminUsersList(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 50
		if raw := c.Query("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				writeError(c, httpx.ErrInvalidID)
				return
			}
			limit = parsed
		}
		page, err := parsePage(c)
		if err != nil {
			writeError(c, err)
			return
		}
		sort, err := domain.NormalizeAdminSort(c.Query("sort"))
		if err != nil {
			writeError(c, err)
			return
		}
		result, err := service.ListWithTotal(c.Request.Context(), c.Query("q"), sort, page, limit)
		if err != nil {
			writeError(c, err)
			return
		}
		out := make([]AdminUserResponse, 0, len(result.Users))
		for _, row := range result.Users {
			out = append(out, toAdminUserResponse(row))
		}
		c.JSON(http.StatusOK, AdminUserListResponse{Users: out, Total: result.Total})
	}
}

// @Summary 预创建用户
// @Tags admin-users
// @Accept json
// @Produce json
// @Param body body AdminUserCreateRequest true "用户资料、角色、可选初始密码与邮箱验证开关"
// @Success 201 {object} AdminUserResponse "创建的用户"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 409 {object} httpx.ErrorResponse "邮箱已被注册"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/users [post]
func adminUsersCreate(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req AdminUserCreateRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		input := identity.AdminCreateUserInput{
			Email:         req.Email,
			Nickname:      req.Nickname,
			WebsiteURL:    req.WebsiteURL,
			Role:          domain.Role(req.Role),
			Password:      req.Password,
			EmailVerified: req.EmailVerified,
		}
		profile, err := service.AdminCreateUser(c.Request.Context(), input)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusCreated, toAdminUserResponse(*profile))
	}
}

// @Summary 获取用户资料
// @Tags admin-users
// @Produce json
// @Param user_id path integer true "用户 ID（十进制字符串）"
// @Success 200 {object} AdminUserResponse "用户资料"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "用户不存在"
// @Router /api/v1/admin/users/{user_id} [get]
func adminUsersGet(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpx.ParseIDParam(c, "user_id")
		if err != nil {
			writeError(c, err)
			return
		}
		profile, err := service.Get(c.Request.Context(), id)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminUserResponse(*profile))
	}
}

// @Summary 修改用户资料与状态
// @Tags admin-users
// @Accept json
// @Produce json
// @Param user_id path integer true "用户 ID（十进制字符串）"
// @Param body body AdminUserUpdateRequest true "可更新的资料、角色、状态与邮箱验证字段"
// @Success 200 {object} AdminUserResponse "更新后的用户"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "用户不存在"
// @Failure 409 {object} httpx.ErrorResponse "不能移除最后一个管理员或邮箱冲突"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/users/{user_id} [patch]
func adminUsersUpdate(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpx.ParseIDParam(c, "user_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req AdminUserUpdateRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		var role *domain.Role
		if req.Role != nil {
			value := domain.Role(*req.Role)
			role = &value
		}
		var status *domain.UserStatus
		if req.Status != nil {
			value := domain.UserStatus(*req.Status)
			status = &value
		}
		input := identity.AdminUpdateUserInput{
			Email:         req.Email,
			Nickname:      req.Nickname,
			WebsiteURL:    req.WebsiteURL,
			Role:          role,
			Status:        status,
			EmailVerified: req.EmailVerified,
		}
		profile, err := service.AdminUpdateUser(c.Request.Context(), id, input)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminUserResponse(*profile))
	}
}

// @Summary 重置目标用户密码
// @Tags admin-users
// @Accept json
// @Param user_id path integer true "用户 ID（十进制字符串）"
// @Param body body AdminUserResetPasswordRequest true "新密码"
// @Success 204 "密码已重置"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "用户不存在"
// @Failure 422 {object} httpx.ErrorResponse "密码不符合要求"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/users/{user_id}/password [post]
func adminUsersResetPassword(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpx.ParseIDParam(c, "user_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req AdminUserResetPasswordRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if err := service.AdminResetPassword(c.Request.Context(), id, req.Password); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 软删除或硬删除用户
// @Tags admin-users
// @Param user_id path integer true "用户 ID（十进制字符串）"
// @Param mode query string true "soft | hard"
// @Param confirm query boolean false "硬删除需要显式确认"
// @Success 204 "删除完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "不能删除自己或权限不足"
// @Failure 404 {object} httpx.ErrorResponse "用户不存在"
// @Failure 409 {object} httpx.ErrorResponse "不能移除最后一个管理员"
// @Failure 422 {object} httpx.ErrorResponse "破坏性操作需要显式确认"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/users/{user_id} [delete]
func adminUsersDelete(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpx.ParseIDParam(c, "user_id")
		if err != nil {
			writeError(c, err)
			return
		}
		actingID, ok := currentUserID(c)
		if !ok {
			return
		}
		mode := c.DefaultQuery("mode", "soft")
		confirm := c.Query("confirm") == "true"
		if err := service.AdminDeleteUser(c.Request.Context(), actingID, id, mode, confirm); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 恢复被软删除的用户
// @Tags admin-users
// @Produce json
// @Param user_id path integer true "用户 ID（十进制字符串）"
// @Success 200 {object} AdminUserResponse "恢复后的用户"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "用户不存在"
// @Failure 409 {object} httpx.ErrorResponse "用户未处于软删除状态"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/users/{user_id}/restore [post]
func adminUsersRestore(service *identity.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpx.ParseIDParam(c, "user_id")
		if err != nil {
			writeError(c, err)
			return
		}
		profile, err := service.AdminRestoreUser(c.Request.Context(), id)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminUserResponse(*profile))
	}
}

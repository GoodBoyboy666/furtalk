package middleware

import (
	"net/http"
	"strconv"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/logging"
	"furtalk/internal/service/comment"
	"github.com/gin-gonic/gin"
)

// WidgetCookieName 是 CHIPS Partitioned widget 凭据 cookie。
const WidgetCookieName = "__Host-furtalk_widget"

// widgetCookieMaxAge 是未提供正有效期时使用的默认 Cookie 有效期。
const widgetCookieMaxAge = 24 * time.Hour

// SetWidgetCookie 以固定属性写入 widget CHIPS cookie。
func SetWidgetCookie(c *gin.Context, token string, maxAge time.Duration) {
	if maxAge <= 0 {
		maxAge = widgetCookieMaxAge
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:        WidgetCookieName,
		Value:       token,
		Path:        "/",
		MaxAge:      int(maxAge.Seconds()),
		Secure:      true,
		HttpOnly:    true,
		SameSite:    http.SameSiteNoneMode,
		Partitioned: true,
	})
}

// ClearWidgetCookie 使当前顶层分区中的 widget CHIPS cookie 过期。
func ClearWidgetCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:        WidgetCookieName,
		Value:       "",
		Path:        "/",
		MaxAge:      -1,
		Secure:      true,
		HttpOnly:    true,
		SameSite:    http.SameSiteNoneMode,
		Partitioned: true,
	})
}

const widgetCredentialKey = "widget_credential"
const widgetPrincipalKey = "widget_principal"

// WidgetPrincipalResolution 认证 widget 评论路由（强制要求有效凭证）。
func WidgetPrincipalResolution(verifier comment.WidgetCredentialVerifier, settingsReader comment.WidgetSettingsReader, authz PrincipalStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if verifier == nil || settingsReader == nil {
			httpx.Abort(c, http.StatusServiceUnavailable, "widget_credential_unavailable", "widget credential verification is unavailable")
			return
		}
		raw, err := c.Cookie(WidgetCookieName)
		if err != nil || raw == "" {
			httpx.Abort(c, http.StatusUnauthorized, "unauthorized", "widget credential required")
			return
		}
		cred, err := verifier.Verify(c.Request.Context(), raw)
		if err != nil {
			httpx.Abort(c, http.StatusUnauthorized, "invalid_credentials", "invalid widget credential")
			return
		}
		principal, err := checkWidgetCredential(c, verifier, settingsReader, authz, cred)
		if err != nil {
			httpx.Abort(c, http.StatusForbidden, "widget_credential_invalid", "widget credential no longer applies")
			return
		}
		if rawSite := c.Param("site_id"); rawSite != "" {
			siteID, err := strconv.ParseInt(rawSite, 10, 64)
			if err != nil || siteID != cred.SiteID() {
				httpx.Abort(c, http.StatusForbidden, "forbidden", "the credential does not authorize this site")
				return
			}
		}
		c.Set(widgetCredentialKey, cred)
		c.Set(widgetPrincipalKey, principal)
		c.Request = c.Request.WithContext(logging.WithAttrs(c.Request.Context(),
			logging.ID("user_id", cred.UserID()),
			logging.ID("site_id", cred.SiteID()),
		))
		c.Next()
	}
}

// WidgetOptionalResolution 解析可选的 Widget 凭据并设置当前主体。
func WidgetOptionalResolution(verifier comment.WidgetCredentialVerifier, settingsReader comment.WidgetSettingsReader, authz PrincipalStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if verifier == nil || settingsReader == nil {
			httpx.Abort(c, http.StatusServiceUnavailable, "widget_credential_unavailable", "widget credential verification is unavailable")
			return
		}
		raw, err := c.Cookie(WidgetCookieName)
		if err != nil || raw == "" {
			c.Next()
			return
		}
		cred, err := verifier.Verify(c.Request.Context(), raw)
		if err != nil {
			// 无效或已停用的旧凭证（含旧 widget_anonymous）不授予主体；清除旧 Cookie，
			// 让新的公开评论请求继续按匿名流程处理。
			ClearWidgetCookie(c)
			c.Next()
			return
		}
		principal, err := checkWidgetCredential(c, verifier, settingsReader, authz, cred)
		if err != nil {
			// 有效签名但 epoch、站点、主体状态或实时角色不满足时不授予主体，也不清除 Cookie；
			// handler 根据提交邮箱决定拒绝或匿名放行。
			c.Next()
			return
		}
		if rawSite := c.Param("site_id"); rawSite != "" {
			siteID, err := strconv.ParseInt(rawSite, 10, 64)
			if err != nil || siteID != cred.SiteID() {
				c.Next()
				return
			}
		}
		c.Set(widgetCredentialKey, cred)
		c.Set(widgetPrincipalKey, principal)
		c.Request = c.Request.WithContext(logging.WithAttrs(c.Request.Context(),
			logging.ID("user_id", cred.UserID()),
			logging.ID("site_id", cred.SiteID()),
		))
		c.Next()
	}
}

// checkWidgetCredential 校验凭证的实时 epoch、主体状态与模式角色。
func checkWidgetCredential(c *gin.Context, verifier comment.WidgetCredentialVerifier, settingsReader comment.WidgetSettingsReader, authz PrincipalStore, cred comment.WidgetCredential) (domain.Principal, error) {
	mode, epoch, err := settingsReader.WidgetConfig(c.Request.Context())
	if err != nil {
		c.Error(err)
		return domain.Principal{}, err
	}
	if cred.Epoch() != epoch {
		return domain.Principal{}, domain.ErrCredentialStale
	}
	principal, err := authz.Resolve(c.Request.Context(), cred.UserID())
	if err != nil {
		return domain.Principal{}, err
	}
	if principal.Status != domain.UserStatusActive || !comment.WidgetRoleAllowed(mode, principal.Role) {
		return domain.Principal{}, domain.ErrCredentialMode
	}
	return principal, nil
}

// WidgetCredentialOf 返回当前请求已验证的 widget 凭据。
func WidgetCredentialOf(c *gin.Context) (comment.WidgetCredential, bool) {
	value, ok := c.Get(widgetCredentialKey)
	if !ok {
		return nil, false
	}
	cred, ok := value.(comment.WidgetCredential)
	return cred, ok
}

// WidgetPrincipalOf 返回请求中已解析的 Widget 主体。
func WidgetPrincipalOf(c *gin.Context) (domain.Principal, bool) {
	value, ok := c.Get(widgetPrincipalKey)
	if !ok {
		return domain.Principal{}, false
	}
	principal, ok := value.(domain.Principal)
	return principal, ok
}

// SiteIDFromCredential 从已验证 widget credential 读取站点 id。
func SiteIDFromCredential(c *gin.Context) (int64, bool) {
	cred, ok := WidgetCredentialOf(c)
	if !ok {
		return 0, false
	}
	return cred.SiteID(), true
}

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

// widgetCookieMaxAge 是无法根据 token 过期时间确定 Cookie 大小时使用的上限。
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
		if err := checkWidgetCredential(c, verifier, settingsReader, authz, cred); err != nil {
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
		c.Request = c.Request.WithContext(logging.WithAttrs(c.Request.Context(),
			logging.ID("user_id", cred.UserID()),
			logging.ID("site_id", cred.SiteID()),
		))
		c.Next()
	}
}

// WidgetOptionalResolution 为统一评论创建路由提供可选凭证解析：
// 缺省 Cookie 视为无凭证；present-invalid 或已失效凭证绝不授予 principal，
// 并机会性清除旧 cookie；有效 widget_authenticated 凭证通过实时模式角色矩阵、
// epoch、站点与活跃主体校验后放入请求上下文。该中间件不因缺失凭证而中止，
// 匿名普通邮箱路径由 handler/service 决定放行，管理员邮箱与认证模式失败关闭。
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
			// 无效或已停用的旧凭证（含旧 widget_anonymous）不授予 principal，
			// 机会性清除，不阻塞新的公开评论路径。
			ClearWidgetCookie(c)
			c.Next()
			return
		}
		if err := checkWidgetCredential(c, verifier, settingsReader, authz, cred); err != nil {
			// 有效签名但 epoch/site/活跃主体/实时角色矩阵不满足：不授予 principal，
			// 也不清除（仍可能是其他合法场景的 Cookie）。由 handler 按提交邮箱
			// 决定失败关闭或匿名放行。
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
		c.Request = c.Request.WithContext(logging.WithAttrs(c.Request.Context(),
			logging.ID("user_id", cred.UserID()),
			logging.ID("site_id", cred.SiteID()),
		))
		c.Next()
	}
}

// checkWidgetCredential 校验凭证的实时 epoch、站点绑定、活跃主体与实时模式角色矩阵。
func checkWidgetCredential(c *gin.Context, verifier comment.WidgetCredentialVerifier, settingsReader comment.WidgetSettingsReader, authz PrincipalStore, cred comment.WidgetCredential) error {
	mode, epoch, err := settingsReader.WidgetConfig(c.Request.Context())
	if err != nil {
		c.Error(err)
		return err
	}
	if cred.Epoch() != epoch {
		return domain.ErrCredentialStale
	}
	principal, err := authz.Resolve(c.Request.Context(), cred.UserID())
	if err != nil {
		return err
	}
	if principal.Status != domain.UserStatusActive || !comment.WidgetRoleAllowed(mode, principal.Role) {
		return domain.ErrCredentialMode
	}
	return nil
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

// SiteIDFromCredential 从已验证 widget credential 读取站点 id。
func SiteIDFromCredential(c *gin.Context) (int64, bool) {
	cred, ok := WidgetCredentialOf(c)
	if !ok {
		return 0, false
	}
	return cred.SiteID(), true
}

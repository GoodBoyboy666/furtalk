package httpx

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"furtalk/internal/platform/urlx"
)

// CORSForSiteParam 路由注册时显式选择的 CORS 策略。
func CORSForSiteParam(param string, origins OriginsProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, ok := siteIDFromParam(c, param)
		if !ok {
			rejectPreflight(c)
			c.Next()
			return
		}
		c.Header("Vary", "Origin")

		origin, ok := parseOriginHeader(c.Request)
		if !ok {
			rejectPreflight(c)
			c.Next()
			return
		}
		allowed, err := origins.AllowedOrigins(c.Request.Context(), siteID)
		if err != nil || !containsOrigin(allowed, origin) {
			rejectPreflight(c)
			c.Next()
			return
		}
		allowOrigin(c, origin)
	}
}

// CORSForCredentialContext 路由注册时显式选择的 CORS 策略。
func CORSForCredentialContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Vary", "Origin")

		origin, ok := parseOriginHeader(c.Request)
		if !ok {
			rejectPreflight(c)
			c.Next()
			return
		}
		allowOrigin(c, origin)
	}
}

// RequireAllowedOrigin 在带凭据的副作用路由上重新校验请求 Origin 是否在站点白名单内。
func RequireAllowedOrigin(origins OriginsProvider, siteID func(*gin.Context) (int64, bool)) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := siteID(c)
		if !ok {
			Abort(c, http.StatusForbidden, "forbidden", "origin is not allowed")
			return
		}
		origin := RequestOrigin(c)
		if origin == "" {
			Abort(c, http.StatusForbidden, "forbidden", "origin is not allowed")
			return
		}
		allowed, err := origins.AllowedOrigins(c.Request.Context(), id)
		if err != nil || !containsOrigin(allowed, origin) {
			Abort(c, http.StatusForbidden, "forbidden", "origin is not allowed")
			return
		}
		c.Next()
	}
}

// SiteIDFromParam 从路由参数解析站点 id，供 RequireAllowedOrigin 使用。
func SiteIDFromParam(param string) func(*gin.Context) (int64, bool) {
	return func(c *gin.Context) (int64, bool) {
		return siteIDFromParam(c, param)
	}
}

// siteIDFromParam 从路由参数解析正数站点 ID。
func siteIDFromParam(c *gin.Context, param string) (int64, bool) {
	raw := c.Param(param)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// allowOrigin 设置精确的 allow-origin 头并处理预检。
func allowOrigin(c *gin.Context, origin string) {
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Credentials", "true")
	if c.Request.Method != http.MethodOptions {
		c.Next()
		return
	}
	c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	if requested := c.Request.Header.Get("Access-Control-Request-Headers"); requested != "" {
		c.Header("Access-Control-Allow-Headers", requested)
	} else {
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, Idempotency-Key")
	}
	c.Header("Access-Control-Max-Age", "600")
	c.AbortWithStatus(http.StatusNoContent)
}

// rejectPreflight 中止一个非法的预检请求。
func rejectPreflight(c *gin.Context) {
	if c.Request.Method != http.MethodOptions {
		return
	}
	c.AbortWithStatusJSON(http.StatusForbidden, Response(c, "cors_origin_not_allowed", "origin is not allowed"))
}

// CanonicalOrigin 验证并格式化单个精确 Origin 值。
func CanonicalOrigin(raw string) (string, bool) {
	if raw == "null" {
		return "", false
	}
	origin, err := urlx.CanonicalOrigin(raw)
	if err != nil {
		return "", false
	}
	return origin, true
}

// parseOriginHeader 使用 CanonicalOrigin 验证单个精确 Origin 值。
func parseOriginHeader(r *http.Request) (string, bool) {
	values := r.Header.Values("Origin")
	if len(values) != 1 {
		return "", false
	}
	return CanonicalOrigin(values[0])
}

// RequestOrigin 返回请求中结构合法的精确 Origin，缺失或无效时返回空字符串。
func RequestOrigin(c *gin.Context) string {
	origin, ok := parseOriginHeader(c.Request)
	if !ok {
		return ""
	}
	return origin
}

// containsOrigin 判断白名单是否包含精确 Origin。
func containsOrigin(allowed []string, origin string) bool {
	for _, candidate := range allowed {
		if candidate == origin {
			return true
		}
	}
	return false
}

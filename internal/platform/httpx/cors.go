package httpx

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSForSiteParam 路由注册时显式选择的 CORS 策略。
// 站点 id 位于路由参数中，中间件按参数解析站点，并对照其精确 origin 白名单。
// 仅当请求 Origin 与站点存储的某个规范 origin 字节级完全一致且站点处于活跃状态时，
// 才授予携带凭据的 CORS 头；每个 CORS 响应都设置 Vary: Origin。
// 预检（OPTIONS）对允许的 origin 应答 204，否则以 403 拒绝。
// CORS 允许并非授权：带凭据的副作用处理器必须通过 RequireAllowedOrigin 重新校验 Origin。
func CORSForSiteParam(param string, origins OriginsProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, ok := siteIDFromParam(c, param)
		if !ok {
			rejectPreflight(c)
			c.Next()
			return
		}
		c.Header("Vary", "Origin")

		origin, ok := validateOriginHeader(c.Request)
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
// 站点上下文来自 credential 或一次性 code，预检阶段未知，因此预检只按结构应答；
// 精确 Origin 由副作用处理器或服务通过 RequireAllowedOrigin 或服务级白名单重新验证。
func CORSForCredentialContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Vary", "Origin")

		origin, ok := validateOriginHeader(c.Request)
		if !ok {
			rejectPreflight(c)
			c.Next()
			return
		}
		allowOrigin(c, origin)
	}
}

// RequireAllowedOrigin 在带凭据的副作用路由上重新校验请求 Origin 是否在站点白名单内。
// siteID 从路由参数或已解析 credential 中读取；任何失败（缺 Origin、站点缺失、
// 白名单读取错误、非精确匹配）一律以 403 拒绝。
func RequireAllowedOrigin(origins OriginsProvider, siteID func(*gin.Context) (int64, bool)) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := siteID(c)
		if !ok {
			Abort(c, http.StatusForbidden, "forbidden", "origin is not allowed")
			return
		}
		origin := ValidRequestOrigin(c)
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

func siteIDFromParam(c *gin.Context, param string) (int64, bool) {
	raw := c.Param(param)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// allowOrigin 设置精确的 allow-origin 头并处理预检。
// 放行的请求继续进入后续中间件，由 RequireAllowedOrigin 或服务重新验证 Origin。
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
// 放行的请求继续进入 handler，由 handler 重新验证 Origin。
func rejectPreflight(c *gin.Context) {
	if c.Request.Method != http.MethodOptions {
		return
	}
	c.AbortWithStatusJSON(http.StatusForbidden, Response(c, "cors_origin_not_allowed", "origin is not allowed"))
}

// CanonicalOrigin 验证并格式化单个精确 origin 值：
//   - 非空且不是字面量 "null"；
//   - 无空白或逗号（多值走私）；
//   - 无通配符；
//   - scheme 为 https，http localhost 开发场景除外；
//   - 无 userinfo、path、query 或 fragment。
//
// 返回精确的规范 origin，用于与存储的 origins 做字节级比较。
func CanonicalOrigin(raw string) (string, bool) {
	origin := strings.TrimSpace(raw)
	if origin == "" || origin == "null" {
		return "", false
	}
	if strings.ContainsAny(origin, " \t\r\n,") {
		return "", false
	}
	if strings.Contains(origin, "*") {
		return "", false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "", false
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", false
	}
	if u.Scheme != "https" {
		host := strings.ToLower(u.Hostname())
		if u.Scheme != "http" || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
			return "", false
		}
	}
	return origin, true
}

// validateOriginHeader 使用 CanonicalOrigin 验证单个精确 Origin 值。
func validateOriginHeader(r *http.Request) (string, bool) {
	values := r.Header.Values("Origin")
	if len(values) != 1 {
		return "", false
	}
	return CanonicalOrigin(values[0])
}

// ValidRequestOrigin 返回请求中结构合法的精确 Origin，缺失或无效时返回空字符串。
func ValidRequestOrigin(c *gin.Context) string {
	origin, ok := validateOriginHeader(c.Request)
	if !ok {
		return ""
	}
	return origin
}

func containsOrigin(allowed []string, origin string) bool {
	for _, candidate := range allowed {
		if candidate == origin {
			return true
		}
	}
	return false
}

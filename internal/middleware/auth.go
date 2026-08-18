// Package middleware 承载业务鉴权中间件。
// 数据查询一律经 service 搭桥，禁止直接操作 repository；不触碰 GORM。
package middleware

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/logging"
	jwt "furtalk/internal/platform/token"
	"github.com/gin-gonic/gin"
)

// FirstPartyCookieName 是 FP 登录 cookie 的名称。
const FirstPartyCookieName = "__Host-furtalk_session"

// CSRFCookieName 与 CSRFHeaderName 定义无状态双重提交 token 的 HTTP 边界。
const (
	CSRFCookieName  = "__Host-furtalk_csrf"
	CSRFHeaderName  = "X-CSRF-Token"
	csrfTokenLength = 43 // base64.RawURLEncoding of 32 random bytes
)

// gin 上下文键：已验证的 claims 与解析出的 principal。
const (
	claimsKey    = "jwt_claims"
	principalKey = "current_principal"
)

// JWTClaims 从请求上下文取出已验证的 FP claims。
func JWTClaims(c *gin.Context) (*jwt.Claims, bool) {
	value, ok := c.Get(claimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := value.(*jwt.Claims)
	return claims, ok
}

// CurrentPrincipal 从请求上下文取出解析出的 principal。
func CurrentPrincipal(c *gin.Context) (domain.Principal, bool) {
	value, ok := c.Get(principalKey)
	if !ok {
		return domain.Principal{}, false
	}
	principal, ok := value.(domain.Principal)
	return principal, ok
}

// JWTVertifier 是 token 验证的接口边界，由 identity.Signer 实现。
type JWTVertifier interface {
	Parse(raw string, wantAudience, wantKind string) (*jwt.Claims, error)
}

// PrincipalStore 把用户 id 解析为当前的授权数据，由 identity.Service 实现。
type PrincipalStore interface {
	Resolve(ctx context.Context, userID int64) (domain.Principal, error)
}

// UserGate 判断 principal 是否可以使用第一方用户 API。
type UserGate interface {
	RequireUser(ctx context.Context, p domain.Principal) error
}

// AdminGate 判断 principal 是否拥有活跃的管理员角色。
type AdminGate interface {
	RequireAdmin(ctx context.Context, p domain.Principal) error
}

// JWTVerification 解析 FP Cookie，把验证通过的 claims 放入上下文。
func JWTVerification(verifier JWTVertifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if verifier == nil {
			c.Next()
			return
		}
		raw, err := c.Cookie(FirstPartyCookieName)
		if err != nil || raw == "" {
			c.Next()
			return
		}
		claims, err := verifier.Parse(raw, jwt.AudienceFirstParty, jwt.TokenKindFirstParty)
		if err != nil {
			c.Next()
			return
		}
		c.Set(claimsKey, claims)
		c.Next()
	}
}

// PrincipalResolution 对携带已验证 claims 的请求，从 authz 缓存解析当前 principal。
func PrincipalResolution(store PrincipalStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			c.Next()
			return
		}
		claims, ok := JWTClaims(c)
		if !ok {
			c.Next()
			return
		}
		userID, err := claims.UserID()
		if err != nil {
			c.Next()
			return
		}
		principal, err := store.Resolve(c.Request.Context(), userID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				// JWT 有效但主体已不存在（如开发库重建后残留的会话）。
				// 按过期未认证会话处理：清除两枚第一方 Cookie 后继续以匿名身份执行，
				// 公开端点照常运行；受保护端点因缺少 principal 由门禁返回 401。
				clearFirstPartyCookie(c)
				c.Next()
				return
			}
			c.Error(err)
			httpx.Abort(c, http.StatusForbidden, "authorization_unavailable", "authorization is unavailable")
			return
		}
		if !sessionVersionMatches(claims, principal) {
			// 第一方 JWT 的会话代次与当前不一致：缺失版本（部署前签发）、
			// 非正版本或版本已被安全事件递增。按陈旧会话处理，清除 Cookie
			// 后以匿名继续，受保护端点由门禁返回 401。
			clearFirstPartyCookie(c)
			c.Next()
			return
		}
		c.Set(principalKey, principal)
		c.Request = c.Request.WithContext(logging.WithAttrs(c.Request.Context(), logging.ID("user_id", principal.UserID)))
		c.Next()
	}
}

// sessionVersionMatches 判断第一方 JWT 的会话代次是否与当前 principal 一致。
// 缺失（解码为 0）或非正版本一律视为陈旧会话；principal 当前版本必须为正数。
func sessionVersionMatches(claims *jwt.Claims, principal domain.Principal) bool {
	return claims.SessionVersion > 0 && principal.SessionVersion > 0 && claims.SessionVersion == principal.SessionVersion
}

// RequireUser 为第一方用户 API 做授权检查。
func RequireUser(gate UserGate) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := CurrentPrincipal(c)
		if !ok {
			httpx.Abort(c, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		if err := gate.RequireUser(c.Request.Context(), principal); err != nil {
			if errors.Is(err, domain.ErrAnonymousRestricted) {
				clearFirstPartyCookie(c)
				httpx.Abort(c, http.StatusForbidden, "anonymous_mode_restricted", "first-party access is unavailable in anonymous mode")
				return
			}
			httpx.Abort(c, http.StatusForbidden, "forbidden", "insufficient permission")
			return
		}
		c.Next()
	}
}

// RequireAdmin 为管理员 API 做授权检查。
func RequireAdmin(gate AdminGate) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := CurrentPrincipal(c)
		if !ok {
			httpx.Abort(c, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		if err := gate.RequireAdmin(c.Request.Context(), principal); err != nil {
			httpx.Abort(c, http.StatusForbidden, "forbidden", "insufficient permission")
			return
		}
		c.Next()
	}
}

// CSRFProtection 对不安全方法执行无状态双重提交校验。
func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		cookieToken, err := c.Cookie(CSRFCookieName)
		headerToken := c.GetHeader(CSRFHeaderName)
		if err != nil || len(cookieToken) != csrfTokenLength || len(headerToken) != csrfTokenLength ||
			subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
			httpx.Abort(c, http.StatusForbidden, "invalid_csrf_token", "invalid CSRF token")
			return
		}
		c.Next()
	}
}

// SetFirstPartyCookie 按固定属性写入 FP 登录 cookie。
func SetFirstPartyCookie(c *gin.Context, token string, ttl time.Duration) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     FirstPartyCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   cookieMaxAge(ttl),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// SetCSRFCookie 写入可由同源前端读取的 host-only 双重提交 cookie。
func SetCSRFCookie(c *gin.Context, token string, ttl time.Duration) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   cookieMaxAge(ttl),
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}

func cookieMaxAge(ttl time.Duration) int {
	seconds := int(ttl / time.Second)
	if seconds <= 0 {
		return -1
	}
	return seconds
}

// clearFirstPartyCookie 使 FP 登录 cookie 过期。
func clearFirstPartyCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     FirstPartyCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearFirstPartyCookie 使 FP 登录与 CSRF cookie 同时过期，供处理器调用。
func ClearFirstPartyCookie(c *gin.Context) {
	clearFirstPartyCookie(c)
}

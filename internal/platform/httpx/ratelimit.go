package httpx

import (
	"net/http"

	"furtalk/internal/platform/ratelimit"

	"github.com/gin-gonic/gin"
)

// RateLimit 是进程内限流中间件。
// 超过配置容量时返回 429。
func RateLimit(limiter *ratelimit.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limiter == nil {
			c.Next()
			return
		}
		key := c.GetString(ClientIPKey)
		if key == "" {
			key = "unknown"
		}
		if !limiter.Allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, Response(c, "rate_limited", "too many requests"))
			return
		}
		c.Next()
	}
}

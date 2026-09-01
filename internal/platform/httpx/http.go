package httpx

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"furtalk/internal/platform/clientip"
	"furtalk/internal/platform/logging"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const RequestIDKey = "request_id"

const ClientIPKey = "client_ip"

// RequestID 读取或生成 X-Request-ID，同时写入 Gin 上下文与标准 context，
// 并写回响应头，使 AccessLog 与业务日志共享同一关联字段。
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.NewString()
		}
		c.Set(RequestIDKey, requestID)
		c.Header("X-Request-ID", requestID)
		c.Request = c.Request.WithContext(logging.WithAttrs(c.Request.Context(), logging.RequestID(requestID)))
		c.Next()
	}
}

// ClientIP 通过 internal/platform/clientip 中的可信代理逻辑解析有效的客户端 IP。
// 仅当直接对端位于已配置的可信代理 CIDR 内时才采用 X-Forwarded-For；
// RemoteAddr 无法解析时该键留空，下游限流仍能以稳定的未知键工作。
func ClientIP(trustedProxies []string) gin.HandlerFunc {
	trusted, _ := clientip.ParseTrustedCIDRs(trustedProxies)
	return func(c *gin.Context) {
		ip, err := clientip.Extract(c.Request, trusted)
		if err != nil {
			c.Set(ClientIPKey, "")
			c.Next()
			return
		}
		c.Set(ClientIPKey, ip.String())
		c.Next()
	}
}

// SecurityHeaders 设置基础的响应安全头：nosniff、frame DENY 与 no-referrer。
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

// BodyLimit 把请求体限制为 maxBytes，超限由 ErrorWriter 转为 413。
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// AccessLog 记录每个请求的方法、路径、状态码、耗时与请求 ID。
// logger 从当前请求 context 派生，因此能看到后续鉴权中间件追加的关联属性。
func AccessLog(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()
		logger := logging.FromContext(c.Request.Context(), logger)
		logger.InfoContext(c.Request.Context(), "http request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			logging.Duration(time.Since(started)),
		)
	}
}

// Recovery 捕获 panic 并返回 500 内部错误响应。
func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, Response(c, "internal_error", "服务器内部错误"))
		_ = recovered
	})
}

// ErrorWriter 把翻译器挂到上下文，并把未被消费的 c.Error 转为响应。
// 请求体超限（http.MaxBytesError）时返回 413。
func ErrorWriter(translator *Translator) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(translatorContextKey, translator)
		c.Next()
		if len(c.Errors) == 0 || c.Writer.Written() {
			return
		}
		status := http.StatusInternalServerError
		code := "internal_error"
		message := "服务器内部错误"
		var maxBytesError *http.MaxBytesError
		if errors.As(c.Errors.Last().Err, &maxBytesError) {
			status = http.StatusRequestEntityTooLarge
			code = "request_body_too_large"
			message = "请求体过大"
		}
		c.JSON(status, Response(c, code, message))
	}
}

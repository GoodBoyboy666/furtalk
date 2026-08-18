// Package router 是路由层：统一注册路由与中间件。
// 不 import 任何 service；业务中间件与注册函数由组合根注入。
package router

import (
	"errors"
	"log/slog"
	"net/http"

	"furtalk/internal/platform/config"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/ratelimit"
	"github.com/gin-gonic/gin"
)

// Register 定义注册函数签名：挂载一个或多个路由到给定分组。
type Register func(group *gin.RouterGroup)

// New 构建 Gin engine 与全局中间件，并挂载注册函数。
func New(
	isReady func() bool,
	cfg config.HTTPConfig,
	logger *slog.Logger,
	limiter *ratelimit.Limiter,
	translator *httpx.Translator,
	authentication []gin.HandlerFunc,
	registers []Register,
) (*gin.Engine, error) {
	if isReady == nil || logger == nil || limiter == nil || translator == nil {
		return nil, errors.New("router: required infrastructure dependency is nil")
	}
	if len(authentication) == 0 || len(registers) == 0 {
		return nil, errors.New("router: authentication and registers are required")
	}
	for _, handlerFn := range authentication {
		if handlerFn == nil {
			return nil, errors.New("router: authentication middleware is nil")
		}
	}

	r := gin.New()
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, err
	}
	globalMiddleware := []gin.HandlerFunc{
		httpx.RequestID(),
		httpx.ClientIP(cfg.TrustedProxies),
		httpx.Recovery(),
		httpx.AccessLog(logger),
		httpx.SecurityHeaders(),
		httpx.BodyLimit(cfg.BodyLimit),
		httpx.RateLimit(limiter),
	}
	globalMiddleware = append(globalMiddleware, authentication...)
	globalMiddleware = append(globalMiddleware, httpx.ErrorWriter(translator))
	r.Use(globalMiddleware...)

	r.GET("/health/live", healthLive)
	r.GET("/health/ready", healthReady(isReady))

	api := r.Group("/api/v1")
	for _, register := range registers {
		register(api)
	}
	return r, nil
}

// @Summary 存活探针
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string "status=ok"
// @Router /health/live [get]
func healthLive(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// @Summary 就绪探针
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string "status=ready"
// @Failure 503 {object} httpx.ErrorResponse "服务未就绪"
// @Router /health/ready [get]
func healthReady(isReady func() bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isReady() {
			c.JSON(http.StatusServiceUnavailable, httpx.Response(c, "not_ready", "服务未就绪"))
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}
}

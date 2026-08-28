package app

import (
	"log/slog"
	"net/http"

	"furtalk/internal/handler"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/config"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/ratelimit"
	"furtalk/internal/platform/webui"
	"furtalk/internal/router"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
)

// httpModule 供应错误 translator、认证中间件、路由注册函数、
// Gin engine 与 http.Server。
func httpModule() fx.Option {
	return fx.Provide(
		handler.NewTranslator,
		provideAuthMiddleware,
		provideRegisters,
		provideRouter,
		provideHTTPServer,
	)
}

// provideAuthMiddleware 按固定顺序构造全局认证中间件。
func provideAuthMiddleware(s *services) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		middleware.JWTVerification(s.signer),
		middleware.PrincipalResolution(s.identity),
	}
}

// provideRegisters 以固定顺序构造全部路由注册函数，含管理端前缀门控。
func provideRegisters(s *services) ([]router.Register, error) {
	adminMiddleware := middleware.RequireAdmin(s.identity)
	csrfMiddleware := middleware.CSRFProtection()

	registers := []router.Register{
		func(api *gin.RouterGroup) {
			handler.RegisterBootstrap(api, s.bootstrap)
			handler.RegisterNotification(api, s.notifications)
			handler.RegisterCaptchaConfig(api, s.captchaConfig)
			handler.RegisterPublicConfig(api, s.settings)
		},
		func(api *gin.RouterGroup) {
			handler.RegisterAuth(api, s.identity, csrfMiddleware)
			handler.RegisterMe(api, s.identity, s.identity, csrfMiddleware)
		},
		func(api *gin.RouterGroup) {
			handler.RegisterFirstPartyCommentAuthorization(api, s.comment, s.identity, csrfMiddleware)
			handler.RegisterMeComments(api, s.comment, s.identity, csrfMiddleware)
			handler.RegisterWidget(
				api,
				s.comment,
				s.widgetJWTVerifier,
				provideWidgetSettings(s),
				s.identity,
				s.sites,
			)
			handler.RegisterFirstParty(api, s.comment, s.identity, csrfMiddleware)
		},
		func(api *gin.RouterGroup) {
			admin := api.Group("/admin", adminMiddleware, csrfMiddleware)
			handler.RegisterAdminUsers(admin, s.identity)
			handler.RegisterAdminSites(admin, s.sites)
			handler.RegisterAdminComments(admin, s.comment)
			handler.RegisterAdminThreads(admin, s.comment)
			handler.RegisterAdminSettings(admin, s.settings, s.providers)
			handler.RegisterAdminSMTP(admin, s.smtp)
		},
	}
	return registers, nil
}

// provideRouter 构建 Gin engine 与全局中间件。
func provideRouter(
	readiness *readinessState,
	cfg config.HTTPConfig,
	logger *slog.Logger,
	limiter *ratelimit.Limiter,
	translator *httpx.Translator,
	authentication []gin.HandlerFunc,
	registers []router.Register,
	identityService *identity.Service,
	runtimeOptions webRuntimeOptions,
) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	engine, err := router.New(readiness.IsReady, cfg, logger, limiter, translator, authentication, registers)
	if err != nil {
		return nil, err
	}
	// Apple form_post 桥必须注册在 SPA NoRoute 回退之前。
	router.RegisterOAuthCallbackBridge(engine, identityService.CreateOAuthHandoff)
	if !runtimeOptions.Enabled {
		return engine, nil
	}
	assets, err := webui.FS()
	if err != nil {
		return nil, err
	}
	if err := router.RegisterWeb(engine, assets); err != nil {
		return nil, err
	}
	return engine, nil
}

// provideHTTPServer 构造 http.Server。
func provideHTTPServer(cfg config.HTTPConfig, engine *gin.Engine) *http.Server {
	return &http.Server{
		Addr:              cfg.Address,
		Handler:           engine,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
}

package app

import (
	"log/slog"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/eventbus"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/passkey"
	"furtalk/internal/platform/ratelimit"
	"furtalk/internal/service/bootstrap"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"furtalk/internal/service/notification"
	"furtalk/internal/service/setting"
	"furtalk/internal/service/site"
	"go.uber.org/fx"
)

// featureModule 供应跨 feature 适配器、签名器与业务服务。
func featureModule() fx.Option {
	return fx.Provide(
		identity.NewSigner,
		identity.NewOAuthProviderFactory,
		comment.NewWidgetSigner,
		comment.NewWidgetJWTVerifierFromSigner,
		newServices,
		provideIdentityService,
		provideWidgetSettings,
		provideNotificationJob,
		provideCacheMonitorJob,
		provideRateLimitCleanupJob,
	)
}

// services 聚合全部业务服务实例。
type services struct {
	bootstrap     *bootstrap.Service
	settings      *setting.Service
	providers     *setting.ProviderService
	captchaConfig *setting.CaptchaConfigService
	sites         *site.Service
	smtp          *setting.SMTPProbe
	identity      *identity.Service
	comment       *comment.Service
	notifications *notification.Service

	signer            *identity.Signer
	widgetSigner      *comment.WidgetSigner
	widgetJWTVerifier *comment.WidgetJWTVerifier
}

// servicesConfig 是 newServices 的最小装配配置。
type servicesConfig struct {
	ProviderSecretKey []byte
	PublicBaseURL     string
}

// newServices 装配全部业务服务。
func newServices(
	cfg servicesConfig,
	smtpConfig mailer.SMTPConfig,
	repos *repositories,
	store cache.Store,
	bus *eventbus.Bus[domain.CommentEvent],
	logger *slog.Logger,
	readiness *readinessState,
	smtp smtpDelivery,
	templates mailer.TemplateRenderer,
	signer *identity.Signer,
	widgetSigner *comment.WidgetSigner,
	widgetJWTVerifier *comment.WidgetJWTVerifier,
	passkeyAdapter *passkey.Adapter,
	oauthFactory identity.OAuthProviderFactory,
) (*services, error) {
	settingsService := setting.NewService(repos.txRunner, repos.settings)
	providerService := setting.NewProviderService(repos.txRunner, repos.settings, cfg.ProviderSecretKey)
	settingsService.SetCaptchaValidator(providerService)
	providerService.SetSettingsInvalidator(settingsService.Invalidate)
	captchaConfigService := setting.NewCaptchaConfigService(settingsService, providerService)
	sitesService := site.NewService(repos.sites)
	smtpService := setting.NewSMTPProbe(smtpConfig)

	failFast := func(err error) {
		readiness.MarkNotReady()
		logger.Error("fail-fast: authorization cache invalidation failed", logging.Error(err))
	}

	captchaGateway := comment.NewCaptchaGateway(captchaGatewayReader{svc: providerService})

	identityService := identity.NewService(identity.Dependencies{
		TxRunner:       repos.txRunner,
		Users:          repos.users,
		Passkeys:       repos.passkeys,
		Identities:     repos.identities,
		Prefs:          repos.prefs,
		Cache:          store,
		Policy:         policyReader{svc: settingsService},
		CaptchaPolicy:  captchaPolicyReader{svc: settingsService},
		Captcha:        identityCaptchaVerifier{gateway: captchaGateway},
		Providers:      oauthProviderReader{svc: providerService},
		Signer:         signer,
		Mailer:         smtp.Mailer,
		Templates:      templates,
		PasskeyAdapter: passkeyAdapter,
		OAuthFactory:   oauthFactory,
		BaseURL:        cfg.PublicBaseURL,
		FailFast:       failFast,
		Logger:         logger,
	})

	bootstrapService, err := bootstrap.NewService(repos.txRunner, identityService, repos.bootstrap, logger)
	if err != nil {
		return nil, err
	}

	authCodeStore := comment.NewAuthCodeStore(store)
	spamGateway := comment.NewSpamGateway(spamProviderReader{svc: providerService}, logger)
	commentService := comment.NewService(comment.Dependencies{
		TxRunner:  repos.txRunner,
		Threads:   repos.threads,
		Comments:  repos.comments,
		Sites:     repos.sites,
		Users:     repos.users,
		Settings:  commentPolicyReader{svc: settingsService},
		Providers: captchaGatewayReader{svc: providerService},
		UserW:     identityService,
		Captcha:   captchaGateway,
		Authz:     identityService,
		Signer:    widgetSigner,
		Codes:     authCodeStore,
		Verifier:  widgetJWTVerifier,
		Spam:      spamGateway,
		Bus:       bus,
		Logger:    logger,
	})

	notificationsService := notification.NewService(repos.users, repos.comments, repos.threads, repos.prefs, identityService, settingsService, bus, smtp.Mailer, templates, signer, cfg.PublicBaseURL, logger)

	// identity 与 comment 相互引用，清理接线通过 setter 在两侧装配完成后进行。
	identityService.SetCommentDeleter(commentService)

	return &services{
		bootstrap:         bootstrapService,
		settings:          settingsService,
		providers:         providerService,
		captchaConfig:     captchaConfigService,
		sites:             sitesService,
		smtp:              smtpService,
		identity:          identityService,
		comment:           commentService,
		notifications:     notificationsService,
		signer:            signer,
		widgetSigner:      widgetSigner,
		widgetJWTVerifier: widgetJWTVerifier,
	}, nil
}

// provideWidgetSettings 把 setting 策略映射为 widget 凭据中间件所需的配置读取器。
func provideWidgetSettings(s *services) comment.WidgetSettingsReader {
	return comment.NewSettingsReader(commentPolicyReader{svc: s.settings})
}

// provideIdentityService 从聚合服务中暴露 *identity.Service，供路由层注入。
func provideIdentityService(s *services) *identity.Service {
	return s.identity
}

// jobContribution 是后台任务的可选分组贡献。
type jobContribution struct {
	fx.Out
	Jobs []BackgroundJob `group:"backgroundJobs,flatten"`
}

// provideNotificationJob 仅在 SMTP 投递启用时贡献通知消费任务。
func provideNotificationJob(s *services, smtp smtpDelivery) jobContribution {
	if !smtp.Enabled {
		return jobContribution{}
	}
	return jobContribution{Jobs: []BackgroundJob{{Name: "notification-consumer", Run: s.notifications.Run}}}
}

// provideCacheMonitorJob 仅在 Redis 后端时贡献缓存健康监控任务。
func provideCacheMonitorJob(store cache.Store, logger *slog.Logger) jobContribution {
	monitor := cache.NewCacheMonitor(store, logger)
	if monitor == nil {
		return jobContribution{}
	}
	return jobContribution{Jobs: []BackgroundJob{{Name: "cache-monitor", Run: monitor}}}
}

// provideRateLimitCleanupJob 贡献限流器空闲桶后台清理任务。
// 清理循环随 Fx 生命周期启动、取消与等待，应用退出时不泄漏 goroutine。
func provideRateLimitCleanupJob(limiter *ratelimit.Limiter) jobContribution {
	return jobContribution{Jobs: []BackgroundJob{{Name: "rate-limit-cleanup", Run: limiter.CleanupLoop}}}
}

package app

import (
	"log/slog"

	"furtalk/internal/domain"
	"furtalk/internal/handler"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/eventbus"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/passkey"
	"furtalk/internal/platform/ratelimit"
	"furtalk/internal/service/identity"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

// platformModule 注册数据库、缓存、限流、事件总线和邮件等基础设施。
func platformModule() fx.Option {
	return fx.Provide(
		newDatabase,
		newCacheStore,
		newRateLimiter,
		newFlowAdmission,
		newEventBus,
		provideSMTPDelivery,
		provideTemplates,
		passkey.New,
	)
}

// newDatabase 根据配置构建数据库连接。
func newDatabase(cfg database.Config) (*gorm.DB, error) {
	return database.NewDatabase(cfg)
}

// newCacheStore 根据配置构建内存或 Redis 缓存；Redis 启动 PING 失败即中止。
func newCacheStore(cfg cache.Config, logger *slog.Logger) (cache.Store, error) {
	return cache.NewStore(cfg, logger)
}

// newRateLimiter 从限流配置构建令牌桶限流器。
func newRateLimiter(cfg ratelimit.Config) *ratelimit.Limiter {
	return ratelimit.NewFromConfig(cfg)
}

// newFlowAdmission 构建固定流程准入预算的策略注册表。
func newFlowAdmission() *ratelimit.PolicyRegistry {
	return ratelimit.NewPolicyRegistry(defaultFlowPolicies())
}

// defaultFlowPolicies 返回各临时状态流程的默认准入策略。
func defaultFlowPolicies() map[string]ratelimit.Config {
	return map[string]ratelimit.Config{
		handler.PolicyPasskeyLoginOptions:        {Rate: 0.5, Burst: 5},
		handler.PolicyOAuthStart:                 {Rate: 0.2, Burst: 5},
		handler.PolicyOAuthHandoff:               {Rate: 0.5, Burst: 5},
		handler.PolicyPasskeyRegistrationOptions: {Rate: 0.2, Burst: 3},
		handler.PolicyWidgetAuthCode:             {Rate: 1, Burst: 10},
		identity.PolicyPasswordLoginIP:           {Rate: 0.5, Burst: 5},
		identity.PolicyPasswordLoginEmail:        {Rate: 0.2, Burst: 3},
	}
}

// newEventBus 构建业务评论事件的有界、非阻塞进程内事件总线。
func newEventBus(logger *slog.Logger) *eventbus.Bus[domain.CommentEvent] {
	return eventbus.New[domain.CommentEvent](0, logger)
}

// smtpDelivery 携带 SMTP 投递是否启用的标记与可用的 mailer 实现。
// 未配置 SMTP 时 Enabled 为 false，各 feature 按无邮件投递处理。
type smtpDelivery struct {
	Enabled bool
	Mailer  mailer.Mailer
}

// provideSMTPDelivery 根据配置提供 SMTP 投递能力。
func provideSMTPDelivery(cfg mailer.SMTPConfig) (smtpDelivery, error) {
	provider, err := mailer.NewProvider(cfg)
	if err != nil {
		return smtpDelivery{}, err
	}
	return smtpDelivery{Enabled: cfg.Host != "", Mailer: provider}, nil
}

// provideTemplates 加载并校验邮件模板。
func provideTemplates() (mailer.TemplateRenderer, error) {
	return mailer.LoadTemplates("configs/email")
}

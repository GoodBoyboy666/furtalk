package app

import (
	"log/slog"
	"os"
	"time"

	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/config"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/passkey"
	"furtalk/internal/platform/ratelimit"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"go.uber.org/fx"
)

// configurationModule 供应不可变配置与按类型映射的最小配置。
func configurationModule(cfg config.Config) fx.Option {
	return fx.Options(
		fx.Supply(cfg),
		fx.Provide(
			newLogger,
			newReadiness,
			configProjections,
		),
	)
}

// newLogger 构建进程共享的 slog logger，输出格式由配置选择。
func newLogger(cfg config.Config) *slog.Logger {
	return logging.NewWithFormat(os.Stdout, cfg.Logging.Format)
}

// configSections 是 config.Config 拆分出的类型化配置集合。
type configSections struct {
	fx.Out
	HTTP         config.HTTPConfig
	Database     database.Config
	Cache        cache.Config
	RateLimit    ratelimit.Config
	SMTP         mailer.SMTPConfig
	Passkey      passkey.Config
	Signer       identity.SignerConfig
	WidgetSigner comment.WidgetSignerConfig
	OAuthFactory identity.OAuthFactoryConfig
	Services     servicesConfig
}

// configProjections 把不可变的 Config 映射为中央 HTTP section 与各消费者自有的配置值。
func configProjections(cfg config.Config) configSections {
	return configSections{
		HTTP: cfg.HTTP,
		Database: database.Config{
			Dialect:  cfg.Database.Dialect,
			Path:     cfg.Database.Path,
			Host:     cfg.Database.Host,
			Port:     cfg.Database.Port,
			Name:     cfg.Database.Name,
			User:     cfg.Database.User,
			Password: cfg.Database.Password,
			SSLMode:  cfg.Database.SSLMode,
		},
		Cache: cache.Config{
			RedisURL: cfg.Cache.RedisURL,
		},
		RateLimit: ratelimit.Config{
			Rate:  cfg.HTTP.RateLimitRate,
			Burst: cfg.HTTP.RateLimitBurst,
		},
		SMTP: mailer.SMTPConfig{
			Host:     cfg.SMTP.Host,
			Port:     cfg.SMTP.Port,
			From:     cfg.SMTP.From,
			TLS:      cfg.SMTP.TLS,
			Username: cfg.SMTP.Username,
			Password: cfg.SMTP.Password,
			Timeout:  cfg.SMTP.Timeout,
		},
		Passkey: passkey.Config{
			RPID:                cfg.WebAuthn.RPID,
			RPOrigins:           cfg.WebAuthn.RPOrigins,
			RPDisplayName:       cfg.WebAuthn.RPName,
			LoginTimeout:        5 * time.Minute,
			RegistrationTimeout: 5 * time.Minute,
		},
		Signer: identity.SignerConfig{
			Issuer:   cfg.Tokens.JWTIssuer,
			Key:      []byte(cfg.Tokens.JWTKey),
			Lifetime: cfg.Tokens.JWTLifetime,
		},
		WidgetSigner: comment.WidgetSignerConfig{
			Issuer:   cfg.Tokens.JWTIssuer,
			Key:      []byte(cfg.Tokens.JWTKey),
			Lifetime: cfg.Tokens.WidgetJWTLifetime,
		},
		OAuthFactory: identity.OAuthFactoryConfig{
			ClientTimeout: cfg.OAuth.ClientTimeout,
		},
		Services: servicesConfig{
			ProviderSecretKey: []byte(cfg.Tokens.SecretKey),
			PublicBaseURL:     cfg.HTTP.PublicBaseURL,
		},
	}
}

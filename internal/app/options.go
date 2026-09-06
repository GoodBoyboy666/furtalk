// Package app 唯一依赖组装入口与生命周期所有者。
// 生产启动路径由 Uber Fx 对象图构成，配置、platform、repository、
// 业务服务、HTTP 适配层、后台任务与全部资源生命周期都由 *fx.App 管理。
package app

import (
	"log/slog"
	"time"

	"furtalk/internal/platform/config"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

// stopAllowance  HTTP shutdown 超时之外为后台任务/资源关闭预留的清理预算。
const stopAllowance = 5 * time.Second

// New 加载静态配置并构建 Fx 应用。
func New(options ...fx.Option) (*fx.App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return fx.New(Options(cfg, options...)), nil
}

// WithWeb 返回 Web 控制台运行时选项。
func WithWeb(enabled bool) fx.Option {
	return fx.Supply(webRuntimeOptions{Enabled: enabled})
}

type webRuntimeOptions struct {
	Enabled bool
}

// Options 构建完整的 Fx 依赖图。
func Options(cfg config.Config, options ...fx.Option) fx.Option {
	runtimeOptions := fx.Option(fx.Supply(webRuntimeOptions{}))
	if len(options) > 0 {
		runtimeOptions = fx.Options(options...)
	}
	return fx.Options(
		configurationModule(cfg),
		runtimeOptions,
		platformModule(),
		persistenceModule(),
		featureModule(),
		httpModule(),
		runtimeModule(),
		fx.StopTimeout(cfg.HTTP.ShutdownTimeout+stopAllowance),
		fx.WithLogger(func(log *slog.Logger) fxevent.Logger {
			eventLogger := &fxevent.SlogLogger{Logger: log}
			// Fx 框架事件走 debug 级别，生命周期错误仍以 error 级别呈现。
			eventLogger.UseLogLevel(slog.LevelDebug)
			return eventLogger
		}),
	)
}

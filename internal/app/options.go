// Package app 唯一组合根与生命周期所有者。
// 生产启动路径由一套 Uber Fx 对象图构成，配置、platform、repository、
// 业务服务、HTTP 适配层、后台任务与全部资源生命周期都由 *fx.App 管理。
// Fx/Dig 只出现在本包；feature core 保持框架无关。
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

// New 生产启动路径的唯一入口，加载并校验静态配置后构建单一 *fx.App。
// Fx 停止预算来自 HTTP shutdown 超时，配置加载须在节点构造之前完成。
func New(options ...fx.Option) (*fx.App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return fx.New(Options(cfg, options...)), nil
}

// WithWeb 返回启用或关闭内嵌 Web 控制台的运行时选项。
// 该选项只控制路由注册，不改变静态配置或业务服务。
func WithWeb(enabled bool) fx.Option {
	return fx.Supply(webRuntimeOptions{Enabled: enabled})
}

type webRuntimeOptions struct {
	Enabled bool
}

// Options 返回完整的生产 Fx 图，与生产启动路径完全一致。
// 测试通过 fx.ValidateApp 校验同一张图，保证验证结果与生产行为一致。
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

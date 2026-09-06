package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/config"
	"furtalk/internal/platform/eventbus"
	"furtalk/internal/platform/logging"

	"go.uber.org/fx"
	"gorm.io/gorm"
)

// runtimeModule 供应后台任务、致命关闭协调器与唯一的生命周期注册 invoke。
func runtimeModule() fx.Option {
	return fx.Options(
		fx.Provide(
			newFatalCoordinator,
			newDatabaseCleanup,
			newCacheCleanup,
			newBusCleanup,
			newJobSupervisor,
			newHTTPServerLifecycle,
		),
		fx.Invoke(registerLifecycle),
	)
}

// BackgroundJob 描述一个后台任务；任务并发启动且无语义顺序。
type BackgroundJob struct {
	Name string
	Run  func(context.Context) error
}

// fatalCoordinator 幂等处理致命运行时关闭：仅首次调用请求 Fx 关闭，
// 并始终以非零退出码结束。HTTP Serve 与关键后台任务共享同一实例。
type fatalCoordinator struct {
	once       sync.Once
	shutdowner fx.Shutdowner
	readiness  *readinessState
	logger     *slog.Logger
}

// newFatalCoordinator 创建致命错误关闭协调器。
func newFatalCoordinator(shutdowner fx.Shutdowner, readiness *readinessState, logger *slog.Logger) *fatalCoordinator {
	return &fatalCoordinator{shutdowner: shutdowner, readiness: readiness, logger: logger}
}

// Fatal 请求应用以非零退出码关闭并标记为未就绪。
func (f *fatalCoordinator) Fatal(err error) {
	f.once.Do(func() {
		f.readiness.MarkNotReady()
		f.logger.Error("fatal runtime error, shutting down", logging.Error(err))
		if err := f.shutdowner.Shutdown(fx.ExitCode(1)); err != nil {
			f.logger.Error("request application shutdown", logging.Error(err))
		}
	})
}

// databaseCleanup 负责关闭数据库连接池。
// 关闭失败只记录日志并继续，正常信号关闭不会被误判为失败。
type databaseCleanup struct {
	db     *gorm.DB
	logger *slog.Logger
}

// newDatabaseCleanup 创建数据库清理器。
func newDatabaseCleanup(db *gorm.DB, logger *slog.Logger) *databaseCleanup {
	return &databaseCleanup{db: db, logger: logger}
}

// Start  fx.Hook 的空实现，数据库清理在启动阶段无动作。
func (c *databaseCleanup) Start(context.Context) error { return nil }

// Stop 关闭数据库连接池；关闭失败只记录日志并继续。
func (c *databaseCleanup) Stop(ctx context.Context) error {
	if c.db == nil {
		return nil
	}
	sqlDB, err := c.db.DB()
	if err != nil {
		c.logger.Error("close database: access connection pool", logging.Error(err))
		return nil
	}
	if err := sqlDB.Close(); err != nil {
		c.logger.Error("close database", logging.Error(err))
	}
	return nil
}

// cacheCleanup 负责缓存后端的关闭；内存后端无连接，跳过。
type cacheCleanup struct {
	store  cache.Store
	logger *slog.Logger
}

// newCacheCleanup 创建缓存清理器。
func newCacheCleanup(store cache.Store, logger *slog.Logger) *cacheCleanup {
	return &cacheCleanup{store: store, logger: logger}
}

// Start  fx.Hook 的空实现，缓存清理在启动阶段无动作。
func (c *cacheCleanup) Start(context.Context) error { return nil }

// Stop 关闭缓存后端连接；内存后端无连接，直接跳过。
func (c *cacheCleanup) Stop(ctx context.Context) error {
	if closer, ok := c.store.(cache.Close); ok {
		if err := closer.Close(); err != nil {
			c.logger.Error("close cache", logging.Error(err))
		}
	}
	return nil
}

// busCleanup 幂等关闭事件总线；关闭后待处理事件被丢弃。
type busCleanup struct {
	bus *eventbus.Bus[domain.CommentEvent]
}

// newBusCleanup 创建事件总线清理器。
func newBusCleanup(bus *eventbus.Bus[domain.CommentEvent]) *busCleanup {
	return &busCleanup{bus: bus}
}

// Start  fx.Hook 的空实现，事件总线在启动阶段无动作。
func (c *busCleanup) Start(context.Context) error { return nil }

// Stop 幂等关闭事件总线；关闭后待处理事件被丢弃。
func (c *busCleanup) Stop(ctx context.Context) error {
	if c.bus != nil {
		c.bus.Close()
	}
	return nil
}

// jobSupervisor 管理全部后台任务：并发启动、取消与等待，并把
// 非取消错误或意外提前返回视为致命错误。多个任务共享一个可取消上下文。
type jobSupervisor struct {
	jobs   []BackgroundJob
	logger *slog.Logger
	fatal  *fatalCoordinator

	stopping atomic.Bool
	cancel   context.CancelFunc
	done     chan struct{}
}

type jobSupervisorParams struct {
	fx.In
	Jobs   []BackgroundJob `group:"backgroundJobs"`
	Logger *slog.Logger
	Fatal  *fatalCoordinator
}

// newJobSupervisor 创建后台任务监督器。
func newJobSupervisor(params jobSupervisorParams) *jobSupervisor {
	return &jobSupervisor{
		jobs:   params.Jobs,
		logger: params.Logger,
		fatal:  params.Fatal,
	}
}

// Start 并发启动后台任务并协调任务失败时的关闭。
func (s *jobSupervisor) Start(ctx context.Context) error {
	if len(s.jobs) == 0 {
		return nil
	}
	sctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	var wg sync.WaitGroup
	errCh := make(chan error, len(s.jobs))
	for _, job := range s.jobs {
		job := job
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := job.Run(sctx)
			select {
			case <-sctx.Done():
				return
			default:
				if err != nil {
					errCh <- fmt.Errorf("background job %s failed: %w", job.Name, err)
					return
				}
				errCh <- fmt.Errorf("background job %s returned unexpectedly", job.Name)
			}
		}()
	}

	done := make(chan struct{})
	s.done = done
	go func() {
		wg.Wait()
		close(done)
	}()

	go func() {
		select {
		case err := <-errCh:
			if s.stopping.Load() {
				return
			}
			s.fatal.Fatal(err)
			cancel()
		case <-sctx.Done():
		}
	}()
	return nil
}

// Stop 取消所有任务并等待其退出，受 Fx 停止上下文约束。
func (s *jobSupervisor) Stop(ctx context.Context) error {
	if s.cancel == nil || s.done == nil {
		return nil
	}
	s.stopping.Store(true)
	s.cancel()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// httpServerLifecycle 拥有 HTTP listener，负责同步绑定、跟踪 Serve 结果、
// 切换就绪状态与优雅关闭。
type httpServerLifecycle struct {
	server          *http.Server
	cfg             config.Config
	readiness       *readinessState
	logger          *slog.Logger
	fatal           *fatalCoordinator
	shutdownTimeout time.Duration

	listener      net.Listener
	serveFinished chan struct{}
}

// newHTTPServerLifecycle 创建 HTTP 服务生命周期管理器。
func newHTTPServerLifecycle(
	server *http.Server,
	cfg config.Config,
	readiness *readinessState,
	logger *slog.Logger,
	fatal *fatalCoordinator,
) *httpServerLifecycle {
	return &httpServerLifecycle{
		server:          server,
		cfg:             cfg,
		readiness:       readiness,
		logger:          logger,
		fatal:           fatal,
		shutdownTimeout: cfg.HTTP.ShutdownTimeout,
	}
}

// Start 绑定 HTTP 监听器并启动服务。
func (h *httpServerLifecycle) Start(ctx context.Context) error {
	h.logRecommendedDefaultWarnings()
	h.logConfigSummary()
	listener, err := net.Listen("tcp", h.server.Addr)
	if err != nil {
		return fmt.Errorf("bind http listener: %w", err)
	}
	h.listener = listener
	serveFinished := make(chan struct{})
	h.serveFinished = serveFinished
	go func() {
		err := h.server.Serve(listener)
		close(serveFinished)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.fatal.Fatal(fmt.Errorf("http server failed: %w", err))
		}
	}()
	h.readiness.MarkReady()
	return nil
}

// Stop 标记未就绪并优雅停止 HTTP 服务。
func (h *httpServerLifecycle) Stop(ctx context.Context) error {
	h.readiness.MarkNotReady()
	if h.server == nil || h.serveFinished == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, h.shutdownTimeout)
	defer cancel()
	shutdownErr := h.server.Shutdown(shutdownCtx)
	if shutdownErr != nil && !errors.Is(shutdownErr, http.ErrServerClosed) {
		h.logger.Error("graceful http shutdown", logging.Error(shutdownErr))
	}
	if h.listener != nil {
		_ = h.listener.Close()
	}
	select {
	case <-h.serveFinished:
	case <-ctx.Done():
		return ctx.Err()
	}
	if errors.Is(shutdownErr, http.ErrServerClosed) {
		return nil
	}
	return shutdownErr
}

// logRecommendedDefaultWarnings 记录缺失建议配置的安全默认值。
func (h *httpServerLifecycle) logRecommendedDefaultWarnings() {
	for _, w := range h.cfg.Warnings() {
		h.logger.Warn("missing recommended configuration, using default",
			"key", w.Key,
			"default", fmt.Sprint(w.Default),
		)
	}
}

// logConfigSummary 输出非敏感的启动配置摘要。
func (h *httpServerLifecycle) logConfigSummary() {
	cfg := h.cfg
	h.logger.Info("startup configuration", "config", map[string]any{
		"address":          cfg.HTTP.Address,
		"public_base_url":  cfg.HTTP.PublicBaseURL,
		"database_dialect": cfg.Database.Dialect,
		"jwt_algorithm":    cfg.Tokens.JWTAlgorithm,
		"jwt_lifetime":     cfg.Tokens.JWTLifetime.String(),
		"trusted_proxies":  len(cfg.HTTP.TrustedProxies),
		"body_limit":       cfg.HTTP.BodyLimit,
		"redis_configured": cfg.Cache.RedisURL != "",
		"smtp_configured":  cfg.SMTP.Host != "",
	})
}

// registerLifecycle 按关闭依赖顺序注册应用生命周期钩子。
func registerLifecycle(
	lc fx.Lifecycle,
	databaseCleanup *databaseCleanup,
	cacheCleanup *cacheCleanup,
	busCleanup *busCleanup,
	supervisor *jobSupervisor,
	httpServer *httpServerLifecycle,
) {
	lc.Append(fx.Hook{OnStart: databaseCleanup.Start, OnStop: databaseCleanup.Stop})
	lc.Append(fx.Hook{OnStart: cacheCleanup.Start, OnStop: cacheCleanup.Stop})
	lc.Append(fx.Hook{OnStart: busCleanup.Start, OnStop: busCleanup.Stop})
	lc.Append(fx.Hook{OnStart: supervisor.Start, OnStop: supervisor.Stop})
	lc.Append(fx.Hook{OnStart: httpServer.Start, OnStop: httpServer.Stop})
}

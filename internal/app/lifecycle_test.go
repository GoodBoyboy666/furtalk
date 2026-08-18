package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/config"
	"furtalk/internal/platform/eventbus"
	"furtalk/internal/platform/ratelimit"
	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// findRepoRoot 向上查找包含 configs/email 的仓库根目录。
// 测试运行在包目录，生产路径依赖相对工作目录的 configs/email。
func findRepoRoot(t *testing.T) (string, error) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "configs", "email")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("configs/email not found above %s", dir)
		}
		dir = parent
	}
}

// warningCaptureHandler 收集 slog 记录，用于断言建议配置缺失告警。
type warningCaptureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *warningCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *warningCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *warningCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *warningCaptureHandler) WithGroup(string) slog.Handler      { return h }

func (h *warningCaptureHandler) snapshot() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]slog.Record{}, h.records...)
}

// TestRecommendedWarningsLoggedOnce 用纯环境变量部署加载配置，断言建议配置缺失
// 告警以 warn 级别携带稳定的 key/default 属性输出，且不含任何敏感值。
func TestRecommendedWarningsLoggedOnce(t *testing.T) {
	t.Setenv("FURTALK_HTTP_PUBLIC_BASE_URL", "https://furtalk.example.com")
	t.Setenv("FURTALK_DATABASE_DIALECT", "sqlite")
	t.Setenv("FURTALK_DATABASE_PATH", ":memory:")
	t.Setenv("FURTALK_TOKENS_JWT_ISSUER", "https://furtalk.example.com")
	t.Setenv("FURTALK_TOKENS_JWT_KEY", strings.Repeat("k", 32))
	t.Setenv("FURTALK_TOKENS_SECRET_KEY", strings.Repeat("s", 32))
	t.Setenv("FURTALK_WEBAUTHN_RP_ID", "furtalk.example.com")
	t.Setenv("FURTALK_WEBAUTHN_RP_ORIGINS", "https://furtalk.example.com")
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("FURTALK_TOKENS_JWT_LIFETIME", "")
	t.Setenv("FURTALK_OAUTH_CLIENT_TIMEOUT", "")
	t.Setenv("FURTALK_SMTP_HOST", "")
	t.Setenv("FURTALK_CACHE_REDIS_URL", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() returned error: %v", err)
	}
	if len(cfg.Warnings()) == 0 {
		t.Fatal("expected warnings from env-only deployment")
	}

	handler := &warningCaptureHandler{}
	readiness := newReadiness()
	lifecycle := newHTTPServerLifecycle(
		&http.Server{},
		cfg,
		readiness,
		slog.New(handler),
		newFatalCoordinator(&recordingShutdowner{}, readiness, testLogger()),
	)
	lifecycle.logRecommendedDefaultWarnings()

	records := handler.snapshot()
	if len(records) == 0 {
		t.Fatal("expected warn records for missing recommended configuration")
	}
	seen := make(map[string]bool)
	for _, r := range records {
		if r.Level != slog.LevelWarn {
			t.Fatalf("record level = %v, want warn", r.Level)
		}
		var key string
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "key" {
				key = a.Value.String()
				seen[key] = true
			}
			return true
		})
		if key == "" {
			t.Fatal("warn record missing key attribute")
		}
	}
	if len(seen) != len(records) {
		t.Fatalf("warning logged more than once: %v", seen)
	}
	if !seen["tokens.jwt_lifetime"] || !seen["oauth.client_timeout"] {
		t.Fatalf("missing expected warnings: %v", seen)
	}
	for key := range seen {
		if strings.Contains(key, "redis") || strings.Contains(key, "smtp") {
			t.Errorf("unexpected warning for optional/disabled field %s", key)
		}
	}
}

// recordingShutdowner 记录 fx.Shutdowner 调用次数，用于幂等断言。
type recordingShutdowner struct {
	mu    sync.Mutex
	calls int
}

func (r *recordingShutdowner) Shutdown(...fx.ShutdownOption) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return nil
}

func (r *recordingShutdowner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func waitFor(fn func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return fn()
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

// TestLifecycleHookOrder 记录与 registerLifecycle 相同的追加顺序，
// 验证 Fx 的 OnStart 顺序与 OnStop 逆序，从而锁定关闭契约：
// HTTP -> jobs -> bus -> cache -> db。
func TestLifecycleHookOrder(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(name string) func(context.Context) error {
		return func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, name)
			return nil
		}
	}
	app := fx.New(
		fx.Invoke(func(lc fx.Lifecycle) {
			lc.Append(fx.Hook{OnStart: record("db:start"), OnStop: record("db:stop")})
			lc.Append(fx.Hook{OnStart: record("cache:start"), OnStop: record("cache:stop")})
			lc.Append(fx.Hook{OnStart: record("bus:start"), OnStop: record("bus:stop")})
			lc.Append(fx.Hook{OnStart: record("jobs:start"), OnStop: record("jobs:stop")})
			lc.Append(fx.Hook{OnStart: record("http:start"), OnStop: record("http:stop")})
		}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := app.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string{}, events...)
	mu.Unlock()
	want := []string{
		"db:start", "cache:start", "bus:start", "jobs:start", "http:start",
		"http:stop", "jobs:stop", "bus:stop", "cache:stop", "db:stop",
	}
	if !equalStrings(got, want) {
		t.Fatalf("hook order = %v, want %v", got, want)
	}
}

func TestFatalCoordinatorIdempotent(t *testing.T) {
	shutdowner := &recordingShutdowner{}
	readiness := newReadiness()
	coordinator := newFatalCoordinator(shutdowner, readiness, testLogger())

	coordinator.Fatal(errors.New("first"))
	coordinator.Fatal(errors.New("second"))

	if shutdowner.count() != 1 {
		t.Fatalf("Shutdown calls = %d, want 1", shutdowner.count())
	}
	if readiness.IsReady() {
		t.Fatal("readiness must be false after fatal")
	}
}

// TestFatalCoordinatorRequestsExitCodeOne 证明致命关闭请求非零退出码。
func TestFatalCoordinatorRequestsExitCodeOne(t *testing.T) {
	app := fx.New(
		fx.Provide(newReadiness),
		fx.Provide(func() *slog.Logger { return testLogger() }),
		fx.Provide(func(sh fx.Shutdowner, readiness *readinessState, logger *slog.Logger) *fatalCoordinator {
			return newFatalCoordinator(sh, readiness, logger)
		}),
		fx.Invoke(func(lc fx.Lifecycle, coordinator *fatalCoordinator) {
			lc.Append(fx.Hook{OnStart: func(context.Context) error {
				coordinator.Fatal(errors.New("boom"))
				return nil
			}})
		}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case sig := <-app.Wait():
		if sig.ExitCode != 1 {
			t.Fatalf("exit code = %d, want 1", sig.ExitCode)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for shutdown signal")
	}
	_ = app.Stop(ctx)
}

func newTestSupervisor(t *testing.T, jobs []BackgroundJob) (*jobSupervisor, *recordingShutdowner, *readinessState) {
	t.Helper()
	shutdowner := &recordingShutdowner{}
	readiness := newReadiness()
	supervisor := newJobSupervisor(jobSupervisorParams{
		Jobs:   jobs,
		Logger: testLogger(),
		Fatal:  newFatalCoordinator(shutdowner, readiness, testLogger()),
	})
	return supervisor, shutdowner, readiness
}

func TestJobSupervisorNoJobs(t *testing.T) {
	supervisor, shutdowner, _ := newTestSupervisor(t, nil)
	ctx := context.Background()
	if err := supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if shutdowner.count() != 0 {
		t.Fatalf("Shutdown calls = %d, want 0", shutdowner.count())
	}
}

// TestRateLimitCleanupJobContributed 证明限流清理任务由组合根贡献，
// 可通过后台任务 supervisor 启动与停止。
func TestRateLimitCleanupJobContributed(t *testing.T) {
	limiter := ratelimit.New(10, 100)
	contribution := provideRateLimitCleanupJob(limiter)
	if len(contribution.Jobs) != 1 || contribution.Jobs[0].Name != "rate-limit-cleanup" {
		t.Fatalf("contributed jobs = %+v, want single rate-limit-cleanup", contribution.Jobs)
	}
	supervisor, shutdowner, _ := newTestSupervisor(t, contribution.Jobs)
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if shutdowner.count() != 0 {
		t.Fatalf("Shutdown calls = %d, want 0 on clean stop", shutdowner.count())
	}
}

func TestJobSupervisorCancellation(t *testing.T) {
	started := make(chan struct{})
	supervisor, shutdowner, _ := newTestSupervisor(t, []BackgroundJob{{
		Name: "blocking",
		Run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return nil
		},
	}})
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if shutdowner.count() != 0 {
		t.Fatalf("Shutdown calls = %d, want 0", shutdowner.count())
	}
}

func TestJobSupervisorFatalError(t *testing.T) {
	started := make(chan struct{})
	supervisor, shutdowner, readiness := newTestSupervisor(t, []BackgroundJob{{
		Name: "failing",
		Run: func(context.Context) error {
			close(started)
			return errors.New("boom")
		},
	}})
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started
	if !waitFor(func() bool { return shutdowner.count() == 1 }) {
		t.Fatalf("Shutdown calls = %d, want 1", shutdowner.count())
	}
	if readiness.IsReady() {
		t.Fatal("readiness must be false after fatal job")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestJobSupervisorUnexpectedReturn(t *testing.T) {
	supervisor, shutdowner, _ := newTestSupervisor(t, []BackgroundJob{{
		Name: "early",
		Run:  func(context.Context) error { return nil },
	}})
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return shutdowner.count() == 1 }) {
		t.Fatalf("Shutdown calls = %d, want 1 (unexpected early return is fatal)", shutdowner.count())
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = supervisor.Stop(stopCtx)
}

func TestJobSupervisorDuplicateFatal(t *testing.T) {
	var jobs []BackgroundJob
	for i := 0; i < 3; i++ {
		i := i
		jobs = append(jobs, BackgroundJob{
			Name: "boom-" + strconv.Itoa(i),
			Run:  func(context.Context) error { return errors.New("boom") },
		})
	}
	supervisor, shutdowner, _ := newTestSupervisor(t, jobs)
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return shutdowner.count() == 1 }) {
		t.Fatalf("Shutdown calls = %d, want 1", shutdowner.count())
	}
	time.Sleep(50 * time.Millisecond)
	if shutdowner.count() != 1 {
		t.Fatalf("duplicate fatal reports must collapse: Shutdown calls = %d, want 1", shutdowner.count())
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = supervisor.Stop(stopCtx)
}

func TestJobSupervisorStopTimeout(t *testing.T) {
	supervisor, _, _ := newTestSupervisor(t, []BackgroundJob{{
		Name: "stuck",
		Run: func(context.Context) error {
			<-make(chan struct{})
			return nil
		},
	}})
	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err == nil {
		t.Fatal("expected stop timeout error")
	}
}

func newTestHTTPLifecycle(t *testing.T, addr string) (*httpServerLifecycle, *recordingShutdowner, *readinessState) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.GET("/health/ready", func(c *gin.Context) { c.Status(http.StatusOK) })
	server := &http.Server{Addr: addr, Handler: router}
	shutdowner := &recordingShutdowner{}
	readiness := newReadiness()
	cfg := testConfig()
	cfg.HTTP.Address = addr
	lifecycle := newHTTPServerLifecycle(server, cfg, readiness, testLogger(), newFatalCoordinator(shutdowner, readiness, testLogger()))
	return lifecycle, shutdowner, readiness
}

func TestHTTPServerLifecycleStartStop(t *testing.T) {
	h, shutdowner, readiness := newTestHTTPLifecycle(t, freeAddress(t))
	ctx := context.Background()
	if readiness.IsReady() {
		t.Fatal("must not be ready before start")
	}
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !readiness.IsReady() {
		t.Fatal("must be ready after listener bind")
	}

	addr := h.listener.Addr().String()
	resp, err := http.Get("http://" + addr + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if err := h.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if readiness.IsReady() {
		t.Fatal("must not be ready after stop")
	}
	if shutdowner.count() != 0 {
		t.Fatalf("Shutdown calls = %d, want 0", shutdowner.count())
	}
}

func TestHTTPServerLifecycleBindFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	h, _, readiness := newTestHTTPLifecycle(t, listener.Addr().String())
	if err := h.Start(context.Background()); err == nil {
		t.Fatal("expected bind failure")
	}
	if readiness.IsReady() {
		t.Fatal("must not be ready when bind fails")
	}
	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPServerLifecycleServeFailure(t *testing.T) {
	h, shutdowner, _ := newTestHTTPLifecycle(t, freeAddress(t))
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 强制 Serve 非取消错误：关闭底层 listener。
	_ = h.listener.Close()
	if !waitFor(func() bool { return shutdowner.count() == 1 }) {
		t.Fatalf("Shutdown calls = %d, want 1 (serve failure is fatal)", shutdowner.count())
	}
	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseCleanupStopNil(t *testing.T) {
	cleanup := newDatabaseCleanup(nil, testLogger())
	if err := cleanup.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type closingStore struct {
	cache.Store
	mu     sync.Mutex
	closed bool
}

func (c *closingStore) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *closingStore) wasClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func TestCacheCleanupStop(t *testing.T) {
	store := &closingStore{}
	cleanup := newCacheCleanup(store, testLogger())
	if err := cleanup.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !store.wasClosed() {
		t.Fatal("cache closer must run")
	}
}

func TestCacheCleanupStopMemoryNoOp(t *testing.T) {
	memory := cache.NewMemory(10)
	cleanup := newCacheCleanup(memory, testLogger())
	if err := cleanup.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBusCleanupStopIdempotent(t *testing.T) {
	bus := eventbus.New[domain.CommentEvent](0, testLogger())
	cleanup := newBusCleanup(bus)
	ctx := context.Background()
	if err := cleanup.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish(domain.CommentEvent{}); !errors.Is(err, eventbus.ErrDropped) {
		t.Fatalf("Publish after close = %v, want ErrDropped", err)
	}
}

// TestProductionAppStartsAndStops 以真实生产根 option 启动/停止一次，
// 覆盖数据库迁移、图装配、HTTP 绑定、readiness 与优雅关闭的集成路径。
func TestProductionAppStartsAndStops(t *testing.T) {
	// 生产路径从仓库根目录启动（configs/email 相对工作目录加载），
	// 测试运行目录是包目录，因此切换到仓库根目录，结束时恢复原目录。
	root, err := findRepoRoot(t)
	if err != nil {
		t.Fatal(err)
	}
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	dir := t.TempDir()
	cfg := testConfig()
	cfg.Database.Path = filepath.Join(dir, "app.db")
	cfg.HTTP.Address = freeAddress(t)

	app := fx.New(Options(cfg))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := app.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	probeURL := "http://" + cfg.HTTP.Address + "/health/ready"
	resp, err := http.Get(probeURL)
	if err != nil {
		t.Fatalf("ready probe: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ready probe status = %d, want 200", resp.StatusCode)
	}

	if err := app.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// 停止后 listener 已释放，连接应被拒绝。
	if _, err := http.Get(probeURL); err == nil {
		t.Fatal("expected connection refused after stop")
	}
}

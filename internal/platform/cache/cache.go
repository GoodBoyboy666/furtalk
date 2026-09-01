// Package cache 提供邮箱验证码、OAuth 状态与授权查询的临时缓存。
// 支持两种可互换的实现：进程内的有限 TTL 存储与基于 Redis 的存储。
// 配置 Redis 后依赖 Redis，
// 运行时错误按致命错误处理。
package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"furtalk/internal/platform/logging"

	"github.com/redis/go-redis/v9"
)

var (
	// ErrNotFound 键不存在或已过期。
	ErrNotFound = errors.New("cache: key not found")
	// ErrCapacity 内存存储达到上限无法写入新键。
	ErrCapacity = errors.New("cache: capacity exceeded")
)

const (
	// EmailCodeConsumed 提交的摘要匹配且记录已被原子删除。
	EmailCodeConsumed EmailCodeVerifyResult = iota
	// EmailCodeAttempted 摘要不匹配，失败次数已原子递增。
	EmailCodeAttempted
	// EmailCodeInvalid 记录缺失、已过期或达到失败上限，记录已删除。
	EmailCodeInvalid
)

// pingTimeout 单次 Redis PING 超时时间。
const pingTimeout = 5 * time.Second

// healthInterval Redis 运行时健康探测的运行间隔。
const healthInterval = 30 * time.Second

// EmailCodeRecord 邮箱验证码记录。
type EmailCodeRecord struct {
	Hash      string    `json:"hash"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// EmailCodeVerifyResult 原子验证的三种结果。
type EmailCodeVerifyResult int

// AtomicEmailCodeVerifier 原子验证邮箱验证码。
type AtomicEmailCodeVerifier interface {
	// AtomicEmailCodeVerify 原子验证 email-code 记录：
	AtomicEmailCodeVerify(ctx context.Context, key, submittedHash string, maxAttempts int) (EmailCodeVerifyResult, error)
}

// Store 内存与 Redis 共享的临时存储接口。
type Store interface {
	// Get 检索一个键并解码到 out 中。键缺失或已过期时返回 ErrNotFound。
	Get(ctx context.Context, key string, out any) error
	// Set 以给定 TTL 将 value 存储到 key 下。
	Set(ctx context.Context, key string, value any, ttl time.Duration) error
	// Delete 删除一个键，键不存在时不返回错误。
	Delete(ctx context.Context, key string) error
	// AtomicConsume 原子读取并移除一个键，返回字符串值。
	AtomicConsume(ctx context.Context, key string) (string, error)
	// GetOrLoad 获取 key，未命中时执行 load()，
	GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error
}

type Close interface {
	Close() error
}

// Config 是缓存需要的静态配置。
type Config struct {
	RedisURL string
}

// NewStore 根据配置构建临时存储。
// 未配置 Redis 时返回内存存储。
func NewStore(cfg Config, logger *slog.Logger) (Store, error) {
	logger = logging.Normalize(logger)
	if cfg.RedisURL == "" {
		return NewMemory(DefaultMemoryLimit), nil
	}
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opts)
	store := NewRedis(client)
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := store.Ping(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis unavailable at startup: %w", err)
	}
	logger.Info("cache backend", "backend", "redis")
	return store, nil
}

// NewCacheMonitor 周期性探测 Redis 存储。
// 探测失败时返回错误，由应用监督器触发快速失败。
// 内存存储返回 nil，不运行监控。
func NewCacheMonitor(store Store, logger *slog.Logger) func(context.Context) error {
	return NewCacheMonitorWithInterval(store, logger, healthInterval)
}

// NewCacheMonitorWithInterval 以自定义间隔构建 Redis 健康探测函数，供测试使用。
func NewCacheMonitorWithInterval(store Store, logger *slog.Logger, interval time.Duration) func(context.Context) error {
	redisStore, ok := store.(*Redis)
	if !ok {
		return nil
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				pingCtx, cancel := context.WithTimeout(context.Background(), pingTimeout)
				err := redisStore.Ping(pingCtx)
				cancel()
				if err != nil {
					logger.Error("redis health check failed, triggering fail-fast", logging.Error(err))
					return fmt.Errorf("redis health check failed: %w", err)
				}
			}
		}
	}
}

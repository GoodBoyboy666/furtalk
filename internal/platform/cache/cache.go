// Package cache 提供邮箱验证码、OAuth 状态与授权查询的临时存储抽象。
// 支持两种可互换的实现：进程内的有界 TTL 存储与基于 Redis 的存储。
// 配置 Redis 后属硬依赖：启动期 PING 失败即中止启动，
// 运行时错误按致命错误处理，不会静默回退到内存。
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
	// ErrNotFound 在键不存在或已过期时由 Get/AtomicConsume 返回。
	ErrNotFound = errors.New("cache: key not found")
	// ErrCapacity 在内存存储达到上限无法写入新键时返回。
	ErrCapacity = errors.New("cache: capacity exceeded")
)

// EmailCodeRecord 是邮箱验证码在临时存储中的记录形态。
// 明文验证码从不存储，只保留其 SHA-256 摘要、失败次数与过期时间。
type EmailCodeRecord struct {
	Hash      string    `json:"hash"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// EmailCodeVerifyResult 表示一次原子验证的三种结果。
type EmailCodeVerifyResult int

const (
	// EmailCodeConsumed 表示提交的摘要匹配且记录已被原子删除，调用方可继续。
	EmailCodeConsumed EmailCodeVerifyResult = iota
	// EmailCodeAttempted 表示摘要不匹配，失败次数已原子递增。
	EmailCodeAttempted
	// EmailCodeInvalid 表示记录缺失、已过期或达到失败上限，记录已删除。
	EmailCodeInvalid
)

// AtomicEmailCodeVerifier 是支持原子验证邮箱验证码的后端边界。
// 内存与 Redis 实现分别在单个临界区 / 单个 Lua 脚本内完成
// 读取、过期与失败次数判断、错误次数更新或正确删除。
type AtomicEmailCodeVerifier interface {
	// AtomicEmailCodeVerify 原子地验证 email-code 记录：
	// 摘要匹配时删除记录并返回 EmailCodeConsumed；摘要不匹配时原子递增失败次数，
	// 达到 maxAttempts 时删除记录并返回 EmailCodeInvalid；缺失或过期记录返回
	// EmailCodeInvalid。并发调用下只有一次正确提交能观察到 EmailCodeConsumed。
	AtomicEmailCodeVerify(ctx context.Context, key, submittedHash string, maxAttempts int) (EmailCodeVerifyResult, error)
}

// Store 是内存与 Redis 实现共享的临时存储接口。
// Set 把值序列化为 JSON 存入，Get 把值反序列化到 out 中。
type Store interface {
	// Get 检索一个键并解码到 out 中。键缺失或已过期时返回 ErrNotFound。
	Get(ctx context.Context, key string, out any) error
	// Set 以给定 TTL 把 value 存储到 key 下。
	Set(ctx context.Context, key string, value any, ttl time.Duration) error
	// Delete 删除一个键，键不存在时也不返回错误。
	Delete(ctx context.Context, key string) error
	// AtomicConsume 原子地读取并移除一个键，返回字符串值。
	// widget 授权码流程通过该方法消费一次性授权码。
	AtomicConsume(ctx context.Context, key string) (string, error)
	// GetOrLoad 获取 key，未命中时在每键 singleflight 下执行 load()，
	// 把结果以 ttl 存储并解码到 out 中。load 出错时直接返回错误，不缓存结果。
	// 授权缓存的未命中回填依赖该方法。
	GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error
}

// Close 由持有连接或后台状态的存储实现。
type Close interface {
	Close() error
}

// pingTimeout 是启动期与运行时健康探测的单次 Redis PING 超时。
const pingTimeout = 5 * time.Second

// Config 是临时存储后端需要的静态配置。
type Config struct {
	RedisURL string
}

// NewStore 根据配置构建临时存储。
// 配置了 Redis 时，启动期 PING 失败会在监听器绑定前中止启动。
// 未配置 Redis 时返回进程内的有界内存存储。
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

// healthInterval 是 Redis 运行时健康探测的运行间隔。
const healthInterval = 30 * time.Second

// NewCacheMonitor 返回周期性探测 Redis 存储的函数。
// 探测失败时返回错误，由应用监督器触发快速失败，不会回退到内存。
// 内存后端返回 nil，不运行监控。
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

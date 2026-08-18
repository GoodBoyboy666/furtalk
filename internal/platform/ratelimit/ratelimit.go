// Package ratelimit 提供进程内令牌桶限流器。
// 计数器仅存于内存，无持久化，无跨进程共享。
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Config 是限流器需要的静态配置。
type Config struct {
	Rate  float64 // 每秒补充的令牌数
	Burst int     // 可累积的最大令牌数
}

// 限流器后台清理参数：空闲淘汰时长与清扫周期。
const (
	idleTimeout   = 10 * time.Minute
	cleanupPeriod = 1 * time.Minute
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter 是每键令牌桶，可安全并发使用。
type Limiter struct {
	rate    float64 // 每秒补充的令牌数
	burst   int     // 可累积的最大令牌数
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

// NewFromConfig 按静态限流配置构建限流器。
func NewFromConfig(cfg Config) *Limiter {
	return New(cfg.Rate, cfg.Burst)
}

// New 构建一个限流器，每秒补充 rate 个令牌，上限为 burst 容量。
// Rate 与 burst 必须为正数。
func New(rate float64, burst int) *Limiter {
	return &Limiter{
		rate:    rate,
		burst:   burst,
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow 报告 key 是否有一个令牌可用。
func (l *Limiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

// AllowN 报告 key 是否有 n 个令牌可用，为 true 时消耗它们。
// n 为零或负数时始终返回 true 且不消耗。
// 请求路径只计算当前桶的令牌，不执行任何全表扫描。
func (l *Limiter) AllowN(key string, n int) bool {
	if n <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(l.burst), last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > float64(l.burst) {
			b.tokens = float64(l.burst)
		}
		b.last = now
	}
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// BucketCount 返回当前桶数量，仅供测试与观测。
func (l *Limiter) BucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// CleanupLoop 周期清理空闲超过 idleTimeout 的桶，直到 ctx 取消。
// 由调用方作为受托管后台任务运行；ctx 取消后立即返回，不泄漏 goroutine。
func (l *Limiter) CleanupLoop(ctx context.Context) error {
	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			l.sweep(l.now())
		}
	}
}

// sweep 丢弃空闲超过 idleTimeout 的桶，以限制内存使用。
func (l *Limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.buckets {
		if now.Sub(b.last) > idleTimeout {
			delete(l.buckets, key)
		}
	}
}

// Package ratelimit 提供进程内令牌桶限流器。
package ratelimit

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config 限流器需要的静态配置。
type Config struct {
	Rate  float64 // 每秒补充的令牌数
	Burst int     // 可累积的最大令牌数
}

// 应用中固定流量准入策略的名称。使用字符串类型，处理函数可以声明式地选择策略，而无需引入应用配置。
const (
	PolicyPasskeyLoginOptions        = "passkey_login_options"
	PolicyOAuthStart                 = "oauth_start"
	PolicyOAuthHandoff               = "oauth_handoff"
	PolicyPasskeyRegistrationOptions = "passkey_registration_options"
	PolicyWidgetAuthCode             = "widget_auth_code"
	PolicyPasswordLoginIP            = "password_login_ip"
	PolicyPasswordLoginEmail         = "password_login_email"

	// 保留这些短别名，供偏好流程命名的调用方使用。
	PasskeyLoginOptionsPolicy        = PolicyPasskeyLoginOptions
	OAuthStartPolicy                 = PolicyOAuthStart
	OAuthHandoffPolicy               = PolicyOAuthHandoff
	PasskeyRegistrationOptionsPolicy = PolicyPasskeyRegistrationOptions
	WidgetAuthCodePolicy             = PolicyWidgetAuthCode
	PasswordLoginIPPolicy            = PolicyPasswordLoginIP
	PasswordLoginEmailPolicy         = PolicyPasswordLoginEmail
)

// DefaultPolicies 返回各流程的限流预算，以及公开密码登录的专用预算。
// 每次调用都返回全新的 map，避免调用方在构造后改动注册表。
func DefaultPolicies() map[string]Config {
	return map[string]Config{
		PolicyPasskeyLoginOptions:        {Rate: 0.5, Burst: 5},
		PolicyOAuthStart:                 {Rate: 0.2, Burst: 5},
		PolicyOAuthHandoff:               {Rate: 0.5, Burst: 5},
		PolicyPasskeyRegistrationOptions: {Rate: 0.2, Burst: 3},
		PolicyWidgetAuthCode:             {Rate: 1, Burst: 10},
		PolicyPasswordLoginIP:            {Rate: 0.5, Burst: 5},
		PolicyPasswordLoginEmail:         {Rate: 0.2, Burst: 3},
	}
}

const (
	idleTimeout   = 10 * time.Minute
	cleanupPeriod = 1 * time.Minute

	// DefaultBucketCapacity 限制每个限流器保留的 subject 数量。
	DefaultBucketCapacity = 10_000
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter 是每键令牌桶，可安全并发使用。
type Limiter struct {
	rate     float64 // 每秒补充的令牌数
	burst    int     // 可累积的最大令牌数
	capacity int
	mu       sync.Mutex
	buckets  map[string]*bucket
	now      func() time.Time
}

// PolicyRegistry 一组相互独立的令牌桶的不可变集合。
// 每个策略拥有自己的桶，耗尽某个流程的配额不会消耗其他流程的令牌。
// CleanupLoop 是唯一的后台循环，用同一个共享 ticker 轮询清理所有策略。
type PolicyRegistry struct {
	policies map[string]*Limiter
	now      func() time.Time
}

// NewPolicyRegistry 按策略定义构建注册表。rate 或 burst 非正的定义会被跳过，请求这些策略时直接失败（fail closed）。
// 输入 map 会被复制，调用方之后的修改不会影响注册表。
func NewPolicyRegistry(configs map[string]Config) *PolicyRegistry {
	registry := &PolicyRegistry{
		policies: make(map[string]*Limiter, len(configs)),
		now:      time.Now,
	}
	for name, cfg := range configs {
		if strings.TrimSpace(name) == "" || cfg.Rate <= 0 || cfg.Burst <= 0 {
			continue
		}
		registry.policies[name] = NewFromConfig(cfg)
	}
	return registry
}

// NewDefaultPolicyRegistry 构建应用的流程注册表。
func NewDefaultPolicyRegistry() *PolicyRegistry {
	return NewPolicyRegistry(DefaultPolicies())
}

// Allow 报告 subject 在指定策略下是否有一个令牌可用。未知策略一律拒绝（fail closed）。
// 空 subject 会固定落入同一个 unknown 桶，调用方无法通过省略身份来绕过准入。
func (r *PolicyRegistry) Allow(policy, subject string) bool {
	return r.AllowN(policy, subject, 1)
}

// AllowN 是 Limiter.AllowN 在策略注册表上的等价方法。
func (r *PolicyRegistry) AllowN(policy, subject string, n int) bool {
	if n <= 0 {
		return true
	}
	if r == nil {
		return false
	}
	l, ok := r.policies[policy]
	if !ok || l == nil {
		return false
	}
	return l.AllowN(normalizeSubject(subject), n)
}

// Limiter 返回指定名称的限流器，供已经接受底层 Limiter 类型的集成点使用。
// 返回的指针应视为只读配置；其桶的并发访问仍然是安全的。
func (r *PolicyRegistry) Limiter(policy string) *Limiter {
	if r == nil {
		return nil
	}
	return r.policies[policy]
}

// PolicyNames 返回排序后的策略名称，用于诊断与测试。
func (r *PolicyRegistry) PolicyNames() []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.policies))
	for name := range r.policies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// BucketCount 返回单个策略当前持有的桶数量。
func (r *PolicyRegistry) BucketCount(policy string) int {
	if l := r.Limiter(policy); l != nil {
		return l.BucketCount()
	}
	return 0
}

// CleanupLoop 是注册表唯一的托管清理任务。
func (r *PolicyRegistry) CleanupLoop(ctx context.Context) error {
	if r == nil {
		<-ctx.Done()
		return nil
	}
	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := r.now()
			for _, limiter := range r.policies {
				limiter.sweep(now)
			}
		}
	}
}

func normalizeSubject(subject string) string {
	if subject = strings.TrimSpace(subject); subject != "" {
		return subject
	}
	return "unknown"
}

// NewFromConfig 按静态限流配置构建限流器。
func NewFromConfig(cfg Config) *Limiter {
	return New(cfg.Rate, cfg.Burst)
}

// New 构建一个限流器，每秒补充 rate 个令牌，上限为 burst 容量。
// Rate 与 burst 必须为正数。
func New(rate float64, burst int) *Limiter {
	return NewWithCapacity(rate, burst, DefaultBucketCapacity)
}

// NewWithCapacity 构建带显式 subject 容量的限流器，供测试和内部受控场景使用。
func NewWithCapacity(rate float64, burst, capacity int) *Limiter {
	if capacity <= 0 {
		capacity = DefaultBucketCapacity
	}
	return &Limiter{
		rate:     rate,
		burst:    burst,
		capacity: capacity,
		buckets:  make(map[string]*bucket),
		now:      time.Now,
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
	key = normalizeSubject(key)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.capacity {
			return false
		}
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

// Package ratelimit 提供进程内令牌桶限流器。
// 计数器仅存于内存，无持久化，无跨进程共享。
package ratelimit

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config 是限流器需要的静态配置。
type Config struct {
	Rate  float64 // 每秒补充的令牌数
	Burst int     // 可累积的最大令牌数
}

// Names of the fixed flow-admission policies used by the application.  They
// are strings so handlers can keep policy selection declarative without
// importing application configuration.
const (
	PolicyPasskeyLoginOptions        = "passkey_login_options"
	PolicyOAuthStart                 = "oauth_start"
	PolicyOAuthHandoff               = "oauth_handoff"
	PolicyPasskeyRegistrationOptions = "passkey_registration_options"
	PolicyWidgetAuthCode             = "widget_auth_code"
	PolicyPasswordLoginIP            = "password_login_ip"
	PolicyPasswordLoginEmail         = "password_login_email"

	// Short aliases are retained for callers that prefer the flow name.
	PasskeyLoginOptionsPolicy        = PolicyPasskeyLoginOptions
	OAuthStartPolicy                 = PolicyOAuthStart
	OAuthHandoffPolicy               = PolicyOAuthHandoff
	PasskeyRegistrationOptionsPolicy = PolicyPasskeyRegistrationOptions
	WidgetAuthCodePolicy             = PolicyWidgetAuthCode
	PasswordLoginIPPolicy            = PolicyPasswordLoginIP
	PasswordLoginEmailPolicy         = PolicyPasswordLoginEmail
)

// DefaultPolicies returns the F-03 flow budgets plus dedicated public password
// login budgets. It returns a fresh map
// on every call so callers cannot mutate a registry after construction.
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

// 限流器后台清理参数：空闲淘汰时长与清扫周期。
const (
	idleTimeout   = 10 * time.Minute
	cleanupPeriod = 1 * time.Minute

	// DefaultBucketCapacity bounds the subjects retained by every limiter.
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

// PolicyRegistry is an immutable collection of independent token buckets.
// Each policy has its own buckets, so a subject exhausting one flow does not
// consume tokens from another.  CleanupLoop is the only background loop and
// sweeps every policy on one shared ticker.
type PolicyRegistry struct {
	policies map[string]*Limiter
	now      func() time.Time
}

// NewPolicyRegistry builds a registry from policy definitions.  Definitions
// with a non-positive rate or burst are omitted and therefore fail closed when
// requested.  The input map is copied; later caller mutation has no effect.
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

// NewDefaultPolicyRegistry constructs the application F-03 flow registry.
func NewDefaultPolicyRegistry() *PolicyRegistry {
	return NewPolicyRegistry(DefaultPolicies())
}

// Allow reports whether policy has one token available for subject.  Unknown
// policies fail closed. Empty subjects use one stable unknown bucket, so a
// caller cannot bypass admission merely by omitting its identity.
func (r *PolicyRegistry) Allow(policy, subject string) bool {
	return r.AllowN(policy, subject, 1)
}

// AllowN is the policy-registry equivalent of Limiter.AllowN.
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

// Limiter returns the named limiter for integration points that already
// accept the lower-level Limiter type.  The returned pointer must be treated
// as read-only configuration; its buckets remain safe for concurrent use.
func (r *PolicyRegistry) Limiter(policy string) *Limiter {
	if r == nil {
		return nil
	}
	return r.policies[policy]
}

// PolicyNames returns sorted policy names for diagnostics and tests.
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

// BucketCount reports the number of buckets held by one policy.
func (r *PolicyRegistry) BucketCount(policy string) int {
	if l := r.Limiter(policy); l != nil {
		return l.BucketCount()
	}
	return 0
}

// CleanupLoop is the registry's single managed cleanup task.
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

// Package onetime 提供可限次校验并一次性消费的过期凭据存储。
package onetime

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"furtalk/internal/platform/cache"
)

var (
	// ErrAtomicUnsupported 表示一次性存储缺少所需的原子后端能力。
	ErrAtomicUnsupported = errors.New("onetime: backend lacks atomic JSON comparison")
)

// Backend 是 Store 所需的最小存储接口，存储访问必须经过命名空间缓存配额约束。
type Backend interface {
	Set(context.Context, string, any, time.Duration) error
	Delete(context.Context, string) error
	GetRawJSON(context.Context, string) (json.RawMessage, error)
	CompareAndSwapJSON(context.Context, string, json.RawMessage, json.RawMessage) (bool, error)
	CompareAndDeleteJSON(context.Context, string, json.RawMessage) (bool, error)
}

// VerifyResult 表示一次性凭据校验的结果。
type VerifyResult uint8

// 一次性凭据校验结果的固定标识。
const (
	// Consumed 表示摘要匹配且凭据已删除。
	Consumed VerifyResult = iota
	// Attempted 表示摘要不匹配且失败次数已记录。
	Attempted
	// Invalid 表示凭据缺失、过期、格式错误或尝试次数耗尽。
	Invalid
)

// record 是保持 JSON 字段名稳定的内部凭据记录。
type record struct {
	Hash      string    `json:"hash"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store 基于单个缓存后端管理过期且限次的凭据。
type Store struct {
	backend Backend
	now     func() time.Time
}

// New 创建平台适配器或基础设施实例。
func New(backend Backend) (*Store, error) {
	if backend == nil {
		return nil, ErrAtomicUnsupported
	}
	return &Store{backend: backend, now: time.Now}, nil
}

// Issue 保存或替换带 TTL 的一次性凭据摘要。
func (s *Store) Issue(ctx context.Context, key, digest string, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.backend.Set(ctx, key, record{
		Hash:      digest,
		Attempts:  0,
		ExpiresAt: s.now().UTC().Add(ttl),
	}, ttl)
}

// Delete 删除指定的一次性凭据。
func (s *Store) Delete(ctx context.Context, key string) error {
	return s.backend.Delete(ctx, key)
}

// VerifyAndConsume 比较凭据摘要并通过原子操作记录失败或完成消费。
func (s *Store) VerifyAndConsume(ctx context.Context, key, submittedDigest string, maxAttempts int) (VerifyResult, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Invalid, err
		}
		raw, err := s.getRaw(ctx, key)
		if errors.Is(err, cache.ErrNotFound) {
			return Invalid, nil
		}
		if err != nil {
			return Invalid, err
		}

		var current record
		if err := json.Unmarshal(raw, &current); err != nil || !validRecord(current) {
			ok, casErr := s.backend.CompareAndDeleteJSON(ctx, key, raw)
			if casErr != nil {
				return Invalid, casErr
			}
			if ok {
				return Invalid, nil
			}
			continue
		}

		if !s.now().Before(current.ExpiresAt) || current.Attempts >= maxAttempts {
			ok, casErr := s.backend.CompareAndDeleteJSON(ctx, key, raw)
			if casErr != nil {
				return Invalid, casErr
			}
			if ok {
				return Invalid, nil
			}
			continue
		}

		if subtle.ConstantTimeCompare([]byte(current.Hash), []byte(submittedDigest)) == 1 {
			ok, casErr := s.backend.CompareAndDeleteJSON(ctx, key, raw)
			if casErr != nil {
				return Invalid, casErr
			}
			if ok {
				return Consumed, nil
			}
			continue
		}

		current.Attempts++
		if current.Attempts >= maxAttempts {
			ok, casErr := s.backend.CompareAndDeleteJSON(ctx, key, raw)
			if casErr != nil {
				return Invalid, casErr
			}
			if ok {
				return Invalid, nil
			}
			continue
		}
		replacement, marshalErr := json.Marshal(current)
		if marshalErr != nil {
			return Invalid, fmt.Errorf("onetime: encode record: %w", marshalErr)
		}
		ok, casErr := s.backend.CompareAndSwapJSON(ctx, key, raw, replacement)
		if casErr != nil {
			return Invalid, casErr
		}
		if ok {
			return Attempted, nil
		}
	}
}

// getRaw 读取一次性凭据的原始 JSON。
func (s *Store) getRaw(ctx context.Context, key string) (json.RawMessage, error) {
	return s.backend.GetRawJSON(ctx, key)
}

// validRecord 校验一次性凭据记录的必要字段。
func validRecord(value record) bool {
	return value.Hash != "" && value.Attempts >= 0 && !value.ExpiresAt.IsZero()
}

var _ interface {
	Issue(context.Context, string, string, time.Duration) error
	Delete(context.Context, string) error
	VerifyAndConsume(context.Context, string, string, int) (VerifyResult, error)
} = (*Store)(nil)

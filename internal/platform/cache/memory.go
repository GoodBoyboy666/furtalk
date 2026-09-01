package cache

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultMemoryLimit 是内存存储的最大存活条目数。
const DefaultMemoryLimit = 10000

type memoryItem struct {
	data    []byte
	expires time.Time
}

// Memory 是进程内的有界 TTL 存储，可安全并发使用，并惰性淘汰过期条目。
// 存活条目数达到上限时先淘汰过期条目；没有可淘汰的过期条目时，
// 用 ErrCapacity 拒绝新的写入，让使用方安全失败而不是无限增长。
type Memory struct {
	mu         sync.Mutex
	items      map[string]memoryItem
	limit      int
	now        func() time.Time
	group      singleflight.Group
	namespaces map[string]map[string]time.Time
}

// NewMemory 构建一个有界内存存储。limit <= 0 时使用默认值。
func NewMemory(limit int) *Memory {
	if limit <= 0 {
		limit = DefaultMemoryLimit
	}
	return &Memory{
		items:      make(map[string]memoryItem),
		limit:      limit,
		now:        time.Now,
		namespaces: make(map[string]map[string]time.Time),
	}
}

// Get 检索一个键并解码到 out 中，键缺失或已过期时返回 ErrNotFound。
func (s *Memory) Get(ctx context.Context, key string, out any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[key]
	if !ok || !s.now().Before(item.expires) {
		delete(s.items, key)
		s.removeNamespaceMembershipLocked(key)
		return ErrNotFound
	}
	return json.Unmarshal(item.data, out)
}

// Set 将 value 序列化后以 ttl 存储到 key 下。
// 容量已满且没有过期条目可淘汰时返回 ErrCapacity。
func (s *Memory) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if _, exists := s.items[key]; !exists && len(s.items) >= s.limit {
		s.evictExpired(now)
	}
	if _, exists := s.items[key]; !exists && len(s.items) >= s.limit {
		return ErrCapacity
	}
	s.items[key] = memoryItem{data: data, expires: now.Add(ttl)}
	return nil
}

// Delete 删除一个键，键不存在时也不返回错误。
func (s *Memory) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	s.removeNamespaceMembershipLocked(key)
	return nil
}

// AtomicConsume 在单个临界区内读取并移除一个键。
func (s *Memory) AtomicConsume(ctx context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[key]
	if !ok || !s.now().Before(item.expires) {
		delete(s.items, key)
		s.removeNamespaceMembershipLocked(key)
		return "", ErrNotFound
	}
	delete(s.items, key)
	s.removeNamespaceMembershipLocked(key)
	var value string
	if err := json.Unmarshal(item.data, &value); err != nil {
		return "", err
	}
	return value, nil
}

func (s *Memory) evictExpired(now time.Time) {
	for key, item := range s.items {
		if !now.Before(item.expires) {
			delete(s.items, key)
			s.removeNamespaceMembershipLocked(key)
		}
	}
}

// AtomicEmailCodeVerify 在单个临界区内验证并消费邮箱验证码记录。
// 正确提交只消费一次；错误提交的失败次数不会在并发下丢失，
// 达到 maxAttempts 或已过期的记录会被删除。
func (s *Memory) AtomicEmailCodeVerify(ctx context.Context, key, submittedHash string, maxAttempts int) (EmailCodeVerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[key]
	if !ok {
		return EmailCodeInvalid, nil
	}
	var record EmailCodeRecord
	if err := json.Unmarshal(item.data, &record); err != nil {
		delete(s.items, key)
		s.removeNamespaceMembershipLocked(key)
		return EmailCodeInvalid, nil
	}
	if !s.now().Before(record.ExpiresAt) || record.Attempts >= maxAttempts {
		delete(s.items, key)
		s.removeNamespaceMembershipLocked(key)
		return EmailCodeInvalid, nil
	}
	if subtle.ConstantTimeCompare([]byte(record.Hash), []byte(submittedHash)) == 1 {
		delete(s.items, key)
		s.removeNamespaceMembershipLocked(key)
		return EmailCodeConsumed, nil
	}
	record.Attempts++
	if record.Attempts >= maxAttempts {
		delete(s.items, key)
		s.removeNamespaceMembershipLocked(key)
		return EmailCodeInvalid, nil
	}
	updated, err := json.Marshal(record)
	if err != nil {
		return EmailCodeInvalid, nil
	}
	s.items[key] = memoryItem{data: updated, expires: item.expires}
	return EmailCodeAttempted, nil
}

// GetOrLoad 从存储中获取 key，未命中时在每键 singleflight 下执行 load() 并存储结果。
// 授权缓存的未命中回填依赖该方法。load 成功时以给定 TTL 写入 key 下并返回。
func (s *Memory) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	err := s.Get(ctx, key, out)
	if err == nil {
		return nil
	}
	if err != ErrNotFound {
		return err
	}
	value, err, _ := s.group.Do(key, func() (any, error) {
		value, err := load()
		if err != nil {
			return nil, err
		}
		if err := s.Set(ctx, key, value, ttl); err != nil {
			return nil, err
		}
		return value, nil
	})
	if err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

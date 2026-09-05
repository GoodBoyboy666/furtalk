package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultMemoryLimit 内存存储最大存活条目数。
const DefaultMemoryLimit = 10000

type memoryItem struct {
	data    []byte
	expires time.Time
}

// Memory 进程内的有限 TTL 存储，可安全并发使用，并惰性淘汰过期条目。
// 存活条目数达到上限时先淘汰过期条目；没有可淘汰的过期条目时， 用 ErrCapacity 拒绝新写入。
type Memory struct {
	mu         sync.Mutex
	items      map[string]memoryItem
	limit      int
	now        func() time.Time
	group      singleflight.Group
	namespaces map[string]map[string]time.Time
}

// NewMemory 构建一个有限内存存储。limit <= 0 时使用默认值。
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
	if err := ctx.Err(); err != nil {
		return err
	}
	item, ok := s.items[key]
	if !ok || !s.now().Before(item.expires) {
		delete(s.items, key)
		s.removeNamespaceMembershipLocked(key)
		return ErrNotFound
	}
	return json.Unmarshal(item.data, out)
}

// GetRawJSON returns the exact JSON payload stored under key. Unlike Get, it
// does not attempt to validate or decode the payload, allowing higher-level
// protocols to classify malformed records and remove them atomically.
func (s *Memory) GetRawJSON(ctx context.Context, key string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	item, ok := s.items[key]
	if !ok || !s.now().Before(item.expires) {
		if ok {
			delete(s.items, key)
			s.removeNamespaceMembershipLocked(key)
		}
		return nil, ErrNotFound
	}
	return append(json.RawMessage(nil), item.data...), nil
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

// Delete 删除一个键，键不存在时不返回错误。
func (s *Memory) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	s.removeNamespaceMembershipLocked(key)
	return nil
}

// AtomicConsume 原子取并移除一个键。
func (s *Memory) AtomicConsume(ctx context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
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

// CompareAndSwapJSON atomically replaces key when its exact JSON value matches
// expected. The existing expiry is retained and stale or missing keys return
// false without an error.
func (s *Memory) CompareAndSwapJSON(ctx context.Context, key string, expected, replacement json.RawMessage) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	item, ok := s.items[key]
	if !ok || !s.now().Before(item.expires) {
		if ok {
			delete(s.items, key)
			s.removeNamespaceMembershipLocked(key)
		}
		return false, nil
	}
	if !bytes.Equal(item.data, expected) {
		return false, nil
	}
	if !json.Valid(replacement) {
		return false, errors.New("cache: replacement is not valid JSON")
	}
	s.items[key] = memoryItem{data: append([]byte(nil), replacement...), expires: item.expires}
	return true, nil
}

// CompareAndDeleteJSON atomically deletes key when its exact JSON value
// matches expected. Stale, missing, and expired keys return false without an
// error.
func (s *Memory) CompareAndDeleteJSON(ctx context.Context, key string, expected json.RawMessage) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	item, ok := s.items[key]
	if !ok || !s.now().Before(item.expires) {
		if ok {
			delete(s.items, key)
			s.removeNamespaceMembershipLocked(key)
		}
		return false, nil
	}
	if !bytes.Equal(item.data, expected) {
		return false, nil
	}
	delete(s.items, key)
	s.removeNamespaceMembershipLocked(key)
	return true, nil
}

// ensure JSON validation errors are returned before modifying a live entry.
// This is intentionally separate from the cache Store interface so unrelated
// cache implementations do not need to expose a CAS capability.
var _ AtomicJSONComparer = (*Memory)(nil)
var _ RawJSONReader = (*Memory)(nil)

// GetOrLoad 从存储中获取 key，未命中时执行 load() 并存储结果。
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

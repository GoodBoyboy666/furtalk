package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrInvalidNamespace Namespace声明不合法。
var ErrInvalidNamespace = errors.New("cache: invalid namespace")

// ErrInvalidNamespaceTTL Namespace写入时 TTL 不是正数，没有有效的存活时间。
var ErrInvalidNamespaceTTL = errors.New("cache: namespace ttl must be positive")

type namespaceBackend interface {
	namespaceGet(context.Context, string, string, string, any) error
	namespaceGetRawJSON(context.Context, string, string, string) (json.RawMessage, error)
	namespaceSet(context.Context, string, string, string, any, time.Duration, int) error
	namespaceDelete(context.Context, string, string, string) error
	namespaceConsume(context.Context, string, string, string) (string, error)
	namespaceCompareAndSwapJSON(context.Context, string, string, string, json.RawMessage, json.RawMessage) (bool, error)
	namespaceCompareAndDeleteJSON(context.Context, string, string, string, json.RawMessage) (bool, error)
}

// Namespace 一个有容量有限的键Namespace。
type Namespace struct {
	store   Store
	backend namespaceBackend
	name    string
	prefix  string
	limit   int

	mu      sync.Mutex
	members map[string]time.Time
	now     func() time.Time
}

// NewNamespace 构造一个有容量有限的缓存Namespace。
func NewNamespace(store Store, name, prefix string, limit int) *Namespace {
	ns, err := NewNamespaceChecked(store, name, prefix, limit)
	if err != nil {
		return nil
	}
	return ns
}

// NewNamespaceChecked NewNamespace 的返回错误版本，供组装根或其他需要显式处理校验错误的调用方使用。
func NewNamespaceChecked(store Store, name, prefix string, limit int) (*Namespace, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidNamespace)
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: empty name", ErrInvalidNamespace)
	}
	if prefix == "" {
		return nil, fmt.Errorf("%w: empty prefix", ErrInvalidNamespace)
	}
	if limit <= 0 {
		return nil, fmt.Errorf("%w: limit must be positive", ErrInvalidNamespace)
	}
	ns := &Namespace{
		store:   store,
		name:    name,
		prefix:  prefix,
		limit:   limit,
		members: make(map[string]time.Time),
		now:     time.Now,
	}
	if backend, ok := store.(namespaceBackend); ok {
		ns.backend = backend
	}
	return ns, nil
}

// Name 返回Namespace的固定标识符。
func (n *Namespace) Name() string {
	if n == nil {
		return ""
	}
	return n.name
}

// Limit 返回Namespace允许的存活条目数量上限。
func (n *Namespace) Limit() int {
	if n == nil {
		return 0
	}
	return n.limit
}

func (n *Namespace) key(suffix string) string {
	return n.prefix + suffix
}

func (n *Namespace) valid() error {
	if n == nil || n.store == nil || n.name == "" || n.prefix == "" || n.limit <= 0 {
		return ErrInvalidNamespace
	}
	return nil
}

// Get 读取并解码Namespace内的值。
func (n *Namespace) Get(ctx context.Context, suffix string, out any) error {
	if err := n.valid(); err != nil {
		return err
	}
	if n.backend != nil {
		return n.backend.namespaceGet(ctx, n.name, n.prefix, suffix, out)
	}

	key := n.key(suffix)
	err := n.store.Get(ctx, key, out)
	if errors.Is(err, ErrNotFound) {
		n.mu.Lock()
		delete(n.members, key)
		n.mu.Unlock()
	}
	return err
}

// GetRawJSON returns an owned copy of the exact JSON payload under suffix.
// Unlike Get, it does not decode or validate the payload.
func (n *Namespace) GetRawJSON(ctx context.Context, suffix string) (json.RawMessage, error) {
	if err := n.valid(); err != nil {
		return nil, err
	}
	if n.backend != nil {
		return n.backend.namespaceGetRawJSON(ctx, n.name, n.prefix, suffix)
	}
	reader, ok := n.store.(RawJSONReader)
	if !ok {
		return nil, errors.New("cache: namespace backend lacks raw JSON capability")
	}
	raw, err := reader.GetRawJSON(ctx, n.key(suffix))
	if errors.Is(err, ErrNotFound) {
		n.mu.Lock()
		delete(n.members, n.key(suffix))
		n.mu.Unlock()
	}
	if err != nil {
		return nil, err
	}
	return bytes.Clone(raw), nil
}

// Set 在Namespace中写入一个值，Namespace已满时返回 ErrCapacity。
// 覆盖仍然存活的已有键时沿用原来的名额，不会额外占位。
func (n *Namespace) Set(ctx context.Context, suffix string, value any, ttl time.Duration) error {
	if err := n.valid(); err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrInvalidNamespaceTTL
	}
	if n.backend != nil {
		return n.backend.namespaceSet(ctx, n.name, n.prefix, suffix, value, ttl, n.limit)
	}
	return n.setFallback(ctx, suffix, value, ttl)
}

// Delete 删除Namespace内的值，并释放其占用的配额名额。
func (n *Namespace) Delete(ctx context.Context, suffix string) error {
	if err := n.valid(); err != nil {
		return err
	}
	if n.backend != nil {
		return n.backend.namespaceDelete(ctx, n.name, n.prefix, suffix)
	}
	key := n.key(suffix)
	err := n.store.Delete(ctx, key)
	if err == nil {
		n.mu.Lock()
		delete(n.members, key)
		n.mu.Unlock()
	}
	return err
}

// CompareAndSwapJSON atomically replaces a namespace value when its exact JSON
// payload matches expected. The existing expiry and quota slot are retained.
func (n *Namespace) CompareAndSwapJSON(ctx context.Context, suffix string, expected, replacement json.RawMessage) (bool, error) {
	if err := n.valid(); err != nil {
		return false, err
	}
	if n.backend != nil {
		return n.backend.namespaceCompareAndSwapJSON(ctx, n.name, n.prefix, suffix, expected, replacement)
	}
	comparer, ok := n.store.(AtomicJSONComparer)
	if !ok {
		return false, errors.New("cache: namespace backend lacks atomic JSON capability")
	}
	return comparer.CompareAndSwapJSON(ctx, n.key(suffix), expected, replacement)
}

// CompareAndDeleteJSON atomically deletes a namespace value when its exact JSON
// payload matches expected and releases its quota slot.
func (n *Namespace) CompareAndDeleteJSON(ctx context.Context, suffix string, expected json.RawMessage) (bool, error) {
	if err := n.valid(); err != nil {
		return false, err
	}
	if n.backend != nil {
		return n.backend.namespaceCompareAndDeleteJSON(ctx, n.name, n.prefix, suffix, expected)
	}
	comparer, ok := n.store.(AtomicJSONComparer)
	if !ok {
		return false, errors.New("cache: namespace backend lacks atomic JSON capability")
	}
	ok, err := comparer.CompareAndDeleteJSON(ctx, n.key(suffix), expected)
	if ok {
		n.mu.Lock()
		delete(n.members, n.key(suffix))
		n.mu.Unlock()
	}
	return ok, err
}

// AtomicConsume 原子读取并删除Namespace内的值。
func (n *Namespace) AtomicConsume(ctx context.Context, suffix string) (string, error) {
	if err := n.valid(); err != nil {
		return "", err
	}
	if n.backend != nil {
		return n.backend.namespaceConsume(ctx, n.name, n.prefix, suffix)
	}
	key := n.key(suffix)
	value, err := n.store.AtomicConsume(ctx, key)
	if err == nil || errors.Is(err, ErrNotFound) {
		n.mu.Lock()
		delete(n.members, key)
		n.mu.Unlock()
	}
	return value, err
}

func (n *Namespace) setFallback(ctx context.Context, suffix string, value any, ttl time.Duration) error {
	key := n.key(suffix)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cleanupFallbackLocked(n.now())

	_, tracked := n.members[key]
	if !tracked {
		// 包装器可能建立在预先写入过数据的测试 store 之上。此时把仍然存活的已有记录视为覆盖写入，避免占用两个名额。
		var existing json.RawMessage
		err := n.store.Get(ctx, key, &existing)
		if err == nil {
			tracked = true
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	if !tracked && len(n.members) >= n.limit {
		return ErrCapacity
	}
	if err := n.store.Set(ctx, key, value, ttl); err != nil {
		return err
	}
	n.members[key] = n.now().Add(ttl)
	return nil
}

func (n *Namespace) cleanupFallbackLocked(now time.Time) {
	for key, expires := range n.members {
		if !now.Before(expires) {
			delete(n.members, key)
		}
	}
}

// namespaceGet 实现 memory 后端的Namespace读取。
func (s *Memory) namespaceGet(ctx context.Context, _, prefix, suffix string, out any) error {
	return s.Get(ctx, prefix+suffix, out)
}

func (s *Memory) namespaceGetRawJSON(ctx context.Context, _, prefix, suffix string) (json.RawMessage, error) {
	return s.GetRawJSON(ctx, prefix+suffix)
}

// namespaceSet 实现 memory 后端的原子准入与写入。
func (s *Memory) namespaceSet(_ context.Context, name, prefix, suffix string, value any, ttl time.Duration, limit int) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	key := prefix + suffix
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	members := s.namespaces[name]
	if members == nil {
		members = make(map[string]time.Time)
		s.namespaces[name] = members
	}
	for member, expires := range members {
		item, exists := s.items[member]
		if !now.Before(expires) || !exists || !now.Before(item.expires) {
			delete(members, member)
			if exists && !now.Before(item.expires) {
				delete(s.items, member)
			}
		}
	}

	item, exists := s.items[key]
	tracked := false
	if expires, ok := members[key]; ok && now.Before(expires) && exists && now.Before(item.expires) {
		tracked = true
	} else if exists && now.Before(item.expires) {
		// 测试中该键可能已经通过普通 Store 写入过。这里将其视为覆盖写入，而不是再扣一个名额。
		if len(members) >= limit {
			return ErrCapacity
		}
		members[key] = item.expires
		tracked = true
	} else {
		delete(members, key)
		if exists {
			delete(s.items, key)
		}
	}
	if !tracked && len(members) >= limit {
		if len(members) == 0 {
			delete(s.namespaces, name)
		}
		return ErrCapacity
	}
	if !tracked && len(s.items) >= s.limit {
		s.evictExpired(now)
		// evictExpired 在清理过期成员的同时会移除空的Namespace map；发布新成员之前需要把这个Namespace重新挂回去。
		if len(members) == 0 {
			s.namespaces[name] = members
		}
		if len(s.items) >= s.limit {
			if len(members) == 0 {
				delete(s.namespaces, name)
			}
			return ErrCapacity
		}
	}
	expires := now.Add(ttl)
	s.items[key] = memoryItem{data: data, expires: expires}
	members[key] = expires
	return nil
}

func (s *Memory) namespaceDelete(_ context.Context, name, prefix, suffix string) error {
	key := prefix + suffix
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	if members := s.namespaces[name]; members != nil {
		delete(members, key)
		if len(members) == 0 {
			delete(s.namespaces, name)
		}
	}
	return nil
}

func (s *Memory) namespaceConsume(_ context.Context, name, prefix, suffix string) (string, error) {
	key := prefix + suffix
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[key]
	if !ok || !s.now().Before(item.expires) {
		delete(s.items, key)
		if members := s.namespaces[name]; members != nil {
			delete(members, key)
		}
		return "", ErrNotFound
	}
	delete(s.items, key)
	if members := s.namespaces[name]; members != nil {
		delete(members, key)
	}
	var value string
	if err := json.Unmarshal(item.data, &value); err != nil {
		return "", err
	}
	return value, nil
}

func (s *Memory) namespaceCompareAndSwapJSON(ctx context.Context, name, prefix, suffix string, expected, replacement json.RawMessage) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !json.Valid(replacement) {
		return false, errors.New("cache: replacement is not valid JSON")
	}
	key := prefix + suffix
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
	s.items[key] = memoryItem{data: bytes.Clone(replacement), expires: item.expires}
	return true, nil
}

func (s *Memory) namespaceCompareAndDeleteJSON(ctx context.Context, name, prefix, suffix string, expected json.RawMessage) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	key := prefix + suffix
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
	if members := s.namespaces[name]; members != nil {
		delete(members, key)
		if len(members) == 0 {
			delete(s.namespaces, name)
		}
	}
	return true, nil
}

func (s *Memory) removeNamespaceMembershipLocked(key string) {
	for name, members := range s.namespaces {
		delete(members, key)
		if len(members) == 0 {
			delete(s.namespaces, name)
		}
	}
}

// Redis Namespace操作。记录键有意沿用既有的 `<prefix><suffix>` 拼接形式。
func namespaceQuotaKey(name string) string {
	return "furtalk:cache:namespace-quota:" + name
}

func (s *Redis) namespaceGet(ctx context.Context, name, prefix, suffix string, out any) error {
	data, err := s.namespaceRead(ctx, name, prefix, suffix)
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("cache: redis namespace get: %w", err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}
	return nil
}

func (s *Redis) namespaceGetRawJSON(ctx context.Context, name, prefix, suffix string) (json.RawMessage, error) {
	data, err := s.namespaceRead(ctx, name, prefix, suffix)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cache: redis namespace get raw: %w", err)
	}
	return bytes.Clone(data), nil
}

func (s *Redis) namespaceRead(ctx context.Context, name, prefix, suffix string) ([]byte, error) {
	value, err := namespaceGetScript.Run(ctx, s.client, []string{prefix + suffix, namespaceQuotaKey(name)}).Text()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func (s *Redis) namespaceSet(ctx context.Context, name, prefix, suffix string, value any, ttl time.Duration, limit int) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	result, err := namespaceSetScript.Run(ctx, s.client,
		[]string{prefix + suffix, namespaceQuotaKey(name)},
		string(data), limit, ttl.Milliseconds()).Int()
	if err != nil {
		return fmt.Errorf("cache: redis namespace set: %w", err)
	}
	if result == 0 {
		return ErrCapacity
	}
	return nil
}

func (s *Redis) namespaceDelete(ctx context.Context, name, prefix, suffix string) error {
	if err := namespaceDeleteScript.Run(ctx, s.client,
		[]string{prefix + suffix, namespaceQuotaKey(name)}).Err(); err != nil {
		return fmt.Errorf("cache: redis namespace delete: %w", err)
	}
	return nil
}

func (s *Redis) namespaceConsume(ctx context.Context, name, prefix, suffix string) (string, error) {
	value, err := namespaceConsumeScript.Run(ctx, s.client,
		[]string{prefix + suffix, namespaceQuotaKey(name)}).Text()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("cache: redis namespace consume: %w", err)
	}
	var decoded string
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return "", fmt.Errorf("cache: redis namespace consume: decode: %w", err)
	}
	return decoded, nil
}

func (s *Redis) namespaceCompareAndSwapJSON(ctx context.Context, name, prefix, suffix string, expected, replacement json.RawMessage) (bool, error) {
	if !json.Valid(replacement) {
		return false, errors.New("cache: replacement is not valid JSON")
	}
	result, err := namespaceCompareAndSwapJSONScript.Run(ctx, s.client,
		[]string{prefix + suffix, namespaceQuotaKey(name)}, []byte(expected), []byte(replacement)).Int()
	if err != nil {
		return false, fmt.Errorf("cache: redis namespace compare-and-swap json: %w", err)
	}
	return result == 1, nil
}

func (s *Redis) namespaceCompareAndDeleteJSON(ctx context.Context, name, prefix, suffix string, expected json.RawMessage) (bool, error) {
	result, err := namespaceCompareAndDeleteJSONScript.Run(ctx, s.client,
		[]string{prefix + suffix, namespaceQuotaKey(name)}, []byte(expected)).Int()
	if err != nil {
		return false, fmt.Errorf("cache: redis namespace compare-and-delete json: %w", err)
	}
	return result == 1, nil
}

// Redis 脚本把配额成员维护与记录变更放在同一个原子操作中完成。过期成员按 score 清理，请求路径上不会使用 KEYS/SCAN。
var namespaceSetScript = redis.NewScript(`
local nowParts = redis.call("TIME")
local now = tonumber(nowParts[1]) * 1000 + math.floor(tonumber(nowParts[2]) / 1000)
local key = KEYS[1]
local quota = KEYS[2]
redis.call("ZREMRANGEBYSCORE", quota, "-inf", now)
local tracked = redis.call("ZSCORE", quota, key)
local exists = redis.call("EXISTS", key)
if not tracked and exists == 0 then
  if tonumber(redis.call("ZCARD", quota)) >= tonumber(ARGV[2]) then
    return 0
  end
end
local ttl = tonumber(ARGV[3])
redis.call("SET", key, ARGV[1], "PX", ttl)
redis.call("ZADD", quota, now + ttl, key)
return 1
`)

var namespaceGetScript = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if not value then
  redis.call("ZREM", KEYS[2], KEYS[1])
end
return value
`)

var namespaceDeleteScript = redis.NewScript(`
redis.call("DEL", KEYS[1])
redis.call("ZREM", KEYS[2], KEYS[1])
return 1
`)

var namespaceConsumeScript = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if value then
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], KEYS[1])
end
return value
`)

var namespaceCompareAndSwapJSONScript = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if not value then
  redis.call("ZREM", KEYS[2], KEYS[1])
  return 0
end
if value ~= ARGV[1] then
  return 0
end
local pttl = redis.call("PTTL", KEYS[1])
if pttl <= 0 then
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], KEYS[1])
  return 0
end
redis.call("SET", KEYS[1], ARGV[2], "PX", pttl)
return 1
`)

var namespaceCompareAndDeleteJSONScript = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if not value then
  redis.call("ZREM", KEYS[2], KEYS[1])
  return 0
end
if value ~= ARGV[1] then
  return 0
end
redis.call("DEL", KEYS[1])
redis.call("ZREM", KEYS[2], KEYS[1])
return 1
`)

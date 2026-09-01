package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrInvalidNamespace reports an invalid namespace declaration.
var ErrInvalidNamespace = errors.New("cache: invalid namespace")

// ErrInvalidNamespaceTTL reports a namespace write with no live lifetime.
var ErrInvalidNamespaceTTL = errors.New("cache: namespace ttl must be positive")

// namespaceBackend is the atomic boundary used by the production cache
// implementations.  It deliberately stays private: callers should use the
// Namespace adapter rather than depending on a particular cache backend.
type namespaceBackend interface {
	namespaceGet(context.Context, string, string, string, any) error
	namespaceSet(context.Context, string, string, string, any, time.Duration, int) error
	namespaceDelete(context.Context, string, string, string) error
	namespaceConsume(context.Context, string, string, string) (string, error)
}

// Namespace owns a bounded key namespace on top of a Store.  The caller
// supplies only a suffix; the namespace owns its prefix and quota accounting.
// Memory and Redis implement namespaceBackend, making admission and record
// creation one atomic operation in production.  Other Store implementations
// use the small synchronized fallback, which is useful for test doubles.
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

// NewNamespace constructs a bounded cache namespace.  Invalid declarations
// return nil; production declarations are fixed constants and should be
// validated during construction with NewNamespaceChecked when errors need to
// be surfaced by a composition root.
func NewNamespace(store Store, name, prefix string, limit int) *Namespace {
	ns, err := NewNamespaceChecked(store, name, prefix, limit)
	if err != nil {
		return nil
	}
	return ns
}

// NewNamespaceChecked is the error-returning form of NewNamespace for
// composition roots and callers that need explicit validation errors.
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

// Name returns the fixed, non-secret namespace identifier.
func (n *Namespace) Name() string {
	if n == nil {
		return ""
	}
	return n.name
}

// Limit returns the namespace's maximum number of live entries.
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

// Get reads and decodes a namespaced value.
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

// Set admits and writes a namespaced value, returning ErrCapacity when the
// namespace is full.  Replacing an existing live key keeps the same slot.
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

// Delete removes a namespaced value and releases its quota slot.
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

// AtomicConsume reads and removes a namespaced value, releasing its slot in
// the same backend operation.
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
		// A wrapper may be created over a pre-seeded test store.  Treat a live
		// existing record as replacement so it does not consume two slots.
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

// namespaceGet implements the memory backend's namespaced read.  Expiration
// and membership release happen under the same cache mutex as ordinary
// records, so a read racing an admission cannot leave a stale slot behind.
func (s *Memory) namespaceGet(_ context.Context, name, prefix, suffix string, out any) error {
	key := prefix + suffix
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

// namespaceSet implements atomic memory admission and publication.  Namespace
// membership is bounded independently from the ordinary cache map and is
// cleaned only for this namespace on the request path.
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
		// The key may have been seeded through the ordinary Store in a test.
		// Claim it as a replacement rather than charging a second slot.
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
		// evictExpired removes empty namespace maps while releasing expired
		// memberships; reattach this namespace before publishing the new member.
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

func (s *Memory) removeNamespaceMembershipLocked(key string) {
	for name, members := range s.namespaces {
		delete(members, key)
		if len(members) == 0 {
			delete(s.namespaces, name)
		}
	}
}

// Redis namespace operations.  The record key intentionally preserves the
// established `<prefix><suffix>` shape.  The quota key is fixed by namespace
// name and never incorporates request data except as a sorted-set member.
func namespaceQuotaKey(name string) string {
	return "furtalk:cache:namespace-quota:" + name
}

func (s *Redis) namespaceGet(ctx context.Context, name, prefix, suffix string, out any) error {
	value, err := namespaceGetScript.Run(ctx, s.client, []string{prefix + suffix, namespaceQuotaKey(name)}).Text()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("cache: redis namespace get: %w", err)
	}
	if err := json.Unmarshal([]byte(value), out); err != nil {
		return err
	}
	return nil
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

// Redis scripts keep quota membership and record mutation in one atomic
// operation.  Expired members are removed by score; no KEYS/SCAN operation is
// used on the request path.
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

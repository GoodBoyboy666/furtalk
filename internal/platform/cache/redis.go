package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

// Redis 基于 Redis 的临时存储。
type Redis struct {
	client *redis.Client
	group  singleflight.Group
}

// NewRedis 创建并持有由 opts 配置的 Redis client。
func NewRedis(opts *redis.Options) *Redis {
	return NewRedisWithClient(redis.NewClient(opts))
}

// NewRedisWithClient 使用现有的 Redis client 创建存储，并接管其所有权。
// 返回的 Redis 关闭时会关闭传入的 client。
func NewRedisWithClient(client *redis.Client) *Redis {
	return &Redis{client: client}
}

// Ping 验证 Redis 连通性。
func (s *Redis) Ping(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("cache: redis ping: %w", err)
	}
	return nil
}

// Get 检索一个键并解码到 out 中，键缺失或已过期时返回 ErrNotFound。
func (s *Redis) Get(ctx context.Context, key string, out any) error {
	data, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("cache: redis get %q: %w", key, err)
	}
	return json.Unmarshal(data, out)
}

// GetRawJSON returns the exact JSON payload stored under key without decoding
// it, allowing a higher-level protocol to handle malformed records safely.
func (s *Redis) GetRawJSON(ctx context.Context, key string) (json.RawMessage, error) {
	data, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cache: redis get %q: %w", key, err)
	}
	return bytes.Clone(data), nil
}

// Set 将 value 序列化后以 ttl 存储到 key 下。
func (s *Redis) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("cache: redis set %q: %w", key, err)
	}
	return nil
}

// Delete 删除一个键，键不存在时不返回错误。
func (s *Redis) Delete(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("cache: redis del %q: %w", key, err)
	}
	return nil
}

// AtomicConsume 使用 Lua GETDEL 在单个原子操作中读取并移除一个键，
func (s *Redis) AtomicConsume(ctx context.Context, key string) (string, error) {
	value, err := consumeScript.Run(ctx, s.client, []string{key}).Text()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("cache: redis atomic consume %q: %w", key, err)
	}
	var decoded string
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return "", fmt.Errorf("cache: redis atomic consume %q: decode: %w", key, err)
	}
	return decoded, nil
}

// GetOrLoad 在 singleflight 下回填缺失的键。
func (s *Redis) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
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

// Close 关闭底层 Redis 连接。
func (s *Redis) Close() error {
	return s.client.Close()
}

// consumeScript 原子地返回并移除一个键值。
var consumeScript = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if value then
  redis.call("DEL", KEYS[1])
end
return value
`)

// compareAndSwapJSONScript compares the exact stored payload and replaces it
// while preserving the key's remaining TTL. The script deliberately does not
// decode JSON; payload semantics belong to the focused capability using it.
var compareAndSwapJSONScript = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if not value or value ~= ARGV[1] then
  return 0
end
local pttl = redis.call("PTTL", KEYS[1])
if pttl > 0 then
  redis.call("SET", KEYS[1], ARGV[2], "PX", pttl)
  return 1
end
if pttl == -1 then
  redis.call("SET", KEYS[1], ARGV[2])
  return 1
end
redis.call("DEL", KEYS[1])
return 0
`)

// compareAndDeleteJSONScript compares the exact stored payload and deletes it
// in the same Redis operation.
var compareAndDeleteJSONScript = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if not value or value ~= ARGV[1] then
  return 0
end
redis.call("DEL", KEYS[1])
return 1
`)

// CompareAndSwapJSON atomically replaces key when its exact JSON value matches
// expected, preserving the current TTL.
func (s *Redis) CompareAndSwapJSON(ctx context.Context, key string, expected, replacement json.RawMessage) (bool, error) {
	if !json.Valid(replacement) {
		return false, errors.New("cache: replacement is not valid JSON")
	}
	result, err := compareAndSwapJSONScript.Run(ctx, s.client, []string{key}, []byte(expected), []byte(replacement)).Int()
	if err != nil {
		return false, fmt.Errorf("cache: redis compare-and-swap json %q: %w", key, err)
	}
	return result == 1, nil
}

// CompareAndDeleteJSON atomically deletes key when its exact JSON value
// matches expected.
func (s *Redis) CompareAndDeleteJSON(ctx context.Context, key string, expected json.RawMessage) (bool, error) {
	result, err := compareAndDeleteJSONScript.Run(ctx, s.client, []string{key}, []byte(expected)).Int()
	if err != nil {
		return false, fmt.Errorf("cache: redis compare-and-delete json %q: %w", key, err)
	}
	return result == 1, nil
}

var _ AtomicJSONComparer = (*Redis)(nil)
var _ RawJSONReader = (*Redis)(nil)

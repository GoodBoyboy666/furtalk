package cache

import (
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

// NewRedis 包装一个就绪的 redis.Client。连接的生命周期由使用方负责。
func NewRedis(client *redis.Client) *Redis {
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

// GetOrLoad 在进程级 singleflight 下回填缺失的键。
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

// emailCodeVerifyScript 在单个原子操作内验证邮箱验证码记录。
// 过期由键自身 TTL 保证：键在脚本启动时存在即未过期。
var emailCodeVerifyScript = redis.NewScript(`
local value = redis.call("GET", KEYS[1])
if not value then
  return -1
end
local ok, record = pcall(cjson.decode, value)
if not ok then
  redis.call("DEL", KEYS[1])
  return -2
end
if record.attempts >= tonumber(ARGV[2]) then
  redis.call("DEL", KEYS[1])
  return -2
end
if record.hash == ARGV[1] then
  redis.call("DEL", KEYS[1])
  return 0
end
record.attempts = record.attempts + 1
if record.attempts >= tonumber(ARGV[2]) then
  redis.call("DEL", KEYS[1])
  return -2
end
local pttl = redis.call("PTTL", KEYS[1])
if pttl > 0 then
  redis.call("SET", KEYS[1], cjson.encode(record), "PX", pttl)
  return 1
end
redis.call("DEL", KEYS[1])
return -2
`)

// AtomicEmailCodeVerify 使用单个 Lua 脚本原子验证邮箱验证码记录，
func (s *Redis) AtomicEmailCodeVerify(ctx context.Context, key, submittedHash string, maxAttempts int) (EmailCodeVerifyResult, error) {
	result, err := emailCodeVerifyScript.Run(ctx, s.client, []string{key}, submittedHash, maxAttempts).Int()
	if err != nil {
		return EmailCodeInvalid, fmt.Errorf("cache: redis atomic email code verify %q: %w", key, err)
	}
	switch result {
	case 0:
		return EmailCodeConsumed, nil
	case 1:
		return EmailCodeAttempted, nil
	default:
		return EmailCodeInvalid, nil
	}
}

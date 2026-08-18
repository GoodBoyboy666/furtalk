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

// Redis 是基于 Redis 的临时存储。
// 启用后属硬依赖：监听器启动前 Ping 必须成功，
// 运行时错误必须快速失败，不回退到内存。
type Redis struct {
	client *redis.Client
	group  singleflight.Group
}

// NewRedis 包装一个就绪的 redis.Client。连接的生命周期由使用方负责。
func NewRedis(client *redis.Client) *Redis {
	return &Redis{client: client}
}

// Ping 验证 Redis 连通性。启动时 PING 失败必须在 HTTP 监听器绑定前中止启动。
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

// Delete 删除一个键，键不存在时也不返回错误。
func (s *Redis) Delete(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("cache: redis del %q: %w", key, err)
	}
	return nil
}

// AtomicConsume 使用 Lua GETDEL 在单个原子操作中读取并移除一个键，
// 保证并发消费者不会两次观察到相同的值。
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
// singleflight 只作用于当前进程，不跨实例协调，进程内的并发未命中会合并为一次加载。
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
// 返回 0=摘要匹配且记录已删除；1=摘要不匹配且失败次数已递增；
// -1/-2=记录缺失或达到失败上限（记录已删除）。
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

// AtomicEmailCodeVerify 使用单个 Lua 脚本原子地验证邮箱验证码记录，
// 保证并发调用下只有一次正确提交成功，错误提交的失败次数不丢失。
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

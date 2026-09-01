package comment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
)

// authCodeKeyPrefix 是一次性授权码的存储键前缀。
const authCodeKeyPrefix = "authcode:"

var errAuthCodeCapacity = errors.New("comment: widget authorization namespace capacity")

// cacheAuthCodeStore 基于缓存存储实现一次性授权码存取。
// 底层缓存负责 TTL 与原子消费（内存后端互斥，Redis 后端 GETDEL）。
type cacheAuthCodeStore struct {
	cache *cache.Namespace
}

// NewAuthCodeStore 在缓存存储之上构建授权码存取实现。
func NewAuthCodeStore(store cache.Store) AuthCodeStore {
	return cacheAuthCodeStore{cache: cache.NewNamespace(store, "widget_auth_code", authCodeKeyPrefix, 1000)}
}

// SetAuthCode 在缓存中写入一次性授权码记录。
func (a cacheAuthCodeStore) SetAuthCode(ctx context.Context, codeHash string, record AuthCodeRecord, ttl time.Duration) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("comment: encode auth code record: %w", err)
	}
	if err := a.cache.Set(ctx, codeHash, string(data), ttl); err != nil {
		if errors.Is(err, cache.ErrCapacity) {
			return fmt.Errorf("%w: %w", domain.ErrUnavailable, errAuthCodeCapacity)
		}
		return err
	}
	return nil
}

// ConsumeAuthCode 原子消费一次授权码记录。
func (a cacheAuthCodeStore) ConsumeAuthCode(ctx context.Context, codeHash string) (AuthCodeRecord, error) {
	raw, err := a.cache.AtomicConsume(ctx, codeHash)
	if errors.Is(err, cache.ErrNotFound) {
		return AuthCodeRecord{}, domain.ErrInvalidCredentials
	}
	if err != nil {
		return AuthCodeRecord{}, fmt.Errorf("comment: consume auth code: %w", err)
	}
	var record AuthCodeRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return AuthCodeRecord{}, fmt.Errorf("comment: decode auth code record: %w", err)
	}
	return record, nil
}

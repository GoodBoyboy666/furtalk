package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const testEmailCodeKey = "email-code:password_reset:user@example.com"

func TestAtomicEmailCodeContractMemory(t *testing.T) {
	store := NewMemory(DefaultMemoryLimit)
	runAtomicEmailCodeContract(t, store, store)
}

func TestAtomicEmailCodeContractRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	store := NewRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = store.Close() })
	runAtomicEmailCodeContract(t, store, store)
}

// runAtomicEmailCodeContract 运行内存与 Redis 后端共享的邮箱验证码原子契约。
func runAtomicEmailCodeContract(t *testing.T, store Store, atomic AtomicEmailCodeVerifier) {
	t.Helper()
	ctx := context.Background()

	t.Run("correct code is consumed exactly once", func(t *testing.T) {
		seedEmailCode(t, ctx, store, "hash-a", 0, time.Minute)
		result, err := atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash-a", 5)
		if err != nil || result != EmailCodeConsumed {
			t.Fatalf("first verify = %v, %v; want EmailCodeConsumed", result, err)
		}
		result, err = atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash-a", 5)
		if err != nil || result != EmailCodeInvalid {
			t.Fatalf("second verify = %v, %v; want EmailCodeInvalid", result, err)
		}
	})

	t.Run("concurrent correct submissions succeed once", func(t *testing.T) {
		seedEmailCode(t, ctx, store, "hash-b", 0, time.Minute)
		const workers = 32
		results := make(chan EmailCodeVerifyResult, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				result, err := atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash-b", 5)
				if err != nil {
					results <- EmailCodeInvalid
					return
				}
				results <- result
			}()
		}
		wg.Wait()
		close(results)
		consumed := 0
		for result := range results {
			if result == EmailCodeConsumed {
				consumed++
			}
		}
		if consumed != 1 {
			t.Fatalf("concurrent correct consumes = %d, want 1", consumed)
		}
	})

	t.Run("wrong codes count attempts and lock after cap", func(t *testing.T) {
		seedEmailCode(t, ctx, store, "hash-c", 0, time.Minute)
		for i := 0; i < 5; i++ {
			result, err := atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "wrong", 5)
			if err != nil {
				t.Fatalf("wrong attempt %d: unexpected error %v", i, err)
			}
			if i < 4 && result != EmailCodeAttempted {
				t.Fatalf("wrong attempt %d = %v; want EmailCodeAttempted", i, result)
			}
			if i == 4 && result != EmailCodeInvalid {
				t.Fatalf("final wrong attempt = %v; want EmailCodeInvalid", result)
			}
		}
		result, err := atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash-c", 5)
		if err != nil || result != EmailCodeInvalid {
			t.Fatalf("correct code after lock = %v, %v; want EmailCodeInvalid", result, err)
		}
	})

	t.Run("concurrent wrong attempts are not lost", func(t *testing.T) {
		seedEmailCode(t, ctx, store, "hash-d", 0, time.Minute)
		const workers = 24
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "wrong", workers*2)
			}()
		}
		wg.Wait()
		var record EmailCodeRecord
		if err := store.Get(ctx, testEmailCodeKey, &record); err != nil {
			t.Fatalf("record after concurrent wrong attempts: %v", err)
		}
		if record.Attempts != workers {
			t.Fatalf("attempts = %d, want %d", record.Attempts, workers)
		}
		result, err := atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash-d", workers*2)
		if err != nil || result != EmailCodeConsumed {
			t.Fatalf("correct code after concurrent wrong = %v, %v; want consumed", result, err)
		}
	})

	t.Run("reissue replaces the old code", func(t *testing.T) {
		seedEmailCode(t, ctx, store, "hash-old", 0, time.Minute)
		seedEmailCode(t, ctx, store, "hash-new", 0, time.Minute)
		result, err := atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash-old", 5)
		if err != nil {
			t.Fatalf("old code after reissue: unexpected error %v", err)
		}
		if result == EmailCodeConsumed {
			t.Fatalf("old code after reissue consumed; want a wrong-attempt outcome")
		}
		result, err = atomic.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash-new", 5)
		if err != nil || result != EmailCodeConsumed {
			t.Fatalf("new code = %v, %v; want consumed", result, err)
		}
	})

	t.Run("missing record is invalid", func(t *testing.T) {
		result, err := atomic.AtomicEmailCodeVerify(ctx, "email-code:login:nobody@example.com", "hash", 5)
		if err != nil || result != EmailCodeInvalid {
			t.Fatalf("missing record = %v, %v; want invalid", result, err)
		}
	})
}

func TestAtomicEmailCodeExpiryMemory(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemory(DefaultMemoryLimit)
	store.now = func() time.Time { return now }
	ctx := context.Background()
	if err := store.Set(ctx, testEmailCodeKey, EmailCodeRecord{
		Hash:      "hash",
		Attempts:  0,
		ExpiresAt: now.Add(-time.Second),
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	result, err := store.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash", 5)
	if err != nil || result != EmailCodeInvalid {
		t.Fatalf("expired record = %v, %v; want invalid", result, err)
	}
}

func TestAtomicEmailCodeExpiryRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	store := NewRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.Set(ctx, testEmailCodeKey, EmailCodeRecord{
		Hash:      "hash",
		Attempts:  0,
		ExpiresAt: time.Now().Add(time.Minute),
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(2 * time.Minute)
	result, err := store.AtomicEmailCodeVerify(ctx, testEmailCodeKey, "hash", 5)
	if err != nil || result != EmailCodeInvalid {
		t.Fatalf("ttl-expired record = %v, %v; want invalid", result, err)
	}
}

func seedEmailCode(t *testing.T, ctx context.Context, store Store, hash string, attempts int, ttl time.Duration) {
	t.Helper()
	record := EmailCodeRecord{
		Hash:      hash,
		Attempts:  attempts,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	if err := store.Set(ctx, testEmailCodeKey, record, ttl); err != nil {
		t.Fatal(err)
	}
}

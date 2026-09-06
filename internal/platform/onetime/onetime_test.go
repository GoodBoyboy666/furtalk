package onetime

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"furtalk/internal/platform/cache"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var _ Backend = (*cache.Namespace)(nil)

func TestStoreMemoryContract(t *testing.T) {
	backend := cache.NewMemory(cache.DefaultMemoryLimit)
	runStoreContract(t, backend)
}

func TestStoreReadsLegacyJSONRecord(t *testing.T) {
	backend := cache.NewMemory(cache.DefaultMemoryLimit)
	store, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	legacy := record{Hash: "digest", Attempts: 0, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := backend.Set(ctx, "legacy", legacy, time.Minute); err != nil {
		t.Fatal(err)
	}
	result, err := store.VerifyAndConsume(ctx, "legacy", "digest", 3)
	if err != nil || result != Consumed {
		t.Fatalf("legacy verification = %v, %v; want consumed", result, err)
	}
}

func TestStoreCorruptRecordIsInvalidAndRemoved(t *testing.T) {
	backend := cache.NewMemory(cache.DefaultMemoryLimit)
	store, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := backend.Set(ctx, "corrupt", map[string]any{"attempts": "not-an-int"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	result, err := store.VerifyAndConsume(ctx, "corrupt", "digest", 3)
	if err != nil || result != Invalid {
		t.Fatalf("corrupt verification = %v, %v; want invalid", result, err)
	}
	var raw json.RawMessage
	if err := backend.Get(ctx, "corrupt", &raw); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("corrupt record after verify = %v, want ErrNotFound", err)
	}
}

func TestStoreMalformedRawRedisRecordIsInvalidAndRemoved(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	backend := cache.NewRedisWithClient(client)
	t.Cleanup(func() { _ = backend.Close() })
	ctx := context.Background()
	if err := client.Set(ctx, "corrupt", []byte("{not-json"), time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	store, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.VerifyAndConsume(ctx, "corrupt", "digest", 3)
	if err != nil || result != Invalid {
		t.Fatalf("malformed verification = %v, %v; want invalid", result, err)
	}
	if err := client.Get(ctx, "corrupt").Err(); !errors.Is(err, redis.Nil) {
		t.Fatalf("malformed record after verify = %v, want redis.Nil", err)
	}
}

func TestStoreRejectsNilBackend(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrAtomicUnsupported) {
		t.Fatalf("New nil backend = %v, want ErrAtomicUnsupported", err)
	}
}

func TestStoreRedisContract(t *testing.T) {
	mr := miniredis.RunT(t)
	backend := cache.NewRedisWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = backend.Close() })
	runStoreContract(t, backend)
	ctx := context.Background()
	store, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Issue(ctx, "expired", "digest", time.Minute); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(2 * time.Minute)
	result, err := store.VerifyAndConsume(ctx, "expired", "digest", 3)
	if err != nil || result != Invalid {
		t.Fatalf("redis expired verification = %v, %v; want invalid", result, err)
	}
}

func TestStoreNamespaceMemoryContract(t *testing.T) {
	backend := cache.NewNamespace(cache.NewMemory(cache.DefaultMemoryLimit), "email", "email:", 1)
	runStoreContract(t, backend)
}

func TestStoreNamespaceRedisContract(t *testing.T) {
	mr := miniredis.RunT(t)
	redisStore := cache.NewRedisWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = redisStore.Close() })
	backend := cache.NewNamespace(redisStore, "email", "email:", 1)
	runStoreContract(t, backend)
}

func TestStoreNamespaceReadsLegacyPhysicalKey(t *testing.T) {
	backend := cache.NewMemory(cache.DefaultMemoryLimit)
	legacy := record{Hash: "digest", Attempts: 0, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := backend.Set(context.Background(), "email:legacy", legacy, time.Minute); err != nil {
		t.Fatal(err)
	}
	namespace := cache.NewNamespace(backend, "email", "email:", 1)
	store, err := New(namespace)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.VerifyAndConsume(context.Background(), "legacy", "digest", 3)
	if err != nil || result != Consumed {
		t.Fatalf("legacy namespace verification = %v, %v; want consumed", result, err)
	}
}

func TestStoreNamespaceRedisReadsLegacyPhysicalKey(t *testing.T) {
	mr := miniredis.RunT(t)
	redisStore := cache.NewRedisWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = redisStore.Close() })
	ctx := context.Background()
	legacy := record{Hash: "digest", Attempts: 0, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := redisStore.Set(ctx, "email:legacy", legacy, time.Minute); err != nil {
		t.Fatal(err)
	}
	namespace := cache.NewNamespace(redisStore, "email", "email:", 1)
	store, err := New(namespace)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.VerifyAndConsume(ctx, "legacy", "digest", 3)
	if err != nil || result != Consumed {
		t.Fatalf("legacy redis namespace verification = %v, %v; want consumed", result, err)
	}
}

func TestStoreNamespaceNewRecordRemainsReadableByBaseBackend(t *testing.T) {
	backend := cache.NewMemory(cache.DefaultMemoryLimit)
	namespace := cache.NewNamespace(backend, "email", "email:", 1)
	namespaced, err := New(namespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := namespaced.Issue(context.Background(), "new", "digest", time.Minute); err != nil {
		t.Fatal(err)
	}
	base, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := base.VerifyAndConsume(context.Background(), "email:new", "digest", 3)
	if err != nil || result != Consumed {
		t.Fatalf("base verification of namespaced record = %v, %v; want consumed", result, err)
	}
}

func TestStoreNamespaceRedisNewRecordRemainsReadableByBaseBackend(t *testing.T) {
	mr := miniredis.RunT(t)
	redisStore := cache.NewRedisWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = redisStore.Close() })
	namespace := cache.NewNamespace(redisStore, "email", "email:", 1)
	namespaced, err := New(namespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := namespaced.Issue(context.Background(), "new", "digest", time.Minute); err != nil {
		t.Fatal(err)
	}
	base, err := New(redisStore)
	if err != nil {
		t.Fatal(err)
	}
	result, err := base.VerifyAndConsume(context.Background(), "email:new", "digest", 3)
	if err != nil || result != Consumed {
		t.Fatalf("base redis verification of namespaced record = %v, %v; want consumed", result, err)
	}
}

// runStoreContract is shared by the Memory and Redis implementations so their
// one-time state transitions remain behaviorally interchangeable.
func runStoreContract(t *testing.T, backend Backend) {
	t.Helper()
	store, err := New(backend)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Issue(ctx, "contract", "digest", time.Minute); err != nil {
		t.Fatal(err)
	}
	result, err := store.VerifyAndConsume(ctx, "contract", "wrong", 3)
	if err != nil || result != Attempted {
		t.Fatalf("wrong verification = %v, %v; want attempted", result, err)
	}
	result, err = store.VerifyAndConsume(ctx, "contract", "digest", 3)
	if err != nil || result != Consumed {
		t.Fatalf("correct verification = %v, %v; want consumed", result, err)
	}
	result, err = store.VerifyAndConsume(ctx, "contract", "digest", 3)
	if err != nil || result != Invalid {
		t.Fatalf("replay verification = %v, %v; want invalid", result, err)
	}

	if err := store.Issue(ctx, "reissue", "old", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.Issue(ctx, "reissue", "new", time.Minute); err != nil {
		t.Fatal(err)
	}
	result, err = store.VerifyAndConsume(ctx, "reissue", "old", 3)
	if err != nil || result != Attempted {
		t.Fatalf("old reissued digest = %v, %v; want attempted", result, err)
	}
	result, err = store.VerifyAndConsume(ctx, "reissue", "new", 3)
	if err != nil || result != Consumed {
		t.Fatalf("new reissued digest = %v, %v; want consumed", result, err)
	}

	const workers = 16
	if err := store.Issue(ctx, "concurrent-correct", "digest", time.Minute); err != nil {
		t.Fatal(err)
	}
	results := make(chan VerifyResult, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := store.VerifyAndConsume(ctx, "concurrent-correct", "digest", workers)
			if err != nil {
				results <- Invalid
				return
			}
			results <- result
		}()
	}
	wg.Wait()
	close(results)
	consumed := 0
	for result := range results {
		if result == Consumed {
			consumed++
		}
	}
	if consumed != 1 {
		t.Fatalf("concurrent correct consumes = %d, want 1", consumed)
	}

	if err := store.Issue(ctx, "concurrent-wrong", "digest", time.Minute); err != nil {
		t.Fatal(err)
	}
	wg = sync.WaitGroup{}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.VerifyAndConsume(ctx, "concurrent-wrong", "wrong", workers+1)
		}()
	}
	wg.Wait()
	result, err = store.VerifyAndConsume(ctx, "concurrent-wrong", "digest", workers+1)
	if err != nil || result != Consumed {
		t.Fatalf("correct after concurrent wrong = %v, %v; want consumed", result, err)
	}

	result, err = store.VerifyAndConsume(ctx, "missing", "digest", 3)
	if err != nil || result != Invalid {
		t.Fatalf("missing verification = %v, %v; want invalid", result, err)
	}
}

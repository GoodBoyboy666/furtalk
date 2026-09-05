package cache

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestAtomicJSONComparerMemory(t *testing.T) {
	store := NewMemory(DefaultMemoryLimit)
	runAtomicJSONContract(t, store)
}

func TestAtomicJSONComparerRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	store := NewRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = store.Close() })
	runAtomicJSONContract(t, store)
}

func runAtomicJSONContract(t *testing.T, store Store) {
	t.Helper()
	atomic, ok := store.(AtomicJSONComparer)
	if !ok {
		t.Fatal("store does not implement AtomicJSONComparer")
	}
	ctx := context.Background()
	key := "atomic-json:test"
	expected := json.RawMessage(`{"value":1}`)
	replacement := json.RawMessage(`{"value":2}`)
	if err := store.Set(ctx, key, json.RawMessage(expected), time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, err := atomic.CompareAndSwapJSON(ctx, key, expected, replacement); err != nil || !ok {
		t.Fatalf("swap = %v, %v; want true", ok, err)
	}
	if ok, err := atomic.CompareAndSwapJSON(ctx, key, expected, json.RawMessage(`{"value":3}`)); err != nil || ok {
		t.Fatalf("stale swap = %v, %v; want false", ok, err)
	}
	var got map[string]int
	if err := store.Get(ctx, key, &got); err != nil || got["value"] != 2 {
		t.Fatalf("stored value = %#v, %v; want value 2", got, err)
	}
	if ok, err := atomic.CompareAndDeleteJSON(ctx, key, expected); err != nil || ok {
		t.Fatalf("stale delete = %v, %v; want false", ok, err)
	}
	if ok, err := atomic.CompareAndDeleteJSON(ctx, key, replacement); err != nil || !ok {
		t.Fatalf("delete = %v, %v; want true", ok, err)
	}
	if err := store.Get(ctx, key, &got); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
}

func TestAtomicJSONComparerPreservesMemoryTTL(t *testing.T) {
	store := NewMemory(DefaultMemoryLimit)
	ctx := context.Background()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	key := "atomic-json:ttl"
	if err := store.Set(ctx, key, map[string]int{"value": 1}, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	raw, err := store.GetRawJSON(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := store.CompareAndSwapJSON(ctx, key, raw, json.RawMessage(`{"value":2}`))
	if err != nil || !ok {
		t.Fatalf("swap = %v, %v", ok, err)
	}
	now = now.Add(29 * time.Second)
	if err := store.Get(ctx, key, &map[string]int{}); err != nil {
		t.Fatalf("entry expired early after swap: %v", err)
	}
	now = now.Add(2 * time.Second)
	if err := store.Get(ctx, key, &map[string]int{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("entry after original expiry = %v, want ErrNotFound", err)
	}
}

func TestAtomicJSONComparerConcurrentStaleWriters(t *testing.T) {
	store := NewMemory(DefaultMemoryLimit)
	ctx := context.Background()
	key := "atomic-json:concurrent"
	initial := json.RawMessage(`{"value":0}`)
	if err := store.Set(ctx, key, initial, time.Minute); err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.CompareAndSwapJSON(ctx, key, initial, json.RawMessage(`{"value":1}`))
			if err != nil {
				t.Errorf("swap: %v", err)
				return
			}
			if ok {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful swaps = %d, want 1", successes)
	}
}

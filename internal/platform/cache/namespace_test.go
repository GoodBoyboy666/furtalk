package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNamespaceMemoryExactJSONCapabilities(t *testing.T) {
	ctx := context.Background()
	store := NewMemory(10)
	ns := NewNamespace(store, "email", "email:", 1)
	if err := ns.Set(ctx, "one", "old", time.Minute); err != nil {
		t.Fatal(err)
	}
	expires := store.items["email:one"].expires
	raw, err := ns.GetRawJSON(ctx, "one")
	if err != nil || !bytes.Equal(raw, json.RawMessage(`"old"`)) {
		t.Fatalf("raw = %s, %v; want exact JSON", raw, err)
	}
	raw[0] = 'x'
	unchanged, err := ns.GetRawJSON(ctx, "one")
	if err != nil || !bytes.Equal(unchanged, json.RawMessage(`"old"`)) {
		t.Fatalf("stored raw changed after caller mutation = %s, %v", unchanged, err)
	}

	if ok, err := ns.CompareAndSwapJSON(ctx, "one", json.RawMessage(`"wrong"`), json.RawMessage(`"new"`)); err != nil || ok {
		t.Fatalf("stale swap = %v, %v; want false, nil", ok, err)
	}
	if ok, err := ns.CompareAndSwapJSON(ctx, "one", json.RawMessage(`"old"`), json.RawMessage(`"new"`)); err != nil || !ok {
		t.Fatalf("matching swap = %v, %v; want true, nil", ok, err)
	}
	if got := store.items["email:one"].expires; !got.Equal(expires) {
		t.Fatalf("swap expiry = %v, want unchanged %v", got, expires)
	}
	if ok, err := ns.CompareAndDeleteJSON(ctx, "one", json.RawMessage(`"old"`)); err != nil || ok {
		t.Fatalf("stale delete = %v, %v; want false, nil", ok, err)
	}
	if ok, err := ns.CompareAndDeleteJSON(ctx, "one", json.RawMessage(`"new"`)); err != nil || !ok {
		t.Fatalf("matching delete = %v, %v; want true, nil", ok, err)
	}
	if err := ns.Set(ctx, "two", "available", time.Minute); err != nil {
		t.Fatalf("slot after compare-delete = %v", err)
	}
}

func TestNamespaceMemoryRawReadCleansMissingMembership(t *testing.T) {
	ctx := context.Background()
	store := NewMemory(10)
	ns := NewNamespace(store, "email", "email:", 1)
	if err := ns.Set(ctx, "one", "old", time.Minute); err != nil {
		t.Fatal(err)
	}
	delete(store.items, "email:one")
	if _, err := ns.GetRawJSON(ctx, "one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing raw = %v, want ErrNotFound", err)
	}
	if err := ns.Set(ctx, "two", "available", time.Minute); err != nil {
		t.Fatalf("slot after missing raw cleanup = %v", err)
	}
}

func TestNamespaceMemoryHardLimitAndIsolation(t *testing.T) {
	ctx := context.Background()
	store := NewMemory(100)
	passkey := NewNamespace(store, "passkey", "webauthn:", 2)
	oauth := NewNamespace(store, "oauth", "oauth-state:", 1)

	if err := passkey.Set(ctx, "a", "value-a", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := passkey.Set(ctx, "b", "value-b", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := passkey.Set(ctx, "c", "value-c", time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatalf("third passkey write = %v, want ErrCapacity", err)
	}
	if err := oauth.Set(ctx, "a", "oauth-a", time.Minute); err != nil {
		t.Fatalf("isolated oauth write = %v", err)
	}

	// Replacing a live key retains one namespace slot.
	if err := passkey.Set(ctx, "a", "value-a2", time.Minute); err != nil {
		t.Fatalf("replacement = %v", err)
	}
	var got string
	if err := passkey.Get(ctx, "a", &got); err != nil || got != "value-a2" {
		t.Fatalf("replacement read = %q, %v", got, err)
	}
}

func TestNamespaceMemoryReleaseOnExpiryDeleteAndConsume(t *testing.T) {
	ctx := context.Background()
	store := NewMemory(100)
	ns := NewNamespace(store, "test", "test:", 1)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	if err := ns.Set(ctx, "expired", "old", time.Second); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := ns.Set(ctx, "after-expiry", "new", time.Minute); err != nil {
		t.Fatalf("write after expiry = %v", err)
	}
	if err := ns.Delete(ctx, "after-expiry"); err != nil {
		t.Fatal(err)
	}
	if err := ns.Set(ctx, "consume", "consumed", time.Minute); err != nil {
		t.Fatal(err)
	}
	value, err := ns.AtomicConsume(ctx, "consume")
	if err != nil || value != "consumed" {
		t.Fatalf("consume = %q, %v", value, err)
	}
	if err := ns.Set(ctx, "after-consume", "available", time.Minute); err != nil {
		t.Fatalf("write after consume = %v", err)
	}
}

func TestNamespaceMemoryMembershipSurvivesGlobalExpiryEviction(t *testing.T) {
	ctx := context.Background()
	store := NewMemory(1)
	ns := NewNamespace(store, "test", "test:", 1)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := ns.Set(ctx, "old", "old", time.Second); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := ns.Set(ctx, "new", "new", time.Minute); err != nil {
		t.Fatalf("write after global eviction = %v", err)
	}
	if err := ns.Set(ctx, "third", "third", time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatalf("third write = %v, want ErrCapacity", err)
	}
}

func TestNamespaceMemoryConcurrentAdmissionNeverExceedsLimit(t *testing.T) {
	ctx := context.Background()
	store := NewMemory(1000)
	ns := NewNamespace(store, "concurrent", "concurrent:", 7)
	const workers = 128
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- ns.Set(ctx, string(rune('a'+i)), i, time.Minute)
		}(i)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrCapacity) {
			t.Fatalf("concurrent admission error = %v", err)
		}
	}
	if successes != 7 {
		t.Fatalf("concurrent successful admissions = %d, want 7", successes)
	}
}

func TestNamespaceFallbackSharesReplacementAndRelease(t *testing.T) {
	ctx := context.Background()
	store := &namespaceTestStore{memory: NewMemory(100)}
	ns := NewNamespace(store, "fallback", "fallback:", 1)
	if err := ns.Set(ctx, "one", "first", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := ns.Set(ctx, "two", "blocked", time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatalf("fallback second write = %v, want ErrCapacity", err)
	}
	if err := ns.Delete(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if err := ns.Set(ctx, "two", "available", time.Minute); err != nil {
		t.Fatalf("fallback write after delete = %v", err)
	}
}

func TestNamespaceMemoryRejectsUntrackedKeyWhenNamespaceFull(t *testing.T) {
	ctx := context.Background()
	store := NewMemory(100)
	ns := NewNamespace(store, "test", "test:", 1)
	if err := ns.Set(ctx, "tracked", "tracked", time.Minute); err != nil {
		t.Fatal(err)
	}
	// A raw write must not let a later namespaced write bypass the hard limit.
	if err := store.Set(ctx, "test:untracked", "untracked", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := ns.Set(ctx, "untracked", "replacement", time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatalf("untracked replacement = %v, want ErrCapacity", err)
	}
}

// namespaceTestStore intentionally hides the concrete backend to exercise the
// synchronized adapter used by narrow test doubles.
type namespaceTestStore struct{ memory *Memory }

func (s *namespaceTestStore) Get(ctx context.Context, key string, out any) error {
	return s.memory.Get(ctx, key, out)
}

func (s *namespaceTestStore) GetRawJSON(ctx context.Context, key string) (json.RawMessage, error) {
	return s.memory.GetRawJSON(ctx, key)
}

func (s *namespaceTestStore) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return s.memory.Set(ctx, key, value, ttl)
}

func (s *namespaceTestStore) Delete(ctx context.Context, key string) error {
	return s.memory.Delete(ctx, key)
}

func (s *namespaceTestStore) CompareAndSwapJSON(ctx context.Context, key string, expected, replacement json.RawMessage) (bool, error) {
	return s.memory.CompareAndSwapJSON(ctx, key, expected, replacement)
}

func (s *namespaceTestStore) CompareAndDeleteJSON(ctx context.Context, key string, expected json.RawMessage) (bool, error) {
	return s.memory.CompareAndDeleteJSON(ctx, key, expected)
}

func (s *namespaceTestStore) AtomicConsume(ctx context.Context, key string) (string, error) {
	return s.memory.AtomicConsume(ctx, key)
}

func (s *namespaceTestStore) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	return s.memory.GetOrLoad(ctx, key, out, ttl, load)
}

var _ Store = (*namespaceTestStore)(nil)

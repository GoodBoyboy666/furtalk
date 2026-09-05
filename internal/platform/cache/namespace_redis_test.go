package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestNamespaceRedisExactJSONCapabilities(t *testing.T) {
	mr := miniredis.RunT(t)
	store := NewRedisWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = store.Close() })
	ns := NewNamespace(store, "email", "email:", 1)
	ctx := context.Background()
	if err := ns.Set(ctx, "one", "old", time.Minute); err != nil {
		t.Fatal(err)
	}
	raw, err := ns.GetRawJSON(ctx, "one")
	if err != nil || !bytes.Equal(raw, json.RawMessage(`"old"`)) {
		t.Fatalf("raw = %s, %v; want exact JSON", raw, err)
	}
	if ok, err := ns.CompareAndSwapJSON(ctx, "one", json.RawMessage(`"old"`), json.RawMessage(`"new"`)); err != nil || !ok {
		t.Fatalf("matching swap = %v, %v; want true, nil", ok, err)
	}
	if ok, err := ns.CompareAndDeleteJSON(ctx, "one", json.RawMessage(`"new"`)); err != nil || !ok {
		t.Fatalf("matching delete = %v, %v; want true, nil", ok, err)
	}
	if err := ns.Set(ctx, "two", "available", time.Minute); err != nil {
		t.Fatalf("slot after compare-delete = %v", err)
	}
}

func TestNamespaceRedisCompareAndSwapPreservesTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	redisStore := NewRedisWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = redisStore.Close() })
	ns := NewNamespace(redisStore, "email", "email:", 1)
	ctx := context.Background()
	if err := ns.Set(ctx, "one", "old", time.Minute); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(30 * time.Second)
	raw, err := ns.GetRawJSON(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ns.CompareAndSwapJSON(ctx, "one", raw, json.RawMessage(`"new"`)); err != nil || !ok {
		t.Fatalf("matching swap = %v, %v; want true, nil", ok, err)
	}
	mr.FastForward(31 * time.Second)
	if _, err := ns.GetRawJSON(ctx, "one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("swapped key after original TTL = %v, want ErrNotFound", err)
	}
}

func TestNamespaceRedisCompareAndSwapMissingCleansQuota(t *testing.T) {
	mr := miniredis.RunT(t)
	redisStore := NewRedisWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = redisStore.Close() })
	ns := NewNamespace(redisStore, "email", "email:", 1)
	ctx := context.Background()
	if err := ns.Set(ctx, "one", "old", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := redisStore.Delete(ctx, "email:one"); err != nil {
		t.Fatal(err)
	}
	if ok, err := ns.CompareAndSwapJSON(ctx, "one", json.RawMessage(`"old"`), json.RawMessage(`"new"`)); err != nil || ok {
		t.Fatalf("missing swap = %v, %v; want false, nil", ok, err)
	}
	if err := ns.Set(ctx, "two", "available", time.Minute); err != nil {
		t.Fatalf("slot after missing swap cleanup = %v", err)
	}
}

func TestNamespaceRedisRawMalformedPayloadAndCleanup(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisWithClient(client)
	t.Cleanup(func() { _ = store.Close() })
	ns := NewNamespace(store, "email", "email:", 1)
	ctx := context.Background()
	if err := client.Set(ctx, "email:bad", []byte("{not-json"), time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	raw, err := ns.GetRawJSON(ctx, "bad")
	if err != nil || !bytes.Equal(raw, json.RawMessage("{not-json")) {
		t.Fatalf("malformed raw = %s, %v; want exact bytes", raw, err)
	}
	if ok, err := ns.CompareAndDeleteJSON(ctx, "bad", raw); err != nil || !ok {
		t.Fatalf("malformed compare-delete = %v, %v; want true, nil", ok, err)
	}
	if err := ns.Set(ctx, "next", "available", time.Minute); err != nil {
		t.Fatalf("slot after malformed cleanup = %v", err)
	}
}

func TestNamespaceRedisSharedAtomicLimitAndRelease(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisWithClient(client)
	t.Cleanup(func() { _ = store.Close() })
	first := NewNamespace(store, "oauth", "oauth-state:", 1)
	second := NewNamespace(store, "oauth", "oauth-state:", 1)
	ctx := context.Background()

	if err := first.Set(ctx, "one", "value", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := second.Set(ctx, "two", "blocked", time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatalf("shared second write = %v, want ErrCapacity", err)
	}
	if err := second.Delete(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if err := second.Set(ctx, "two", "available", time.Minute); err != nil {
		t.Fatalf("write after release = %v", err)
	}
	var got string
	if err := first.Get(ctx, "two", &got); err != nil || got != "available" {
		t.Fatalf("shared read = %q, %v", got, err)
	}
}

func TestNamespaceRedisConsumeReleasesQuota(t *testing.T) {
	mr := miniredis.RunT(t)
	store := NewRedisWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = store.Close() })
	ns := NewNamespace(store, "handoff", "oauth-handoff:", 1)
	ctx := context.Background()
	if err := ns.Set(ctx, "token", "payload", time.Minute); err != nil {
		t.Fatal(err)
	}
	value, err := ns.AtomicConsume(ctx, "token")
	if err != nil || value != "payload" {
		t.Fatalf("consume = %q, %v", value, err)
	}
	if err := ns.Set(ctx, "next", "payload", time.Minute); err != nil {
		t.Fatalf("write after consume = %v", err)
	}
}

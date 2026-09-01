package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestNamespaceRedisSharedAtomicLimitAndRelease(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedis(client)
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
	store := NewRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
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

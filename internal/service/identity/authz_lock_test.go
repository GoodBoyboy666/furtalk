package identity

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/repository"
)

// blockingAuthzCache pauses the first miss after the database load and before
// cache publication, reproducing the old load -> invalidate -> publish race.
type blockingAuthzCache struct {
	*cache.Memory
	loadCompleted chan struct{}
	allowPublish  chan struct{}
	deleteCalled  chan struct{}
	blockOnce     sync.Once
	deleteOnce    sync.Once
}

func newBlockingAuthzCache() *blockingAuthzCache {
	return &blockingAuthzCache{
		Memory:        cache.NewMemory(cache.DefaultMemoryLimit),
		loadCompleted: make(chan struct{}),
		allowPublish:  make(chan struct{}),
		deleteCalled:  make(chan struct{}),
	}
}

func (c *blockingAuthzCache) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	if err := c.Memory.Get(ctx, key, out); err == nil {
		return nil
	} else if !errors.Is(err, cache.ErrNotFound) {
		return err
	}
	value, err := load()
	if err != nil {
		return err
	}
	blocked := false
	c.blockOnce.Do(func() {
		blocked = true
		close(c.loadCompleted)
	})
	if blocked {
		select {
		case <-c.allowPublish:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := c.Memory.Set(ctx, key, value, ttl); err != nil {
		return err
	}
	return c.Memory.Get(ctx, key, out)
}

func (c *blockingAuthzCache) Delete(ctx context.Context, key string) error {
	if err := c.Memory.Delete(ctx, key); err != nil {
		return err
	}
	c.deleteOnce.Do(func() { close(c.deleteCalled) })
	return nil
}

func waitForAuthzRefs(t *testing.T, registry *authzLockRegistry, userID int64, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		registry.mu.Lock()
		entry := registry.entries[userID]
		got := 0
		if entry != nil {
			got = entry.refs
		}
		registry.mu.Unlock()
		if got == want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("authz lock refs for user %d did not reach %d", userID, want)
}

func authzEntryCount(registry *authzLockRegistry) int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.entries)
}

func TestResolveAndInvalidateSerializeOldSnapshotPublication(t *testing.T) {
	db := newEmailCodeTestDB(t)
	users := repository.NewUserRepo(db)
	user := &domain.User{
		Email:           "authz-race@example.com",
		EmailNormalized: "authz-race@example.com",
		Nickname:        "authz-race",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	store := newBlockingAuthzCache()
	svc := NewService(Dependencies{Users: users, Cache: store})

	type resolveResult struct {
		principal domain.Principal
		err       error
	}
	resolved := make(chan resolveResult, 1)
	go func() {
		principal, err := svc.Resolve(context.Background(), user.ID)
		resolved <- resolveResult{principal: principal, err: err}
	}()

	select {
	case <-store.loadCompleted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for old database snapshot")
	}
	if err := users.UpdateRoleStatus(context.Background(), user.ID, domain.RoleAdmin, domain.UserStatusActive); err != nil {
		t.Fatalf("commit role update: %v", err)
	}

	invalidated := make(chan error, 1)
	go func() { invalidated <- svc.invalidateAuthz(context.Background(), user.ID) }()
	waitForAuthzRefs(t, &svc.authzLocks, user.ID, 2)
	select {
	case <-store.deleteCalled:
		t.Fatal("invalidation reached cache before in-flight publication completed")
	default:
	}

	close(store.allowPublish)
	result := <-resolved
	if result.err != nil {
		t.Fatalf("resolve old snapshot: %v", result.err)
	}
	if result.principal.Role != domain.RoleUser {
		t.Fatalf("in-flight principal role = %q, want old role user", result.principal.Role)
	}
	if err := <-invalidated; err != nil {
		t.Fatalf("invalidate authz: %v", err)
	}
	if err := store.Memory.Get(context.Background(), authzKey(user.ID), &domain.AuthzInfo{}); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("stale cache entry remained after serialization: %v", err)
	}

	principal, err := svc.Resolve(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("resolve committed role: %v", err)
	}
	if principal.Role != domain.RoleAdmin {
		t.Fatalf("resolved role = %q, want committed admin", principal.Role)
	}
	if got := authzEntryCount(&svc.authzLocks); got != 0 {
		t.Fatalf("authz lock entries = %d, want cleanup to zero", got)
	}
}

func TestAuthzLockRegistryIsPerUserAndCleansUp(t *testing.T) {
	var registry authzLockRegistry
	unlockFirst := registry.lock(1)

	secondAcquired := make(chan func(), 1)
	go func() { secondAcquired <- registry.lock(2) }()
	var unlockSecond func()
	select {
	case unlockSecond = <-secondAcquired:
	case <-time.After(5 * time.Second):
		t.Fatal("different user was blocked by the first user's lock")
	}
	unlockSecond()

	sameAcquired := make(chan func(), 1)
	go func() { sameAcquired <- registry.lock(1) }()
	waitForAuthzRefs(t, &registry, 1, 2)
	select {
	case unlock := <-sameAcquired:
		unlock()
		t.Fatal("same user acquired lock before the holder released it")
	default:
	}

	unlockFirst()
	select {
	case unlock := <-sameAcquired:
		unlock()
	case <-time.After(5 * time.Second):
		t.Fatal("same user did not acquire lock after release")
	}
	if got := authzEntryCount(&registry); got != 0 {
		t.Fatalf("authz lock entries = %d, want cleanup to zero", got)
	}
}

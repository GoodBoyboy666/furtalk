package identity

import (
	"context"
	"testing"

	"furtalk/internal/platform/cache"
	"furtalk/internal/repository"
)

// TestResolveRoundTripsSessionVersion 验证 Resolve 从数据库装载并在 authz
// 缓存中携带会话代次，principal 与缓存内的版本一致。
func TestResolveRoundTripsSessionVersion(t *testing.T) {
	db := newCaptchaLoginDB(t)
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{
		Users:  repository.NewUserRepo(db),
		Cache:  store,
		Policy: loginTestPolicy{},
	})
	user := insertVerifiedUser(t, db, "resolve@example.com")

	principal, err := svc.Resolve(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if principal.SessionVersion != 1 {
		t.Fatalf("principal session version = %d, want 1", principal.SessionVersion)
	}

	// 第二次解析命中缓存，版本仍一致。
	again, err := svc.Resolve(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("resolve cached: %v", err)
	}
	if again.SessionVersion != principal.SessionVersion {
		t.Fatalf("cached session version = %d, want %d", again.SessionVersion, principal.SessionVersion)
	}
}

// TestResolveSessionVersionMatchesStoredUser 验证缓存序列化后的会话代次与
// 数据库当前值一致（AuthzInfo JSON 字段携带 session_version）。
func TestResolveSessionVersionMatchesStoredUser(t *testing.T) {
	db := newCaptchaLoginDB(t)
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{
		Users:  repository.NewUserRepo(db),
		Cache:  store,
		Policy: loginTestPolicy{},
	})
	user := insertVerifiedUser(t, db, "match@example.com")

	principal, err := svc.Resolve(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	stored, err := repository.NewUserRepo(db).FindByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if principal.SessionVersion != stored.SessionVersion {
		t.Fatalf("principal version = %d, stored = %d, want equal", principal.SessionVersion, stored.SessionVersion)
	}
}

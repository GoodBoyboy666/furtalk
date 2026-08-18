package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
)

// seedOAuthState 向内存缓存写入一条一次性 OAuth state 记录。
func seedOAuthState(t *testing.T, store *cache.Memory, state string, record OAuthState) {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(context.Background(), oauthStatePrefix+state, string(data), oauthStateTTL); err != nil {
		t.Fatal(err)
	}
}

// TestOAuthErrorRedirectSuccess 验证成功路径：原子消费 state、返回净化后的回跳地址，
// 且不创建任何用户、绑定或会话；同 state 不可重放。
func TestOAuthErrorRedirectSuccess(t *testing.T) {
	ctx := context.Background()
	db := newCaptchaLoginDB(t)
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{
		TxRunner:   gormtx.NewRunner(db),
		Users:      repository.NewUserRepo(db),
		Identities: repository.NewExternalIdentityRepo(db),
		Cache:      store,
	})
	state := "state-ok"
	seedOAuthState(t, store, state, OAuthState{
		Provider: "apple",
		Purpose:  oauthPurposeLogin,
		Redirect: "/account/security",
	})

	redirect, err := svc.OAuthErrorRedirect(ctx, "apple", state)
	if err != nil {
		t.Fatalf("OAuthErrorRedirect: %v", err)
	}
	if redirect != "/account/security" {
		t.Fatalf("redirect = %q, want /account/security", redirect)
	}
	var userCount, identityCount int64
	if err := db.Table("users").Count(&userCount).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := db.Table("external_identities").Count(&identityCount).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if userCount != 0 || identityCount != 0 {
		t.Fatalf("side-effect writes users=%d identities=%d, want 0/0", userCount, identityCount)
	}
	// state 必须被一次性消费，重放返回通用失败。
	if _, err := svc.OAuthErrorRedirect(ctx, "apple", state); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("replay err = %v, want ErrInvalidCredentials", err)
	}
}

// TestOAuthErrorRedirectUnknownState 验证未知 state 返回 ErrInvalidCredentials。
func TestOAuthErrorRedirectUnknownState(t *testing.T) {
	svc := NewService(Dependencies{Cache: cache.NewMemory(10000)})
	if _, err := svc.OAuthErrorRedirect(context.Background(), "apple", "missing-state"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("unknown state err = %v, want ErrInvalidCredentials", err)
	}
}

// TestOAuthErrorRedirectMismatchedProvider 验证 state 的 provider 与回调不一致时
// 返回 ErrInvalidCredentials，不返回任何回跳地址。
func TestOAuthErrorRedirectMismatchedProvider(t *testing.T) {
	ctx := context.Background()
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{Cache: store})
	seedOAuthState(t, store, "state-apple", OAuthState{
		Provider: "apple",
		Purpose:  oauthPurposeLogin,
		Redirect: "/account/security",
	})
	if _, err := svc.OAuthErrorRedirect(ctx, "github", "state-apple"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("mismatched provider err = %v, want ErrInvalidCredentials", err)
	}
}

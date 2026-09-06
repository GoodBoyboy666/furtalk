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

// TestOAuthAccessDeniedSuccess 验证成功路径：原子消费 state、恢复净化后的回跳地址、
// 返回 ErrOAuthAccessDenied，且不创建任何用户、绑定或会话；同 state 不可重放。
func TestOAuthAccessDeniedSuccess(t *testing.T) {
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

	redirect, err := svc.OAuthAccessDenied(ctx, "apple", state)
	if !errors.Is(err, domain.ErrOAuthAccessDenied) {
		t.Fatalf("err = %v, want ErrOAuthAccessDenied", err)
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
	// state 必须被一次性消费，重放返回回调无效。
	if _, err := svc.OAuthAccessDenied(ctx, "apple", state); !errors.Is(err, domain.ErrOAuthCallbackInvalid) {
		t.Fatalf("replay err = %v, want ErrOAuthCallbackInvalid", err)
	}
}

// TestOAuthAccessDeniedUnknownState 验证未知 state 返回 ErrOAuthCallbackInvalid。
func TestOAuthAccessDeniedUnknownState(t *testing.T) {
	svc := NewService(Dependencies{Cache: cache.NewMemory(10000)})
	if _, err := svc.OAuthAccessDenied(context.Background(), "apple", "missing-state"); !errors.Is(err, domain.ErrOAuthCallbackInvalid) {
		t.Fatalf("unknown state err = %v, want ErrOAuthCallbackInvalid", err)
	}
}

// TestOAuthAccessDeniedMismatchedProvider 验证 state 的 provider 与回调不一致时
// 返回 ErrOAuthCallbackInvalid，不返回任何回跳地址。
func TestOAuthAccessDeniedMismatchedProvider(t *testing.T) {
	ctx := context.Background()
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{Cache: store})
	seedOAuthState(t, store, "state-apple", OAuthState{
		Provider: "apple",
		Purpose:  oauthPurposeLogin,
		Redirect: "/account/security",
	})
	if _, err := svc.OAuthAccessDenied(ctx, "github", "state-apple"); !errors.Is(err, domain.ErrOAuthCallbackInvalid) {
		t.Fatalf("mismatched provider err = %v, want ErrOAuthCallbackInvalid", err)
	}
}

// TestCreateAndConsumeOAuthHandoff 验证 Apple handoff 创建与一次性消费，
// 载荷往返正确且不可重放。
func TestCreateAndConsumeOAuthHandoff(t *testing.T) {
	ctx := context.Background()
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{Cache: store})
	seedOAuthState(t, store, "state-1", OAuthState{Provider: "apple", Purpose: oauthPurposeLogin})

	token, err := svc.CreateOAuthHandoff(ctx, "apple", "state-1", "code-1", "")
	if err != nil {
		t.Fatalf("CreateOAuthHandoff: %v", err)
	}
	if token == "" {
		t.Fatal("handoff token is empty")
	}

	handoff, err := svc.ConsumeOAuthHandoff(ctx, token)
	if err != nil {
		t.Fatalf("ConsumeOAuthHandoff: %v", err)
	}
	if handoff.Provider != "apple" || handoff.State != "state-1" || handoff.Code != "code-1" || handoff.Error != "" {
		t.Fatalf("handoff = %+v, want apple/state-1/code-1", handoff)
	}

	// handoff 只能消费一次；重放返回回调无效。
	if _, err := svc.ConsumeOAuthHandoff(ctx, token); !errors.Is(err, domain.ErrOAuthCallbackInvalid) {
		t.Fatalf("replay err = %v, want ErrOAuthCallbackInvalid", err)
	}
}

// TestCreateOAuthHandoffRequiresLiveAppleState verifies that the bridge cannot
// allocate handoff records for another provider or an unknown/invalid state.
func TestCreateOAuthHandoffRequiresLiveAppleState(t *testing.T) {
	ctx := context.Background()
	store := cache.NewMemory(10000)
	svc := NewService(Dependencies{Cache: store})

	for _, tc := range []struct {
		name     string
		provider string
		state    string
		record   *OAuthState
	}{
		{name: "unknown state", provider: "apple", state: "missing"},
		{name: "non apple provider", provider: "github", state: "state-github", record: &OAuthState{Provider: "github"}},
		{name: "mismatched provider", provider: "apple", state: "state-github-callback", record: &OAuthState{Provider: "github"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.record != nil {
				seedOAuthState(t, store, tc.state, *tc.record)
			}
			if _, err := svc.CreateOAuthHandoff(ctx, tc.provider, tc.state, "code", ""); !errors.Is(err, domain.ErrOAuthCallbackInvalid) {
				t.Fatalf("err = %v, want ErrOAuthCallbackInvalid", err)
			}
		})
	}
}

// TestCreateOAuthHandoffMissingState 验证缺少 state 的 handoff 创建被拒绝。
func TestCreateOAuthHandoffMissingState(t *testing.T) {
	svc := NewService(Dependencies{Cache: cache.NewMemory(10000)})
	if _, err := svc.CreateOAuthHandoff(context.Background(), "apple", "", "code-1", ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("missing state err = %v, want ErrValidation", err)
	}
}

// TestConsumeOAuthHandoffUnknown 验证未知/过期 handoff 返回 ErrOAuthCallbackInvalid。
func TestConsumeOAuthHandoffUnknown(t *testing.T) {
	svc := NewService(Dependencies{Cache: cache.NewMemory(10000)})
	if _, err := svc.ConsumeOAuthHandoff(context.Background(), "missing-handoff"); !errors.Is(err, domain.ErrOAuthCallbackInvalid) {
		t.Fatalf("unknown handoff err = %v, want ErrOAuthCallbackInvalid", err)
	}
}

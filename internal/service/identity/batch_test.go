package identity

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
)

func TestAdminBatchUsersCountsNoopsAndInvalidatesOnlyChangedAuthz(t *testing.T) {
	svc, store := newAdminTestService(t)
	active := mustCreateUser(t, svc, AdminCreateUserInput{Email: "active-batch@example.com", Nickname: "active", Role: domain.RoleUser})
	disabled := mustCreateUser(t, svc, AdminCreateUserInput{Email: "disabled-batch@example.com", Nickname: "disabled", Role: domain.RoleUser})
	status := domain.UserStatusDisabled
	if _, err := svc.AdminUpdateUser(context.Background(), disabled.ID, AdminUpdateUserInput{Status: &status}); err != nil {
		t.Fatalf("disable fixture: %v", err)
	}
	store.cache.deleted = nil

	result, err := svc.AdminBatchUsers(context.Background(), AdminUserBatchInput{
		ActingID: 999,
		IDs:      []int64{disabled.ID, active.ID},
		Action:   AdminUserBatchEnable,
	})
	if err != nil {
		t.Fatalf("batch enable: %v", err)
	}
	if result.ChangedCount != 1 || result.UnchangedCount != 1 || result.RequestedCount != 2 {
		t.Fatalf("result = %+v, want requested 2 changed 1 unchanged 1", result)
	}
	if len(store.cache.deleted) != 1 || store.cache.deleted[0] != authzKey(disabled.ID) {
		t.Fatalf("cache deletes = %v, want only disabled user", store.cache.deleted)
	}
}

func TestAdminBatchUsersRollsBackOnSelfDeleteAndReportsFailedID(t *testing.T) {
	svc, store := newAdminTestService(t)
	acting := mustCreateUser(t, svc, AdminCreateUserInput{Email: "acting-batch@example.com", Nickname: "acting", Role: domain.RoleAdmin})
	target := mustCreateUser(t, svc, AdminCreateUserInput{Email: "target-batch@example.com", Nickname: "target", Role: domain.RoleUser})
	store.cache.deleted = nil

	_, err := svc.AdminBatchUsers(context.Background(), AdminUserBatchInput{
		ActingID: acting.ID,
		IDs:      []int64{target.ID, acting.ID},
		Action:   AdminUserBatchSoftDelete,
		Confirm:  true,
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self-delete batch err = %v, want ErrForbidden", err)
	}
	var resourceErr *domain.ResourceError
	if !errors.As(err, &resourceErr) || resourceErr.ResourceID != acting.ID {
		t.Fatalf("failed resource = %+v, want acting id %d", resourceErr, acting.ID)
	}
	for _, id := range []int64{acting.ID, target.ID} {
		user, findErr := svc.users.FindByID(context.Background(), id)
		if findErr != nil {
			t.Fatalf("find user %d: %v", id, findErr)
		}
		if user.Status != domain.UserStatusActive {
			t.Fatalf("user %d changed after rollback: %+v", id, user)
		}
	}
	if len(store.cache.deleted) != 0 {
		t.Fatalf("rolled back batch must not invalidate cache: %v", store.cache.deleted)
	}
}

func TestAdminBatchUsersFinalAdminGuardRollsBackWholeBatch(t *testing.T) {
	svc, store := newAdminTestService(t)
	first := mustCreateUser(t, svc, AdminCreateUserInput{Email: "first-admin-batch@example.com", Nickname: "first", Role: domain.RoleAdmin})
	second := mustCreateUser(t, svc, AdminCreateUserInput{Email: "second-admin-batch@example.com", Nickname: "second", Role: domain.RoleAdmin})
	store.cache.deleted = nil

	_, err := svc.AdminBatchUsers(context.Background(), AdminUserBatchInput{
		ActingID: 999,
		IDs:      []int64{first.ID, second.ID},
		Action:   AdminUserBatchDisable,
	})
	if !errors.Is(err, domain.ErrLastAdmin) {
		t.Fatalf("disable final admins err = %v, want ErrLastAdmin", err)
	}
	var resourceErr *domain.ResourceError
	if !errors.As(err, &resourceErr) {
		t.Fatalf("error = %v, want failed resource", err)
	}
	for _, id := range []int64{first.ID, second.ID} {
		user, findErr := svc.users.FindByID(context.Background(), id)
		if findErr != nil {
			t.Fatalf("find admin %d: %v", id, findErr)
		}
		if user.Status != domain.UserStatusActive {
			t.Fatalf("admin %d changed after rollback: %+v", id, user)
		}
	}
	if len(store.cache.deleted) != 0 {
		t.Fatalf("guard failure must not invalidate cache: %v", store.cache.deleted)
	}
}

func TestAdminBatchUsersRejectsDeletedLifecycleActionsAndRestoresNoop(t *testing.T) {
	svc, _ := newAdminTestService(t)
	admin := mustCreateUser(t, svc, AdminCreateUserInput{Email: "restore-admin-batch@example.com", Nickname: "admin", Role: domain.RoleAdmin})
	target := mustCreateUser(t, svc, AdminCreateUserInput{Email: "restore-target-batch@example.com", Nickname: "target", Role: domain.RoleUser})
	if err := svc.AdminDeleteUser(context.Background(), admin.ID, target.ID, domain.UserDeleteModeSoft, false); err != nil {
		t.Fatalf("soft-delete fixture: %v", err)
	}

	_, err := svc.AdminBatchUsers(context.Background(), AdminUserBatchInput{
		ActingID: admin.ID,
		IDs:      []int64{target.ID},
		Action:   AdminUserBatchEnable,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("enable deleted user err = %v, want ErrConflict", err)
	}

	result, err := svc.AdminBatchUsers(context.Background(), AdminUserBatchInput{
		ActingID: admin.ID,
		IDs:      []int64{admin.ID, target.ID},
		Action:   AdminUserBatchRestore,
	})
	if err != nil {
		t.Fatalf("restore batch: %v", err)
	}
	if result.ChangedCount != 1 || result.UnchangedCount != 1 {
		t.Fatalf("restore result = %+v, want changed 1 unchanged 1", result)
	}
	user, err := svc.users.FindByID(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("find restored target: %v", err)
	}
	if user.Status != domain.UserStatusActive || user.DeletedAt != nil {
		t.Fatalf("restored user = %+v", user)
	}
}

func TestAdminBatchUsersCacheFailureHappensAfterCommit(t *testing.T) {
	svc, store := newAdminTestService(t)
	target := mustCreateUser(t, svc, AdminCreateUserInput{Email: "cache-batch@example.com", Nickname: "target", Role: domain.RoleUser})
	store.cache.err = errors.New("cache unavailable")

	_, err := svc.AdminBatchUsers(context.Background(), AdminUserBatchInput{
		ActingID: 999,
		IDs:      []int64{target.ID},
		Action:   AdminUserBatchDisable,
	})
	if !errors.Is(err, domain.ErrCacheInvalidation) {
		t.Fatalf("cache failure err = %v, want ErrCacheInvalidation", err)
	}
	user, findErr := svc.users.FindByID(context.Background(), target.ID)
	if findErr != nil {
		t.Fatalf("find committed user: %v", findErr)
	}
	if user.Status != domain.UserStatusDisabled {
		t.Fatalf("status = %q, want committed disabled after cache failure", user.Status)
	}
}

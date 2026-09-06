package identity

import (
	"context"
	"errors"
	"sync"
	"testing"

	"furtalk/internal/domain"
)

// TestAdminMutationsSerializeLastAdminGuard 验证两个管理员并发变更不会留下零个活跃管理员。
func TestAdminMutationsSerializeLastAdminGuard(t *testing.T) {
	svc, _ := newAdminTestService(t)
	first := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "concurrent-admin-1@example.com", Nickname: "admin-1", Role: domain.RoleAdmin,
	})
	second := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "concurrent-admin-2@example.com", Nickname: "admin-2", Role: domain.RoleAdmin,
	})

	role := domain.RoleUser
	status := domain.UserStatusDisabled
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := svc.AdminUpdateUser(context.Background(), first.ID, AdminUpdateUserInput{Role: &role})
		errs <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := svc.AdminUpdateUser(context.Background(), second.ID, AdminUpdateUserInput{Status: &status})
		errs <- err
	}()
	close(start)
	wg.Wait()
	close(errs)

	var success, lastAdmin int
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, domain.ErrLastAdmin):
			lastAdmin++
		default:
			t.Fatalf("concurrent admin mutation err = %v, want nil or ErrLastAdmin", err)
		}
	}
	if success != 1 || lastAdmin != 1 {
		t.Fatalf("concurrent admin results success=%d lastAdmin=%d, want 1/1", success, lastAdmin)
	}

	count, err := svc.users.CountByRoleAndStatus(context.Background(), domain.RoleAdmin, domain.UserStatusActive)
	if err != nil {
		t.Fatalf("count active admins: %v", err)
	}
	if count != 1 {
		t.Fatalf("active admin count = %d, want 1", count)
	}
}

// TestAdminDeleteMutationsSerializeLastAdminGuard 验证相互删除两个管理员时只有一个请求成功。
func TestAdminDeleteMutationsSerializeLastAdminGuard(t *testing.T) {
	svc, _ := newAdminTestService(t)
	first := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "delete-admin-1@example.com", Nickname: "delete-admin-1", Role: domain.RoleAdmin,
	})
	second := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "delete-admin-2@example.com", Nickname: "delete-admin-2", Role: domain.RoleAdmin,
	})

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errs <- svc.AdminDeleteUser(context.Background(), first.ID, second.ID, domain.UserDeleteModeSoft, false)
	}()
	go func() {
		defer wg.Done()
		<-start
		errs <- svc.AdminDeleteUser(context.Background(), second.ID, first.ID, domain.UserDeleteModeSoft, false)
	}()
	close(start)
	wg.Wait()
	close(errs)

	var success, lastAdmin int
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, domain.ErrLastAdmin):
			lastAdmin++
		default:
			t.Fatalf("concurrent admin delete err = %v, want nil or ErrLastAdmin", err)
		}
	}
	if success != 1 || lastAdmin != 1 {
		t.Fatalf("concurrent admin delete results success=%d lastAdmin=%d, want 1/1", success, lastAdmin)
	}

	count, err := svc.users.CountByRoleAndStatus(context.Background(), domain.RoleAdmin, domain.UserStatusActive)
	if err != nil {
		t.Fatalf("count active admins after delete: %v", err)
	}
	if count != 1 {
		t.Fatalf("active admin count after delete = %d, want 1", count)
	}
}

// TestAdminBatchAndSingleMutationShareGuard 验证批量与单用户管理员变更使用同一互斥边界。
func TestAdminBatchAndSingleMutationShareGuard(t *testing.T) {
	svc, _ := newAdminTestService(t)
	first := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "batch-admin-1@example.com", Nickname: "batch-admin-1", Role: domain.RoleAdmin,
	})
	second := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "batch-admin-2@example.com", Nickname: "batch-admin-2", Role: domain.RoleAdmin,
	})

	start := make(chan struct{})
	batchErr := make(chan error, 1)
	singleErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := svc.AdminBatchUsers(context.Background(), AdminUserBatchInput{
			ActingID: first.ID,
			IDs:      []int64{first.ID, second.ID},
			Action:   AdminUserBatchDisable,
		})
		batchErr <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		status := domain.UserStatusDisabled
		_, err := svc.AdminUpdateUser(context.Background(), second.ID, AdminUpdateUserInput{Status: &status})
		singleErr <- err
	}()
	close(start)
	wg.Wait()

	be := <-batchErr
	se := <-singleErr
	if (be == nil) == (se == nil) {
		t.Fatalf("batch and single mutations must have exactly one success, got batch=%v single=%v", be, se)
	}
	if be != nil && !errors.Is(be, domain.ErrLastAdmin) {
		t.Fatalf("batch mutation err = %v, want nil or ErrLastAdmin", be)
	}
	if se != nil && !errors.Is(se, domain.ErrLastAdmin) {
		t.Fatalf("single mutation err = %v, want nil or ErrLastAdmin", se)
	}
	count, err := svc.users.CountByRoleAndStatus(context.Background(), domain.RoleAdmin, domain.UserStatusActive)
	if err != nil {
		t.Fatalf("count active admins after batch race: %v", err)
	}
	if count < 1 {
		t.Fatalf("active admin count after batch race = %d, want at least 1", count)
	}
}

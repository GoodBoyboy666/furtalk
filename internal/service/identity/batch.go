package identity

import (
	"context"
	"sort"
	"time"

	"furtalk/internal/domain"
)

const maxUserBatchLimit = 100

// AdminUserBatchAction 是管理员用户批量命令的受控动作集合。
// 角色不属于批量操作；角色编辑仍只通过单条用户更新命令完成。
type AdminUserBatchAction string

const (
	AdminUserBatchEnable        AdminUserBatchAction = "enable"
	AdminUserBatchDisable       AdminUserBatchAction = "disable"
	AdminUserBatchVerifyEmail   AdminUserBatchAction = "verify_email"
	AdminUserBatchUnverifyEmail AdminUserBatchAction = "unverify_email"
	AdminUserBatchSoftDelete    AdminUserBatchAction = "soft_delete"
	AdminUserBatchHardDelete    AdminUserBatchAction = "hard_delete"
	AdminUserBatchRestore       AdminUserBatchAction = "restore"
)

// ValidAdminUserBatchAction 报告动作是否属于用户批量命令白名单。
func ValidAdminUserBatchAction(action string) bool {
	switch AdminUserBatchAction(action) {
	case AdminUserBatchEnable, AdminUserBatchDisable,
		AdminUserBatchVerifyEmail, AdminUserBatchUnverifyEmail,
		AdminUserBatchSoftDelete, AdminUserBatchHardDelete, AdminUserBatchRestore:
		return true
	default:
		return false
	}
}

// AdminUserBatchInput 是管理员用户批量管理服务输入。
type AdminUserBatchInput struct {
	ActingID int64
	IDs      []int64
	Action   AdminUserBatchAction
	Confirm  bool
}

// AdminBatchUsers 在一个数据库事务内执行用户批量命令。
// 所有目标按稳定 ID 顺序校验和写入；任一目标失败都会回滚整批。
// 授权缓存只在事务成功提交后失效。
func (s *Service) AdminBatchUsers(ctx context.Context, input AdminUserBatchInput) (*domain.BatchResult, error) {
	if input.ActingID <= 0 || len(input.IDs) == 0 || len(input.IDs) > maxUserBatchLimit || !ValidAdminUserBatchAction(string(input.Action)) {
		return nil, domain.ErrValidation
	}
	if (input.Action == AdminUserBatchSoftDelete || input.Action == AdminUserBatchHardDelete) && !input.Confirm {
		return nil, domain.ErrConfirmationRequired
	}

	ids := append([]int64(nil), input.IDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i, id := range ids {
		if id <= 0 || (i > 0 && ids[i-1] == id) {
			return nil, domain.ErrValidation
		}
	}

	result := &domain.BatchResult{Action: string(input.Action), RequestedCount: len(ids)}
	changedAuthz := make([]int64, 0, len(ids))
	err := s.txRunner.RunInTx(ctx, func(txCtx context.Context) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		for _, id := range ids {
			user, findErr := s.users.FindByID(txCtx, id)
			if findErr != nil {
				return &domain.ResourceError{ResourceID: id, Err: findErr}
			}

			changed, authzChanged, actionErr := s.applyAdminUserBatchAction(txCtx, input.ActingID, user, input.Action, now)
			if actionErr != nil {
				return &domain.ResourceError{ResourceID: id, Err: actionErr}
			}
			if changed {
				result.ChangedCount++
			} else {
				result.UnchangedCount++
			}
			if authzChanged {
				changedAuthz = append(changedAuthz, id)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	for _, id := range changedAuthz {
		if err := s.invalidateAuthz(ctx, id); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// applyAdminUserBatchAction 返回实际写入与是否需要失效授权缓存。
func (s *Service) applyAdminUserBatchAction(ctx context.Context, actingID int64, user *domain.User, action AdminUserBatchAction, now time.Time) (changed, authzChanged bool, err error) {
	if user == nil {
		return false, false, domain.ErrNotFound
	}

	switch action {
	case AdminUserBatchEnable, AdminUserBatchDisable,
		AdminUserBatchVerifyEmail, AdminUserBatchUnverifyEmail:
		if user.Status == domain.UserStatusDeleted {
			return false, false, domain.ErrConflict
		}
	}

	switch action {
	case AdminUserBatchEnable:
		if user.Status == domain.UserStatusActive {
			return false, false, nil
		}
		if err := s.ensureNotLastActiveAdmin(ctx, user, domain.UserStatusActive); err != nil {
			return false, false, err
		}
		if err := s.users.UpdateAdmin(ctx, user.ID, map[string]any{"status": domain.UserStatusActive}); err != nil {
			return false, false, err
		}
		return true, true, nil

	case AdminUserBatchDisable:
		if user.Status == domain.UserStatusDisabled {
			return false, false, nil
		}
		if err := s.ensureNotLastActiveAdmin(ctx, user, domain.UserStatusDisabled); err != nil {
			return false, false, err
		}
		if err := s.users.UpdateAdmin(ctx, user.ID, map[string]any{"status": domain.UserStatusDisabled}); err != nil {
			return false, false, err
		}
		return true, true, nil

	case AdminUserBatchVerifyEmail:
		if user.EmailVerifiedAt != nil {
			return false, false, nil
		}
		changed, err := s.users.MarkEmailVerified(ctx, user.ID, now)
		return changed, false, err

	case AdminUserBatchUnverifyEmail:
		if user.EmailVerifiedAt == nil {
			return false, false, nil
		}
		if err := s.users.UpdateAdmin(ctx, user.ID, map[string]any{"email_verified_at": nil}); err != nil {
			return false, false, err
		}
		return true, false, nil

	case AdminUserBatchSoftDelete:
		changed, err := s.applyAdminUserDeleteInTx(ctx, actingID, user, domain.UserDeleteModeSoft, true, now)
		return changed, changed, err

	case AdminUserBatchHardDelete:
		changed, err := s.applyAdminUserDeleteInTx(ctx, actingID, user, domain.UserDeleteModeHard, true, now)
		return changed, changed, err

	case AdminUserBatchRestore:
		changed, err := s.restoreAdminUserInTx(ctx, user)
		return changed, changed, err

	default:
		return false, false, domain.ErrValidation
	}
}

// applyAdminUserDeleteInTx performs the shared account/comment deletion
// transition. The caller must already be inside the database transaction.
func (s *Service) applyAdminUserDeleteInTx(ctx context.Context, actingID int64, user *domain.User, mode string, confirm bool, now time.Time) (bool, error) {
	if user == nil {
		return false, domain.ErrNotFound
	}
	if actingID == user.ID {
		return false, domain.ErrForbidden
	}
	if mode != domain.UserDeleteModeSoft && mode != domain.UserDeleteModeHard {
		return false, domain.ErrValidation
	}
	if mode == domain.UserDeleteModeHard && !confirm {
		return false, domain.ErrConfirmationRequired
	}
	if mode == domain.UserDeleteModeSoft && user.Status == domain.UserStatusDeleted {
		return false, nil
	}
	if err := s.ensureNotLastActiveAdmin(ctx, user, domain.UserStatusDeleted); err != nil {
		return false, err
	}
	if mode == domain.UserDeleteModeHard {
		if s.commentDeleter != nil {
			if err := s.commentDeleter.PrepareUserHardDelete(ctx, user.ID); err != nil {
				return false, err
			}
		}
		if err := s.users.Delete(ctx, user.ID); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := s.users.SoftDelete(ctx, user.ID, user.Status, now); err != nil {
		return false, err
	}
	if s.commentDeleter != nil {
		if err := s.commentDeleter.SoftDeleteUserComments(ctx, user.ID); err != nil {
			return false, err
		}
	}
	return true, nil
}

// restoreAdminUserInTx restores only the account lifecycle. It returns false
// for an already-live account so batch callers can count a no-op while the
// single-user entry point can preserve its conflict response.
func (s *Service) restoreAdminUserInTx(ctx context.Context, user *domain.User) (bool, error) {
	if user == nil {
		return false, domain.ErrNotFound
	}
	if user.Status != domain.UserStatusDeleted {
		return false, nil
	}
	if err := s.users.Restore(ctx, user.ID); err != nil {
		return false, err
	}
	return true, nil
}

// ensureNotLastActiveAdmin enforces the guard for transitions that remove an
// active administrator. The desired status is passed explicitly so callers
// cannot accidentally apply the guard to a no-op or a non-admin user.
func (s *Service) ensureNotLastActiveAdmin(ctx context.Context, user *domain.User, nextStatus domain.UserStatus) error {
	if user.Role != domain.RoleAdmin || user.Status != domain.UserStatusActive || nextStatus == domain.UserStatusActive {
		return nil
	}
	count, err := s.users.CountByRoleAndStatus(ctx, domain.RoleAdmin, domain.UserStatusActive)
	if err != nil {
		return err
	}
	if count <= 1 {
		return domain.ErrLastAdmin
	}
	return nil
}

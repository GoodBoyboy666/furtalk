package identity

import (
	"context"
	"fmt"
	"sort"
	"time"

	"furtalk/internal/domain"
)

const maxUserBatchLimit = 100

// AdminUserBatchAction 管理员用户批量命令的受控动作集合。
// 角色不属于批量操作；角色编辑仍只通过单条用户更新命令完成。
type AdminUserBatchAction string

// AdminUserBatchAction 的取值定义用户批量命令支持的动作。
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

// AdminUserBatchInput 管理员用户批量管理服务输入。
type AdminUserBatchInput struct {
	ActingID int64
	IDs      []int64
	Action   AdminUserBatchAction
	Confirm  bool
}

// AdminBatchUsers 在一个数据库事务内执行用户批量命令。
func (s *Service) AdminBatchUsers(ctx context.Context, input AdminUserBatchInput) (*domain.BatchResult, error) {
	// 目标一次锁定读取，所有业务校验通过后按字段分组复数写入；授权缓存只在提交后失效。
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
	changedIDs := make([]int64, 0, len(ids))
	activeAdminCount := int64(0)
	destructive := input.Action == AdminUserBatchDisable || input.Action == AdminUserBatchSoftDelete || input.Action == AdminUserBatchHardDelete
	transaction := s.txRunner.RunInTx
	if destructive {
		err := s.runAdminMutationWithActiveAdminCount(ctx, func(txCtx context.Context, count int64) error {
			activeAdminCount = count
			return s.applyAdminUserBatchPlan(txCtx, input, ids, result, &changedAuthz, &changedIDs, &activeAdminCount)
		})
		if err != nil {
			return nil, err
		}
	} else {
		err := transaction(ctx, func(txCtx context.Context) error {
			return s.applyAdminUserBatchPlan(txCtx, input, ids, result, &changedAuthz, &changedIDs, &activeAdminCount)
		})
		if err != nil {
			return nil, err
		}
	}

	for _, id := range changedAuthz {
		if err := s.invalidateAuthz(ctx, id); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// applyAdminUserBatchPlan 锁定并加载目标集合，校验动作后执行有界分组写入。
func (s *Service) applyAdminUserBatchPlan(ctx context.Context, input AdminUserBatchInput, ids []int64, result *domain.BatchResult, changedAuthz, changedIDs *[]int64, activeAdminCount *int64) error {
	// destructive action 的活跃管理员数量由 runAdminMutation 提供，供计划阶段模拟递减。
	users, err := s.users.FindByIDsLocked(ctx, ids)
	if err != nil {
		return err
	}
	byID := make(map[int64]*domain.User, len(users))
	for i := range users {
		user := users[i]
		byID[user.ID] = &user
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	statusIDs := make([]int64, 0, len(ids))
	verifyIDs := make([]int64, 0, len(ids))
	unverifyIDs := make([]int64, 0, len(ids))
	for _, id := range ids {
		user := byID[id]
		if user == nil {
			return &domain.ResourceError{ResourceID: id, Err: domain.ErrNotFound}
		}

		changed, authzChanged, actionErr := planAdminUserBatchAction(input.ActingID, user, input.Action, activeAdminCount)
		if actionErr != nil {
			return &domain.ResourceError{ResourceID: id, Err: actionErr}
		}
		if !changed {
			result.UnchangedCount++
			continue
		}
		result.ChangedCount++
		*changedIDs = append(*changedIDs, id)
		if authzChanged {
			*changedAuthz = append(*changedAuthz, id)
		}
		switch input.Action {
		case AdminUserBatchEnable, AdminUserBatchDisable, AdminUserBatchSoftDelete, AdminUserBatchRestore:
			statusIDs = append(statusIDs, id)
		case AdminUserBatchVerifyEmail:
			verifyIDs = append(verifyIDs, id)
		case AdminUserBatchUnverifyEmail:
			unverifyIDs = append(unverifyIDs, id)
		}
	}

	switch input.Action {
	case AdminUserBatchEnable:
		affected, writeErr := s.users.UpdateStatusMany(ctx, statusIDs, domain.UserStatusActive)
		if err := requireUserRows("enable users", affected, writeErr, len(statusIDs)); err != nil {
			return err
		}
	case AdminUserBatchDisable:
		affected, writeErr := s.users.UpdateStatusMany(ctx, statusIDs, domain.UserStatusDisabled)
		if err := requireUserRows("disable users", affected, writeErr, len(statusIDs)); err != nil {
			return err
		}
	case AdminUserBatchVerifyEmail:
		affected, writeErr := s.users.MarkEmailVerifiedMany(ctx, verifyIDs, now)
		if err := requireUserRows("verify users", affected, writeErr, len(verifyIDs)); err != nil {
			return err
		}
	case AdminUserBatchUnverifyEmail:
		affected, writeErr := s.users.UnverifyEmailMany(ctx, unverifyIDs)
		if err := requireUserRows("unverify users", affected, writeErr, len(unverifyIDs)); err != nil {
			return err
		}
	case AdminUserBatchSoftDelete:
		affected, writeErr := s.users.SoftDeleteMany(ctx, *changedIDs, now)
		if err := requireUserRows("soft delete users", affected, writeErr, len(*changedIDs)); err != nil {
			return err
		}
		if s.commentDeleter != nil {
			if err := s.commentDeleter.SoftDeleteUsersComments(ctx, *changedIDs); err != nil {
				return err
			}
		}
	case AdminUserBatchHardDelete:
		if s.commentDeleter != nil {
			if err := s.commentDeleter.PrepareUsersHardDelete(ctx, *changedIDs); err != nil {
				return err
			}
		}
		affected, writeErr := s.users.DeleteMany(ctx, *changedIDs)
		if err := requireUserRows("hard delete users", affected, writeErr, len(*changedIDs)); err != nil {
			return err
		}
	case AdminUserBatchRestore:
		affected, writeErr := s.users.RestoreMany(ctx, statusIDs)
		if err := requireUserRows("restore users", affected, writeErr, len(statusIDs)); err != nil {
			return err
		}
	}
	return nil
}

// planAdminUserBatchAction 校验单个用户动作并生成变化标记。
func planAdminUserBatchAction(actingID int64, user *domain.User, action AdminUserBatchAction, activeAdminCount *int64) (changed, authzChanged bool, err error) {
	// destructive action 按排序目标递减 activeAdminCount，保持第一个失败 ID 的最后管理员语义。
	if user == nil {
		return false, false, domain.ErrNotFound
	}
	switch action {
	case AdminUserBatchEnable, AdminUserBatchDisable, AdminUserBatchVerifyEmail, AdminUserBatchUnverifyEmail:
		if user.Status == domain.UserStatusDeleted {
			return false, false, domain.ErrConflict
		}
	}
	switch action {
	case AdminUserBatchEnable:
		return user.Status != domain.UserStatusActive, user.Status != domain.UserStatusActive, nil
	case AdminUserBatchDisable:
		if user.Status == domain.UserStatusDisabled {
			return false, false, nil
		}
		if err := planAdminAdminRemoval(user, domain.UserStatusDisabled, activeAdminCount); err != nil {
			return false, false, err
		}
		return true, true, nil
	case AdminUserBatchVerifyEmail:
		return user.EmailVerifiedAt == nil, false, nil
	case AdminUserBatchUnverifyEmail:
		return user.EmailVerifiedAt != nil, false, nil
	case AdminUserBatchSoftDelete:
		if actingID == user.ID {
			return false, false, domain.ErrForbidden
		}
		if user.Status == domain.UserStatusDeleted {
			return false, false, nil
		}
		if err := planAdminAdminRemoval(user, domain.UserStatusDeleted, activeAdminCount); err != nil {
			return false, false, err
		}
		return true, true, nil
	case AdminUserBatchHardDelete:
		if actingID == user.ID {
			return false, false, domain.ErrForbidden
		}
		if err := planAdminAdminRemoval(user, domain.UserStatusDeleted, activeAdminCount); err != nil {
			return false, false, err
		}
		return true, true, nil
	case AdminUserBatchRestore:
		return user.Status == domain.UserStatusDeleted, user.Status == domain.UserStatusDeleted, nil
	default:
		return false, false, domain.ErrValidation
	}
}

// planAdminAdminRemoval 模拟移除一个活跃管理员并检查最后管理员保护。
func planAdminAdminRemoval(user *domain.User, nextStatus domain.UserStatus, activeAdminCount *int64) error {
	if user.Role != domain.RoleAdmin || user.Status != domain.UserStatusActive || nextStatus == domain.UserStatusActive {
		return nil
	}
	if activeAdminCount == nil {
		return domain.ErrLastAdmin
	}
	if *activeAdminCount <= 1 {
		return domain.ErrLastAdmin
	}
	*activeAdminCount = *activeAdminCount - 1
	return nil
}

// requireUserRows 校验批量用户写入的实际影响行数。
func requireUserRows(operation string, count int64, err error, expected int) error {
	if err != nil {
		return err
	}
	if count != int64(expected) {
		return fmt.Errorf("%s affected %d rows, expected %d", operation, count, expected)
	}
	return nil
}

// applyAdminUserDeleteInTx 执行单用户账号与评论删除转换。
func (s *Service) applyAdminUserDeleteInTx(ctx context.Context, actingID int64, user *domain.User, mode string, confirm bool, now time.Time) (bool, error) {
	// 批量管理使用上面的复数 repository 原语；此 helper 保留单用户窄接口。
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

// restoreAdminUserInTx 恢复单个用户账号生命周期并返回是否发生变化。
func (s *Service) restoreAdminUserInTx(ctx context.Context, user *domain.User) (bool, error) {
	// 已存活账号返回 false，批量入口计为 no-op，单用户入口再映射为冲突。
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

// ensureNotLastActiveAdmin 为单用户转换执行最后活跃管理员保护。
func (s *Service) ensureNotLastActiveAdmin(ctx context.Context, user *domain.User, nextStatus domain.UserStatus) error {
	// 批量转换使用锁定的活跃管理员数量和排序模拟。
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

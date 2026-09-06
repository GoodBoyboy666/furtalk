package comment

import (
	"context"
	"sort"

	"furtalk/internal/domain"
)

// AdminBatchThreads 在单个数据库事务内执行站点作用域的评论区批量命令。
func (s *Service) AdminBatchThreads(ctx context.Context, siteID int64, input AdminThreadBatchInput) (*domain.BatchResult, error) {
	// 目标一次锁定读取，预校验全部通过后才执行复数写入。
	if siteID <= 0 || len(input.IDs) == 0 || len(input.IDs) > maxLimit || !ValidAdminThreadBatchAction(string(input.Action)) {
		return nil, domain.ErrValidation
	}
	if input.Action == AdminThreadBatchHardDelete && !input.Confirm {
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
	err := s.txRunner.RunInTx(ctx, func(txCtx context.Context) error {
		threads, err := s.threads.GetBySiteAndIDsLocked(txCtx, siteID, ids)
		if err != nil {
			return err
		}
		byID := make(map[int64]*domain.Thread, len(threads))
		for i := range threads {
			thread := threads[i]
			byID[thread.ID] = &thread
		}

		writeIDs := make([]int64, 0, len(ids))
		for _, id := range ids {
			thread := byID[id]
			if thread == nil {
				return &domain.ResourceError{ResourceID: id, Err: domain.ErrNotFound}
			}
			changed, actionErr := planAdminThreadBatchAction(thread, input.Action)
			if actionErr != nil {
				return &domain.ResourceError{ResourceID: id, Err: actionErr}
			}
			if changed {
				result.ChangedCount++
				writeIDs = append(writeIDs, id)
			} else {
				result.UnchangedCount++
			}
		}

		if input.Action == AdminThreadBatchHardDelete {
			affected, writeErr := s.threads.DeleteThreads(txCtx, siteID, writeIDs)
			return requireRows("delete threads", affected, writeErr, len(writeIDs))
		}
		enabled := input.Action == AdminThreadBatchEnable
		affected, writeErr := s.threads.UpdateCommentsEnabledMany(txCtx, siteID, writeIDs, enabled)
		return requireRows("update thread comments enabled", affected, writeErr, len(writeIDs))
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// planAdminThreadBatchAction 返回目标是否需要写入。
func planAdminThreadBatchAction(thread *domain.Thread, action AdminThreadBatchAction) (bool, error) {
	// 站点范围读取完成后，评论区批量动作没有额外业务冲突。
	if thread == nil {
		return false, domain.ErrNotFound
	}
	switch action {
	case AdminThreadBatchEnable:
		return !thread.CommentsEnabled, nil
	case AdminThreadBatchDisable:
		return thread.CommentsEnabled, nil
	case AdminThreadBatchHardDelete:
		return true, nil
	default:
		return false, domain.ErrValidation
	}
}

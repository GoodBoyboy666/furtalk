package comment

import (
	"context"
	"sort"

	"furtalk/internal/domain"
)

// AdminBatchThreads 在单个数据库事务内执行站点作用域的评论区批量命令。
// 目标按稳定 ID 顺序读取；任一目标缺失、跨站点或写入失败都会回滚整批。
func (s *Service) AdminBatchThreads(ctx context.Context, siteID int64, input AdminThreadBatchInput) (*domain.BatchResult, error) {
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

	result := &domain.BatchResult{
		Action:         string(input.Action),
		RequestedCount: len(ids),
	}
	err := s.txRunner.RunInTx(ctx, func(txCtx context.Context) error {
		for _, id := range ids {
			thread, findErr := s.threads.GetBySiteAndID(txCtx, siteID, id)
			if findErr != nil {
				return &domain.ResourceError{ResourceID: id, Err: findErr}
			}

			changed, actionErr := s.applyAdminThreadBatchAction(txCtx, siteID, thread, input.Action)
			if actionErr != nil {
				return &domain.ResourceError{ResourceID: id, Err: actionErr}
			}
			if changed {
				result.ChangedCount++
			} else {
				result.UnchangedCount++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// applyAdminThreadBatchAction 返回是否实际写入。
func (s *Service) applyAdminThreadBatchAction(ctx context.Context, siteID int64, thread *domain.Thread, action AdminThreadBatchAction) (bool, error) {
	if thread == nil {
		return false, domain.ErrNotFound
	}
	switch action {
	case AdminThreadBatchEnable:
		if thread.CommentsEnabled {
			return false, nil
		}
		if _, err := s.threads.UpdateCommentsEnabled(ctx, siteID, thread.ID, true); err != nil {
			return false, err
		}
		return true, nil
	case AdminThreadBatchDisable:
		if !thread.CommentsEnabled {
			return false, nil
		}
		if _, err := s.threads.UpdateCommentsEnabled(ctx, siteID, thread.ID, false); err != nil {
			return false, err
		}
		return true, nil
	case AdminThreadBatchHardDelete:
		if err := s.threads.DeleteThread(ctx, siteID, thread.ID); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, domain.ErrValidation
	}
}

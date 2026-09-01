package comment

import (
	"context"
	"sort"
	"time"

	"furtalk/internal/domain"
)

// AdminBatch 批量执行评论管理命令。
// 所有目标都在同一个数据库事务中按稳定 ID 顺序校验和写入
func (s *Service) AdminBatch(ctx context.Context, input AdminBatchInput) (*domain.BatchResult, error) {
	if len(input.IDs) == 0 || len(input.IDs) > maxLimit || !ValidAdminBatchAction(string(input.Action)) {
		return nil, domain.ErrValidation
	}
	if (input.Action == AdminBatchSoftDelete || input.Action == AdminBatchHardDelete) && !input.Confirm {
		return nil, domain.ErrConfirmationRequired
	}

	ids := append([]int64(nil), input.IDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i, id := range ids {
		if id <= 0 || (i > 0 && ids[i-1] == id) {
			return nil, domain.ErrValidation
		}
	}

	var policy domain.CommentPolicy
	var err error
	if input.Action == AdminBatchPublish {
		policy, err = s.settings.CommentPolicy(ctx)
		if err != nil {
			return nil, err
		}
	}

	result := &domain.BatchResult{
		Action:         string(input.Action),
		RequestedCount: len(ids),
	}
	published := make([]*domain.Comment, 0)
	err = s.txRunner.RunInTx(ctx, func(txCtx context.Context) error {
		now := s.now().UTC()
		for _, id := range ids {
			comment, findErr := s.comments.FindGlobalByID(txCtx, id)
			if findErr != nil {
				return &domain.ResourceError{ResourceID: id, Err: findErr}
			}

			changed, actionErr := s.applyAdminBatchAction(txCtx, comment, input.Action, now)
			if actionErr != nil {
				return &domain.ResourceError{ResourceID: id, Err: actionErr}
			}
			if changed {
				result.ChangedCount++
				if input.Action == AdminBatchPublish {
					updated, reloadErr := s.comments.FindGlobalByID(txCtx, id)
					if reloadErr != nil {
						return &domain.ResourceError{ResourceID: id, Err: reloadErr}
					}
					published = append(published, updated)
				}
			} else {
				result.UnchangedCount++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if input.Action == AdminBatchPublish && policy.Moderation == domain.ModerationReview {
		for _, comment := range published {
			s.publishCommentPublished(ctx, comment, policy.Mode)
		}
	}
	return result, nil
}

// applyAdminBatchAction 应用批量动作并返回是否发生实际写入。
func (s *Service) applyAdminBatchAction(ctx context.Context, comment *domain.Comment, action AdminBatchAction, now time.Time) (bool, error) {
	if comment == nil {
		return false, domain.ErrNotFound
	}
	switch action {
	case AdminBatchPending:
		if comment.Status == domain.CommentStatusPending {
			return false, nil
		}
		return s.applyAdminTransition(ctx, comment, actionPending, now)
	case AdminBatchPublish:
		if comment.Status == domain.CommentStatusPublished {
			return false, nil
		}
		return s.applyAdminTransition(ctx, comment, actionPublish, now)
	case AdminBatchSpam:
		if comment.Status == domain.CommentStatusSpam {
			return false, nil
		}
		return s.applyAdminTransition(ctx, comment, actionSpam, now)
	case AdminBatchSoftDelete:
		if comment.Status == domain.CommentStatusDeleted {
			return false, nil
		}
		return s.applyAdminTransition(ctx, comment, actionSoftDelete, now)
	case AdminBatchRestore:
		return s.applyAdminTransition(ctx, comment, actionRestore, now)
	case AdminBatchHardDelete:
		if err := s.hardDeleteInCurrentTx(ctx, comment.SiteID, comment.ID); err != nil {
			return false, err
		}
		return true, nil
	case AdminBatchPin:
		if err := validatePinTarget(comment, true); err != nil {
			return false, err
		}
		if comment.IsPinned {
			return false, nil
		}
		if _, err := s.comments.SetPinned(ctx, comment.SiteID, comment.ID, true); err != nil {
			return false, err
		}
		return true, nil
	case AdminBatchUnpin:
		if err := validatePinTarget(comment, false); err != nil {
			return false, err
		}
		if !comment.IsPinned {
			return false, nil
		}
		if _, err := s.comments.SetPinned(ctx, comment.SiteID, comment.ID, false); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, domain.ErrValidation
	}
}

// hardDeleteInCurrentTx 解除回复引用并删除目标行；调用方已经位于外层事务。
func (s *Service) hardDeleteInCurrentTx(ctx context.Context, siteID, id int64) error {
	if err := s.comments.DetachCommentChildren(ctx, siteID, id); err != nil {
		return err
	}
	return s.comments.HardDelete(ctx, siteID, id)
}

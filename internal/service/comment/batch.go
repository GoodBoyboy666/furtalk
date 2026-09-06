package comment

import (
	"context"
	"fmt"
	"sort"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
)

// AdminBatch 批量执行评论管理命令。
func (s *Service) AdminBatch(ctx context.Context, input AdminBatchInput) (*domain.BatchResult, error) {
	// 目标在事务内一次锁定读取，业务校验全部通过后再执行有限数量的复数写入。
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
	var published []*domain.Comment
	err = s.txRunner.RunInTx(ctx, func(txCtx context.Context) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		comments, err := s.comments.FindGlobalByIDsLocked(txCtx, ids)
		if err != nil {
			// 单条 SQL 覆盖完整读取；基础设施错误无法诚实归因到某个 ID。
			return err
		}
		byID := make(map[int64]*domain.Comment, len(comments))
		for i := range comments {
			comment := comments[i]
			byID[comment.ID] = &comment
		}

		statusGroups := make(map[string][]repository.CommentStatusBatchTarget)
		pinTargets := make([]repository.CommentBatchTarget, 0, len(ids))
		deleteTargets := make([]repository.CommentBatchTarget, 0, len(ids))
		for _, id := range ids {
			comment := byID[id]
			if comment == nil {
				return &domain.ResourceError{ResourceID: id, Err: domain.ErrNotFound}
			}
			plan, changed, actionErr := planAdminBatchComment(comment, input.Action, now)
			if actionErr != nil {
				return &domain.ResourceError{ResourceID: id, Err: actionErr}
			}
			if !changed {
				result.UnchangedCount++
				continue
			}
			result.ChangedCount++
			switch input.Action {
			case AdminBatchPin, AdminBatchUnpin:
				pinTargets = append(pinTargets, repository.CommentBatchTarget{SiteID: comment.SiteID, ID: comment.ID})
			case AdminBatchHardDelete:
				deleteTargets = append(deleteTargets, repository.CommentBatchTarget{SiteID: comment.SiteID, ID: comment.ID})
			default:
				key := commentStatusBatchGroupKey(plan)
				statusGroups[key] = append(statusGroups[key], plan)
			}

			if input.Action == AdminBatchPublish {
				updated := *comment
				updated.Status = plan.Status
				updated.StatusBeforeDelete = plan.StatusBeforeDelete
				updated.PublishedAt = plan.PublishedAt
				updated.DeletedAt = plan.DeletedAt
				published = append(published, &updated)
			}
		}

		switch input.Action {
		case AdminBatchPin:
			affected, writeErr := s.comments.SetPinnedMany(txCtx, pinTargets, true)
			if err := requireRows("pin comments", affected, writeErr, len(pinTargets)); err != nil {
				return err
			}
		case AdminBatchUnpin:
			affected, writeErr := s.comments.SetPinnedMany(txCtx, pinTargets, false)
			if err := requireRows("unpin comments", affected, writeErr, len(pinTargets)); err != nil {
				return err
			}
		case AdminBatchHardDelete:
			if err := s.comments.DetachCommentChildrenMany(txCtx, deleteTargets); err != nil {
				return err
			}
			affected, writeErr := s.comments.HardDeleteMany(txCtx, deleteTargets)
			if err := requireRows("hard delete comments", affected, writeErr, len(deleteTargets)); err != nil {
				return err
			}
		default:
			keys := make([]string, 0, len(statusGroups))
			for key := range statusGroups {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				targets := statusGroups[key]
				affected, writeErr := s.comments.UpdateStatusMany(txCtx, targets)
				if err := requireRows("update comment statuses", affected, writeErr, len(targets)); err != nil {
					return err
				}
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

// planAdminBatchComment 校验单个动作并返回状态变更计划。
func planAdminBatchComment(comment *domain.Comment, action AdminBatchAction, now time.Time) (repository.CommentStatusBatchTarget, bool, error) {
	// 计划阶段只做内存校验，数据库 I/O 留给后续分组写入。
	if comment == nil {
		return repository.CommentStatusBatchTarget{}, false, domain.ErrNotFound
	}
	target := repository.CommentStatusBatchTarget{
		CommentBatchTarget: repository.CommentBatchTarget{SiteID: comment.SiteID, ID: comment.ID},
	}
	switch action {
	case AdminBatchPending:
		if comment.Status == domain.CommentStatusPending {
			return target, false, nil
		}
		if !canTransition(comment.Status, domain.CommentStatusPending) {
			return target, false, domain.ErrConflict
		}
		target.Status = domain.CommentStatusPending
	case AdminBatchPublish:
		if comment.Status == domain.CommentStatusPublished {
			return target, false, nil
		}
		if !canTransition(comment.Status, domain.CommentStatusPublished) {
			return target, false, domain.ErrConflict
		}
		target.Status = domain.CommentStatusPublished
		target.PublishedAt = &now
	case AdminBatchSpam:
		if comment.Status == domain.CommentStatusSpam {
			return target, false, nil
		}
		if !canTransition(comment.Status, domain.CommentStatusSpam) {
			return target, false, domain.ErrConflict
		}
		target.Status = domain.CommentStatusSpam
		target.PreservePublishedAt = true
	case AdminBatchSoftDelete:
		if comment.Status == domain.CommentStatusDeleted {
			return target, false, nil
		}
		if !canTransition(comment.Status, domain.CommentStatusDeleted) {
			return target, false, domain.ErrConflict
		}
		before := comment.Status
		target.Status = domain.CommentStatusDeleted
		target.StatusBeforeDelete = &before
		target.PreservePublishedAt = true
		target.DeletedAt = &now
	case AdminBatchRestore:
		if comment.Status != domain.CommentStatusDeleted || comment.StatusBeforeDelete == nil {
			return target, false, domain.ErrConflict
		}
		if *comment.StatusBeforeDelete != domain.CommentStatusPending &&
			*comment.StatusBeforeDelete != domain.CommentStatusPublished &&
			*comment.StatusBeforeDelete != domain.CommentStatusSpam {
			return target, false, domain.ErrConflict
		}
		target.Status = *comment.StatusBeforeDelete
		if target.Status == domain.CommentStatusPublished {
			target.PublishedAt = &now
		}
	case AdminBatchPin:
		if err := validatePinTarget(comment, true); err != nil {
			return target, false, err
		}
		if comment.IsPinned {
			return target, false, nil
		}
		return target, true, nil
	case AdminBatchUnpin:
		if err := validatePinTarget(comment, false); err != nil {
			return target, false, err
		}
		if !comment.IsPinned {
			return target, false, nil
		}
		return target, true, nil
	case AdminBatchHardDelete:
		return target, true, nil
	default:
		return target, false, domain.ErrValidation
	}
	return target, true, nil
}

// requireRows 校验批量写入的影响行数与预期一致。
func requireRows(operation string, count int64, err error, expected int) error {
	// 分组 SQL 无法准确定位单个目标，错误保持为批量事务错误。
	if err != nil {
		return err
	}
	if count != int64(expected) {
		return fmt.Errorf("%s affected %d rows, expected %d", operation, count, expected)
	}
	return nil
}

// commentStatusBatchGroupKey 描述状态变更实际写入的字段值。
func commentStatusBatchGroupKey(target repository.CommentStatusBatchTarget) string {
	// 分组数量限制在有限状态机范围内，并保留 spam/soft-delete 各行的发布时间。
	before := ""
	if target.StatusBeforeDelete != nil {
		before = string(*target.StatusBeforeDelete)
	}
	published := "clear"
	if target.PreservePublishedAt {
		published = "preserve"
	} else if target.PublishedAt != nil {
		published = "set"
	}
	deleted := "clear"
	if target.DeletedAt != nil {
		deleted = "set"
	}
	return string(target.Status) + "|" + before + "|" + published + "|" + deleted
}

// hardDeleteInCurrentTx 解除回复引用并删除目标行；调用方已经位于外层事务。
func (s *Service) hardDeleteInCurrentTx(ctx context.Context, siteID, id int64) error {
	if err := s.comments.DetachCommentChildren(ctx, siteID, id); err != nil {
		return err
	}
	return s.comments.HardDelete(ctx, siteID, id)
}

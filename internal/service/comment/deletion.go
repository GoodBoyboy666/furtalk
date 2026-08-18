package comment

import (
	"context"

	"furtalk/internal/domain"
)

// SoftDeleteUserComments 单行软删除该用户发表的全部评论，不处理其他用户的回复。
// 供身份服务在软删除用户时统一协调；已删除节点保持原状态。
func (s *Service) SoftDeleteUserComments(ctx context.Context, userID int64) error {
	return s.comments.SoftDeleteByUser(ctx, userID, s.now())
}

// PrepareUserHardDelete 在物理删除用户前解除保留评论对该用户评论的
// parent_id / root_id 引用，使删除只级联移除该用户自己的评论。
// 供身份服务在硬删除用户时统一协调，须与用户行删除在同一事务内。
func (s *Service) PrepareUserHardDelete(ctx context.Context, userID int64) error {
	return s.comments.DetachUserCommentChildren(ctx, userID)
}

// DeleteByOwner 删除当前用户自己的某条评论，按 user_delete_mode 软删或硬删。
// 只处理选中评论；硬删除在同一事务内解除保留回复的引用并删除该行，
// 其回复保持原状态与正文。用户不能自行选择软删或硬删。
func (s *Service) DeleteByOwner(ctx context.Context, actorID, commentID int64, wantSiteID *int64) (*DeleteResult, error) {
	comment, err := s.comments.FindGlobalByID(ctx, commentID)
	if err != nil {
		return nil, err
	}
	if wantSiteID != nil && comment.SiteID != *wantSiteID {
		return nil, domain.ErrNotFound
	}
	if comment.UserID != actorID {
		return nil, domain.ErrForbidden
	}
	if comment.Status == domain.CommentStatusDeleted {
		return nil, domain.ErrConflict
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if pol.UserDeleteMode == domain.UserDeleteModeHard {
		if err := s.hardDeleteOne(ctx, comment.SiteID, commentID); err != nil {
			return nil, err
		}
		return &DeleteResult{DeletedRootID: commentID, Hard: true}, nil
	}
	if err := s.softDeleteOne(ctx, comment.SiteID, comment); err != nil {
		return nil, err
	}
	return &DeleteResult{DeletedRootID: commentID, Hard: false}, nil
}

// AdminDelete 按管理员选择的模式删除单条评论；软删除保留占位节点，
// 硬删除需显式确认且只删除选中行。回复评论保持原状态。
func (s *Service) AdminDelete(ctx context.Context, id int64, hard, confirm bool) (*DeleteResult, error) {
	if hard && !confirm {
		return nil, domain.ErrConfirmationRequired
	}
	comment, err := s.comments.FindGlobalByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if hard {
		if err := s.hardDeleteOne(ctx, comment.SiteID, id); err != nil {
			return nil, err
		}
		return &DeleteResult{DeletedRootID: id, Hard: true}, nil
	}
	// 已软删除的评论再次软删除属于非法转换（409），
	// 与四状态状态机中的 same-state 冲突语义一致；硬删除仍可清理占位节点。
	if comment.Status == domain.CommentStatusDeleted {
		return nil, domain.ErrConflict
	}
	if err := s.softDeleteOne(ctx, comment.SiteID, comment); err != nil {
		return nil, err
	}
	return &DeleteResult{DeletedRootID: id, Hard: false}, nil
}

// softDeleteOne 单行软删除选中评论，保留删除前状态、发布时间与删除时间。
func (s *Service) softDeleteOne(ctx context.Context, siteID int64, comment *domain.Comment) error {
	before := comment.Status
	now := s.now()
	return s.comments.UpdateStatus(ctx, siteID, comment.ID, domain.CommentStatusDeleted, &before, comment.PublishedAt, &now)
}

// hardDeleteOne 在同一事务内解除保留回复对目标评论的 parent_id / root_id
// 引用，然后只删除目标行。任一步失败整体回滚。
func (s *Service) hardDeleteOne(ctx context.Context, siteID, id int64) error {
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.comments.DetachCommentChildren(ctx, siteID, id); err != nil {
			return err
		}
		return s.comments.HardDelete(ctx, siteID, id)
	})
}

package comment

import (
	"context"

	"furtalk/internal/domain"
)

// AdminSetPinned 通过管理员 API 修改评论置顶状态。
// 路由负责管理员门禁；此方法负责评论根节点、状态和幂等规则。
func (s *Service) AdminSetPinned(ctx context.Context, commentID int64, pinned bool) (*AdminCommentView, error) {
	comment, err := s.comments.FindGlobalByID(ctx, commentID)
	if err != nil {
		return nil, err
	}
	if err := validatePinTarget(comment, pinned); err != nil {
		return nil, err
	}
	updated, err := s.comments.SetPinned(ctx, comment.SiteID, comment.ID, pinned)
	if err != nil {
		return nil, err
	}
	return s.adminViewFor(ctx, updated)
}

// WidgetSetPinned 使用站点绑定的 Widget 凭据修改评论置顶状态。
// principal 由 Widget 中间件实时解析，不能从请求数据或 JWT 自行推导角色。
func (s *Service) WidgetSetPinned(ctx context.Context, principal domain.Principal, siteID, commentID int64, pinned bool) (*PinResult, error) {
	if principal.Status != domain.UserStatusActive || principal.Role != domain.RoleAdmin {
		return nil, domain.ErrForbidden
	}
	comment, err := s.comments.FindBySiteAndID(ctx, siteID, commentID)
	if err != nil {
		return nil, err
	}
	if err := validatePinTarget(comment, pinned); err != nil {
		return nil, err
	}
	updated, err := s.comments.SetPinned(ctx, siteID, commentID, pinned)
	if err != nil {
		return nil, err
	}
	return &PinResult{CommentID: updated.ID, IsPinned: updated.IsPinned}, nil
}

// validatePinTarget 在服务层显式维护根评论约束，数据库 CHECK 作为最终防线。
// 取消置顶允许任意审核状态的根评论，便于清理隐藏的置顶评论。
func validatePinTarget(comment *domain.Comment, pinned bool) error {
	if comment == nil || comment.ParentID != nil || comment.RootID != nil || comment.Depth != 0 {
		return domain.ErrConflict
	}
	if pinned && comment.Status != domain.CommentStatusPublished {
		return domain.ErrConflict
	}
	return nil
}

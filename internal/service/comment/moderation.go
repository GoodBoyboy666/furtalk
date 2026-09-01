package comment

import (
	"context"
	"errors"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gravatar"
)

// adminAction 标识一个审核转换。
type adminAction int

// 审核动作枚举。
const (
	actionPublish adminAction = iota
	actionSpam
	actionSoftDelete
	actionRestore
	actionPending
)

// canTransition 报告数据模型状态机是否允许直接转换。
// 管理员可显式把评论从四个状态中的任意一个移动到任意另一个状态；
// 相同状态请求始终冲突，不会静默改写时间戳。
func canTransition(from, to domain.CommentStatus) bool {
	if from == to {
		return false
	}
	switch to {
	case domain.CommentStatusPending, domain.CommentStatusPublished, domain.CommentStatusSpam:
		// pending/spam/published 互相转换，且可以从 deleted 显式恢复为任一活动状态。
		return true
	case domain.CommentStatusDeleted:
		// 进入 deleted 只允许来自活动状态；deleted -> deleted 冲突。
		return from == domain.CommentStatusPending || from == domain.CommentStatusPublished || from == domain.CommentStatusSpam
	default:
		return false
	}
}

// AdminList 过滤并按页码分页所有评论，关联作者邮箱并返回匹配总数。
func (s *Service) AdminList(ctx context.Context, filter domain.AdminFilter, page int) (*AdminListResult, error) {
	limit := normalizeLimit(filter.Limit)
	filter.Limit = limit
	filter.Offset = domain.OffsetForPage(page, limit)
	if filter.Sort == "" {
		filter.Sort = domain.CommentSortDesc
	}
	rows, err := s.comments.ListAdmin(ctx, filter)
	if err != nil {
		return nil, err
	}
	total, err := s.comments.CountAdmin(ctx, filter)
	if err != nil {
		return nil, err
	}
	gravatarBase, err := s.avatarBaseURL(ctx)
	if err != nil {
		return nil, err
	}
	result := &AdminListResult{Comments: make([]AdminCommentView, 0, len(rows)), Total: total}
	for _, r := range rows {
		result.Comments = append(result.Comments, AdminCommentView{
			CommentView: toCommentViewWithReply(&r.Comment, r.AuthorNickname, r.AuthorWebsite, r.AuthorRole,
				gravatar.URL(r.AuthorEmailNormalized, gravatarBase), r.ReplyToNickname, 0, false),
			Email:     r.AuthorEmail,
			IPMode:    r.IPMode,
			IPValue:   r.IPValue,
			UAMode:    r.UAMode,
			UARaw:     r.UARaw,
			UABrowser: r.UABrowser,
			UAOS:      r.UAOS,
			UADevice:  r.UADevice,
		})
	}
	return result, nil
}

// AdminGet 返回一条带管理员独有邮箱和隐私字段的评论。
func (s *Service) AdminGet(ctx context.Context, id int64) (*AdminCommentView, error) {
	comment, err := s.comments.FindGlobalByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.adminViewFor(ctx, comment)
}

// AdminEditBody 只编辑 Markdown 正文并保持当前状态。
func (s *Service) AdminEditBody(ctx context.Context, id int64, body string) (*AdminCommentView, error) {
	if err := validateBody(body); err != nil {
		return nil, err
	}
	comment, err := s.comments.FindGlobalByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.comments.UpdateBody(ctx, comment.SiteID, id, body); err != nil {
		return nil, err
	}
	updated, err := s.comments.FindGlobalByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.adminViewFor(ctx, updated)
}

// AdminPublish 把评论发布为 published。来源可以是 pending、spam 或 deleted；
// 离开 deleted 时只恢复目标单条。只有审核策略为 review 时才在提交后
// 发布 CommentPublished 事件；direct 策略下管理员发布不产生发布通知。
func (s *Service) AdminPublish(ctx context.Context, id int64) (*AdminCommentView, error) {
	comment, err := s.adminTransition(ctx, id, actionPublish)
	if err != nil {
		return nil, err
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if pol.Moderation == domain.ModerationReview {
		s.publishCommentPublished(ctx, comment, pol.Mode)
	}
	return s.adminViewFor(ctx, comment)
}

// AdminMarkSpam 把评论标记为 spam。来源可以是 pending、published 或 deleted；
// 保留历史 published_at，清除删除标记。
func (s *Service) AdminMarkSpam(ctx context.Context, id int64) (*AdminCommentView, error) {
	comment, err := s.adminTransition(ctx, id, actionSpam)
	if err != nil {
		return nil, err
	}
	return s.adminViewFor(ctx, comment)
}

// AdminPending 把评论移入待审核（pending）。来源可以是 published、spam 或
// deleted；离开 deleted 时只更新目标单条。
func (s *Service) AdminPending(ctx context.Context, id int64) (*AdminCommentView, error) {
	comment, err := s.adminTransition(ctx, id, actionPending)
	if err != nil {
		return nil, err
	}
	return s.adminViewFor(ctx, comment)
}

// AdminRestore 恢复已删除的单条评论：回到删除前状态，清除删除标记。
// 只恢复目标单条，其他评论保持原状态。
func (s *Service) AdminRestore(ctx context.Context, id int64) (*AdminCommentView, error) {
	comment, err := s.adminTransition(ctx, id, actionRestore)
	if err != nil {
		return nil, err
	}
	return s.adminViewFor(ctx, comment)
}

// adminTransition 应用一个审核转换并返回更新后的评论。
func (s *Service) adminTransition(ctx context.Context, id int64, action adminAction) (*domain.Comment, error) {
	comment, err := s.comments.FindGlobalByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.applyAdminTransition(ctx, comment, action, s.now().UTC()); err != nil {
		return nil, err
	}
	updated, err := s.comments.FindGlobalByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// applyAdminTransition 在当前事务中把已加载评论移动到目标审核状态。
// 单条和批量入口共用该状态机；调用方负责在需要时处理 no-op 语义。
func (s *Service) applyAdminTransition(ctx context.Context, comment *domain.Comment, action adminAction, now time.Time) (bool, error) {
	if comment == nil {
		return false, domain.ErrNotFound
	}
	switch action {
	case actionPublish:
		if !canTransition(comment.Status, domain.CommentStatusPublished) {
			return false, domain.ErrConflict
		}
		if err := s.comments.UpdateStatus(ctx, comment.SiteID, comment.ID, domain.CommentStatusPublished, nil, &now, nil); err != nil {
			return false, err
		}
	case actionPending:
		if !canTransition(comment.Status, domain.CommentStatusPending) {
			return false, domain.ErrConflict
		}
		if err := s.comments.UpdateStatus(ctx, comment.SiteID, comment.ID, domain.CommentStatusPending, nil, nil, nil); err != nil {
			return false, err
		}
	case actionSpam:
		if !canTransition(comment.Status, domain.CommentStatusSpam) {
			return false, domain.ErrConflict
		}
		if err := s.comments.UpdateStatus(ctx, comment.SiteID, comment.ID, domain.CommentStatusSpam, nil, comment.PublishedAt, nil); err != nil {
			return false, err
		}
	case actionSoftDelete:
		if !canTransition(comment.Status, domain.CommentStatusDeleted) {
			return false, domain.ErrConflict
		}
		before := comment.Status
		if err := s.comments.UpdateStatus(ctx, comment.SiteID, comment.ID, domain.CommentStatusDeleted, &before, comment.PublishedAt, &now); err != nil {
			return false, err
		}
	case actionRestore:
		if comment.Status != domain.CommentStatusDeleted || comment.StatusBeforeDelete == nil {
			return false, domain.ErrConflict
		}
		target := *comment.StatusBeforeDelete
		var publishedAt *time.Time
		if target == domain.CommentStatusPublished {
			publishedAt = &now
		}
		if err := s.comments.UpdateStatus(ctx, comment.SiteID, comment.ID, target, nil, publishedAt, nil); err != nil {
			return false, err
		}
	default:
		return false, errors.New("comment: unknown moderation action")
	}
	return true, nil
}

// adminViewFor 加载作者资料并构建管理员视图。
func (s *Service) adminViewFor(ctx context.Context, comment *domain.Comment) (*AdminCommentView, error) {
	user, err := s.users.FindByID(ctx, comment.UserID)
	if err != nil {
		return nil, err
	}
	gravatarBase, err := s.avatarBaseURL(ctx)
	if err != nil {
		return nil, err
	}
	view := toCommentView(comment, user.Nickname, user.WebsiteURL, user.Role, gravatar.URL(user.EmailNormalized, gravatarBase))
	replyNickname, err := s.replyToNickname(ctx, comment)
	if err != nil {
		return nil, err
	}
	view.ReplyToNickname = replyNickname
	return &AdminCommentView{
		CommentView: view,
		Email:       user.Email,
		IPMode:      comment.IPMode,
		IPValue:     comment.IPValue,
		UAMode:      comment.UAMode,
		UARaw:       comment.UARaw,
		UABrowser:   comment.UABrowser,
		UAOS:        comment.UAOS,
		UADevice:    comment.UADevice,
	}, nil
}

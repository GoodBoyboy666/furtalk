package comment

import (
	"context"

	"furtalk/internal/domain"
	"furtalk/internal/platform/logging"
)

// publishCommentCreated 提交后发出创建通知。
func (s *Service) publishCommentCreated(ctx context.Context, comment *domain.Comment, mode string) {
	ev := domain.CommentEvent{
		Type:      domain.TypeCommentCreated,
		SiteID:    comment.SiteID,
		ThreadID:  comment.ThreadID,
		CommentID: comment.ID,
		UserID:    comment.UserID,
		ParentID:  comment.ParentID,
		Mode:      mode,
	}
	s.publish(ctx, ev)
}

// publishCommentPublished 提交后发出发布通知。
func (s *Service) publishCommentPublished(ctx context.Context, comment *domain.Comment, mode string) {
	ev := domain.CommentEvent{
		Type:      domain.TypeCommentPublished,
		SiteID:    comment.SiteID,
		ThreadID:  comment.ThreadID,
		CommentID: comment.ID,
		UserID:    comment.UserID,
		ParentID:  comment.ParentID,
		Mode:      mode,
	}
	s.publish(ctx, ev)
}

func (s *Service) publish(ctx context.Context, ev domain.CommentEvent) {
	if s.bus == nil {
		return
	}
	if err := s.bus.Publish(ev); err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "event publish failed",
			"type", string(ev.Type),
			logging.ID("site_id", ev.SiteID),
			logging.ID("comment_id", ev.CommentID),
			logging.Error(err),
		)
	}
}

package comment

import (
	"context"

	"furtalk/internal/domain"
	"furtalk/internal/platform/value"
)

// ListByOwner 返回当前用户本人的评论，支持站点与状态筛选以及页码分页，并返回匹配总数。
func (s *Service) ListByOwner(ctx context.Context, ownerID int64, siteID *int64, status *domain.CommentStatus, page, limit int) (*OwnerCommentListResult, error) {
	limit = normalizeLimit(limit)
	filter := domain.OwnerFilter{
		SiteID: siteID,
		Status: status,
		Offset: domain.OffsetForPage(page, limit),
		Limit:  limit,
	}
	rows, err := s.comments.ListByOwner(ctx, ownerID, filter)
	if err != nil {
		return nil, err
	}
	total, err := s.comments.CountByOwner(ctx, ownerID, filter)
	if err != nil {
		return nil, err
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	result := &OwnerCommentListResult{
		Comments:       make([]OwnerCommentView, 0, len(rows)),
		Total:          total,
		UserDeleteMode: pol.UserDeleteMode,
	}
	for i := range rows {
		result.Comments = append(result.Comments, toOwnerCommentView(&rows[i], pol.GravatarBaseURL))
	}
	return result, nil
}

// GetByOwner 返回当前用户本人一条评论的展示视图及当前删除策略。
func (s *Service) GetByOwner(ctx context.Context, ownerID, commentID int64) (*OwnerCommentDetail, error) {
	row, err := s.comments.GetByOwnerAndID(ctx, ownerID, commentID)
	if err != nil {
		return nil, err
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	view := toOwnerCommentView(row, pol.GravatarBaseURL)
	return &OwnerCommentDetail{View: view, UserDeleteMode: pol.UserDeleteMode}, nil
}

// ListOwnerSites 返回当前用户发表过评论的站点列表。
func (s *Service) ListOwnerSites(ctx context.Context, ownerID int64) ([]OwnerSiteView, error) {
	rows, err := s.comments.ListOwnerSites(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	out := make([]OwnerSiteView, 0, len(rows))
	for _, r := range rows {
		out = append(out, OwnerSiteView{ID: r.ID, Name: r.Name})
	}
	return out, nil
}

// toOwnerCommentView 把本人评论行映射为展示视图，只派生公开头像 URL。
func toOwnerCommentView(row *domain.OwnerComment, gravatarBase string) OwnerCommentView {
	return OwnerCommentView{
		CommentView: toCommentViewWithReply(&row.Comment, row.AuthorNickname, row.AuthorWebsite, row.AuthorRole,
			value.GravatarURL(row.AuthorEmailNormalized, gravatarBase), row.ReplyToNickname, 0, false),
		SiteName:  row.SiteName,
		PageKey:   row.PageKey,
		PageURL:   row.PageURL,
		PageTitle: row.PageTitle,
	}
}

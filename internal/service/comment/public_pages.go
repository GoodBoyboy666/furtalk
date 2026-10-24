package comment

import (
	"context"
	"errors"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gravatar"
)

// publicPageCommentView 将可见评论映射为不含隐私字段的业务视图。
func publicPageCommentView(row domain.PublicComment, avatarBaseURL string) CommentView {
	return toCommentViewWithReply(&row.Comment, row.AuthorNickname, row.AuthorWebsite, row.AuthorRole,
		gravatar.URL(row.AuthorEmailNormalized, avatarBaseURL), row.ReplyToNickname, row.LikeCount, row.LikedByMe)
}

// ListPublicRoots 返回线程元数据与独立分页的可见根评论。
func (s *Service) ListPublicRoots(ctx context.Context, siteID int64, pageKey, cursorRaw, sortRaw string, limit int, viewerID *int64) (*RootThreadView, error) {
	if err := s.validateSiteActive(ctx, siteID); err != nil {
		return nil, err
	}
	if err := validatePageKey(pageKey); err != nil {
		return nil, err
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	sort, err := normalizeSort(sortRaw, pol.CommentSort)
	if err != nil {
		return nil, err
	}
	thread, err := s.threads.GetBySiteAndKey(ctx, siteID, pageKey)
	if errors.Is(err, domain.ErrNotFound) {
		// 缺失页面只返回合成元数据；带旧线程位置的游标仍需拒绝。
		if _, cursorErr := decodeRootCursor(cursorRaw, siteID, 0, sort); cursorErr != nil {
			return nil, cursorErr
		}
		return &RootThreadView{SiteID: siteID, PageKey: pageKey, CommentsEnabled: true, Comments: []RootCommentView{}}, nil
	}
	if err != nil {
		return nil, err
	}
	cursor, err := decodeRootCursor(cursorRaw, siteID, thread.ID, sort)
	if err != nil {
		return nil, err
	}
	limit = normalizeLimit(limit)
	rows, err := s.comments.ListPublicRoots(ctx, siteID, thread.ID, sort, cursor, limit+1, viewerID)
	if err != nil {
		return nil, err
	}
	view := &RootThreadView{
		ID: thread.ID, SiteID: siteID, PageKey: pageKey,
		PageURL: thread.PageURL, PageTitle: thread.PageTitle, CommentsEnabled: thread.CommentsEnabled,
		Comments: make([]RootCommentView, 0, min(len(rows), limit)),
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	for _, row := range rows {
		view.Comments = append(view.Comments, RootCommentView{CommentView: publicPageCommentView(row.PublicComment, pol.GravatarBaseURL), HasReplies: row.HasReplies})
	}
	if hasMore {
		next := encodeRootCursor(siteID, thread.ID, sort, rows[len(rows)-1])
		view.NextCursor = &next
	}
	return view, nil
}

// ListPublicReplies 返回指定线程内可见根的独立回复分页。
func (s *Service) ListPublicReplies(ctx context.Context, siteID, rootID int64, pageKey, cursorRaw string, limit int, viewerID *int64) (*ReplyPageView, error) {
	if err := s.validateSiteActive(ctx, siteID); err != nil {
		return nil, err
	}
	if err := validatePageKey(pageKey); err != nil {
		return nil, err
	}
	thread, err := s.threads.GetBySiteAndKey(ctx, siteID, pageKey)
	if err != nil {
		return nil, err
	}
	cursor, err := decodeReplyCursor(cursorRaw, siteID, thread.ID, rootID)
	if err != nil {
		return nil, err
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	limit = normalizeLimit(limit)
	rows, err := s.comments.ListPublicReplies(ctx, siteID, thread.ID, rootID, cursor, limit+1, viewerID)
	if err != nil {
		return nil, err
	}
	view := &ReplyPageView{RootID: rootID, Comments: make([]CommentView, 0, min(len(rows), limit))}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	for _, row := range rows {
		view.Comments = append(view.Comments, publicPageCommentView(row, pol.GravatarBaseURL))
	}
	if hasMore {
		next := encodeReplyCursor(siteID, thread.ID, rootID, rows[len(rows)-1])
		view.NextCursor = &next
	}
	return view, nil
}

package comment

import "context"

// LikeResult 表示评论点赞结果。
type LikeResult struct {
	CommentID int64
	LikeCount int64
	Liked     bool
}

// LikeComment 为已发布的站点内评论添加当前账号的 Like。
func (s *Service) LikeComment(ctx context.Context, siteID, commentID, userID int64) (*LikeResult, error) {
	row, err := s.comments.AddLike(ctx, siteID, commentID, userID)
	if err != nil {
		return nil, err
	}
	return &LikeResult{CommentID: row.CommentID, LikeCount: row.LikeCount, Liked: row.Liked}, nil
}

// UnlikeComment 为已发布的站点内评论移除当前账号的 Like。
func (s *Service) UnlikeComment(ctx context.Context, siteID, commentID, userID int64) (*LikeResult, error) {
	row, err := s.comments.RemoveLike(ctx, siteID, commentID, userID)
	if err != nil {
		return nil, err
	}
	return &LikeResult{CommentID: row.CommentID, LikeCount: row.LikeCount, Liked: row.Liked}, nil
}

// ViewerState 从可选解析的 widget 凭证提取查看者用户 ID。
func ViewerState(cred WidgetCredential) *int64 {
	if cred == nil {
		return nil
	}
	id := cred.UserID()
	return &id
}

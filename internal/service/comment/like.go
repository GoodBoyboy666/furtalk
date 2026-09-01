package comment

import "context"

type LikeResult struct {
	CommentID int64
	LikeCount int64
	Liked     bool
}

// LikeComment 为已发布的站点内评论添加当前账号的 Like。
// 主体身份来自已验证 widget 凭证；重复添加是幂等成功。
func (s *Service) LikeComment(ctx context.Context, siteID, commentID, userID int64) (*LikeResult, error) {
	row, err := s.comments.AddLike(ctx, siteID, commentID, userID)
	if err != nil {
		return nil, err
	}
	return &LikeResult{CommentID: row.CommentID, LikeCount: row.LikeCount, Liked: row.Liked}, nil
}

// UnlikeComment 为已发布的站点内评论移除当前账号的 Like。
// 重复移除是幂等成功且计数不会为负。
func (s *Service) UnlikeComment(ctx context.Context, siteID, commentID, userID int64) (*LikeResult, error) {
	row, err := s.comments.RemoveLike(ctx, siteID, commentID, userID)
	if err != nil {
		return nil, err
	}
	return &LikeResult{CommentID: row.CommentID, LikeCount: row.LikeCount, Liked: row.Liked}, nil
}

// ViewerState 从可选解析的 widget 凭证提取查看者用户 ID。
// 返回 nil 表示匿名/无有效凭证，读取保持公开且 liked_by_me 恒为 false。
func ViewerState(cred WidgetCredential) *int64 {
	if cred == nil {
		return nil
	}
	id := cred.UserID()
	return &id
}

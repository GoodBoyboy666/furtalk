package repository

import (
	"context"
	"fmt"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
)

// publicRootProjection 标记根评论是否存在任意深度的可见回复。
const publicRootProjection = publicListProjection + ` AND visible.vis_parent_id IS NULL`

// publicReplyProjection 保留空回复页的根标记并关联公开作者资料。
const publicReplyProjection = publicCommentColumns + `,
       requested_root.id AS requested_root_id
  FROM requested_root
  LEFT JOIN reply_page AS visible ON visible.vis_root_id = requested_root.id
  LEFT JOIN users ON users.id = visible.user_id
  LEFT JOIN users AS reply_users ON reply_users.id = visible.reply_to_user_id
 ORDER BY visible.created_at ASC, visible.id ASC`

// publicPageViewerExpression 构造查看者点赞映射及其参数。
func publicPageViewerExpression(viewerID *int64) (string, []any) {
	if viewerID == nil {
		return "0", nil
	}
	return "EXISTS (SELECT 1 FROM comment_likes AS cl2 WHERE cl2.site_id = visible.site_id AND cl2.comment_id = visible.id AND cl2.user_id = ?)", []any{*viewerID}
}

// ListPublicRoots 按根评论自身排序和游标列出可见根评论。
func (r *CommentRepo) ListPublicRoots(ctx context.Context, siteID, threadID int64, sort domain.CommentSort, cursor *domain.Cursor, limit int, viewerID *int64) ([]domain.PublicRootComment, error) {
	likedByMe, viewerArgs := publicPageViewerExpression(viewerID)
	sql := "WITH RECURSIVE visible AS (" + publicListCteAnchor + publicListCteStep + "), roots AS (" + fmt.Sprintf(publicRootProjection, likedByMe) + `)
SELECT roots.*,
       EXISTS (SELECT 1 FROM visible AS replies
                WHERE replies.site_id = roots.site_id AND replies.thread_id = roots.thread_id
                  AND replies.vis_root_id = roots.id AND replies.status = 'published') AS has_replies
  FROM roots
 WHERE roots.site_id = ? AND roots.thread_id = ?`
	args := []any{siteID, threadID, siteID, threadID}
	args = append(args, viewerArgs...)
	args = append(args, string(domain.CommentStatusPublished), siteID, threadID)
	pinnedExpr := "CASE WHEN roots.is_pinned THEN 1 ELSE 0 END"
	pinnedCursor := 0
	if cursor != nil && cursor.Pinned {
		pinnedCursor = 1
	}
	switch sort {
	case domain.CommentSortHot:
		if cursor != nil {
			sql += " AND (" + pinnedExpr + " < ? OR (" + pinnedExpr + " = ? AND (roots.like_count < ? OR (roots.like_count = ? AND (roots.created_at < ? OR (roots.created_at = ? AND roots.id < ?))))))"
			args = append(args, pinnedCursor, pinnedCursor, cursor.LikeCount, cursor.LikeCount, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
		}
		sql += " ORDER BY " + pinnedExpr + " DESC, roots.like_count DESC, roots.created_at DESC, roots.id DESC"
	case domain.CommentSortDesc:
		if cursor != nil {
			sql += " AND (" + pinnedExpr + " < ? OR (" + pinnedExpr + " = ? AND (roots.created_at < ? OR (roots.created_at = ? AND roots.id < ?))))"
			args = append(args, pinnedCursor, pinnedCursor, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
		}
		sql += " ORDER BY " + pinnedExpr + " DESC, roots.created_at DESC, roots.id DESC"
	default:
		if cursor != nil {
			sql += " AND (" + pinnedExpr + " < ? OR (" + pinnedExpr + " = ? AND (roots.created_at > ? OR (roots.created_at = ? AND roots.id > ?))))"
			args = append(args, pinnedCursor, pinnedCursor, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
		}
		sql += " ORDER BY " + pinnedExpr + " DESC, roots.created_at ASC, roots.id ASC"
	}
	if limit <= 0 {
		limit = 50
	}
	sql += " LIMIT ?"
	args = append(args, limit)
	rows := make([]domain.PublicRootComment, 0)
	if err := gormtx.DB(ctx, r.db).Raw(sql, args...).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("list public roots: %w", err)
	}
	return rows, nil
}

// ListPublicReplies 分页列出同一可见根下的全部已发布后代。
func (r *CommentRepo) ListPublicReplies(ctx context.Context, siteID, threadID, rootID int64, cursor *domain.Cursor, limit int, viewerID *int64) ([]domain.PublicComment, error) {
	sql := "WITH RECURSIVE visible AS (" + publicListCteAnchor + publicListCteStep + `), requested_root AS (
 SELECT id FROM visible
  WHERE site_id = ? AND thread_id = ? AND id = ? AND status = ? AND vis_parent_id IS NULL
), reply_page AS (
 SELECT * FROM visible
  WHERE site_id = ? AND thread_id = ? AND status = ?
    AND vis_root_id = (SELECT id FROM requested_root) AND id <> ?`
	args := []any{siteID, threadID, siteID, threadID, siteID, threadID, rootID, string(domain.CommentStatusPublished), siteID, threadID, string(domain.CommentStatusPublished), rootID}
	if cursor != nil {
		sql += " AND (visible.created_at > ? OR (visible.created_at = ? AND visible.id > ?))"
		args = append(args, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
	}
	if limit <= 0 {
		limit = 50
	}
	sql += " ORDER BY visible.created_at ASC, visible.id ASC LIMIT ?) "
	args = append(args, limit)
	likedByMe, viewerArgs := publicPageViewerExpression(viewerID)
	sql += fmt.Sprintf(publicReplyProjection, likedByMe)
	args = append(args, viewerArgs...)

	// 根校验和回复读取共用一次 SQL 快照；空页的 LEFT JOIN 行只用于确认根存在。
	type replyRow struct {
		domain.PublicComment
		RequestedRootID int64
	}
	var scanned []replyRow
	if err := gormtx.DB(ctx, r.db).Raw(sql, args...).Scan(&scanned).Error; err != nil {
		return nil, fmt.Errorf("list public replies: %w", err)
	}
	if len(scanned) == 0 {
		return nil, domain.ErrNotFound
	}
	rows := make([]domain.PublicComment, 0, len(scanned))
	for _, row := range scanned {
		if row.RequestedRootID == rootID && row.ID != 0 {
			rows = append(rows, row.PublicComment)
		}
	}
	return rows, nil
}

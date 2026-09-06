package repository

import (
	"context"
	"fmt"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// LikeResult 表示评论点赞后的计数与当前用户状态。
type LikeResult struct {
	CommentID int64
	LikeCount int64
	Liked     bool
}

// AddLike 创建评论点赞并返回最新状态。
func (r *CommentRepo) AddLike(ctx context.Context, siteID, commentID, userID int64) (*LikeResult, error) {
	var result *LikeResult
	err := gormtx.DB(ctx, r.db).Transaction(func(tx *gorm.DB) error {
		if err := requirePublishedComment(tx, siteID, commentID); err != nil {
			return err
		}
		row := &model.CommentLike{SiteID: siteID, CommentID: commentID, UserID: userID}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "site_id"}, {Name: "comment_id"}, {Name: "user_id"}},
			DoNothing: true,
		}).Create(row).Error; err != nil {
			return fmt.Errorf("add comment like: %w", err)
		}
		count, err := likeCount(tx, siteID, commentID)
		if err != nil {
			return err
		}
		result = &LikeResult{CommentID: commentID, LikeCount: count, Liked: true}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RemoveLike 删除评论点赞并返回最新状态。
func (r *CommentRepo) RemoveLike(ctx context.Context, siteID, commentID, userID int64) (*LikeResult, error) {
	var result *LikeResult
	err := gormtx.DB(ctx, r.db).Transaction(func(tx *gorm.DB) error {
		if err := requirePublishedComment(tx, siteID, commentID); err != nil {
			return err
		}
		if err := tx.
			Where("site_id = ? AND comment_id = ? AND user_id = ?", siteID, commentID, userID).
			Delete(&model.CommentLike{}).Error; err != nil {
			return fmt.Errorf("remove comment like: %w", err)
		}
		count, err := likeCount(tx, siteID, commentID)
		if err != nil {
			return err
		}
		result = &LikeResult{CommentID: commentID, LikeCount: count, Liked: false}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// requirePublishedComment 确认站点内存在已发布的评论，缺失或未发布返回 domain.ErrNotFound。
func requirePublishedComment(tx *gorm.DB, siteID, commentID int64) error {
	var count int64
	if err := tx.Model(&model.Comment{}).
		Where("site_id = ? AND id = ? AND status = ?", siteID, commentID, domain.CommentStatusPublished).
		Count(&count).Error; err != nil {
		return fmt.Errorf("check published comment: %w", err)
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// likeCount 返回站点内某条评论的权威 Like 计数。
func likeCount(tx *gorm.DB, siteID, commentID int64) (int64, error) {
	var count int64
	if err := tx.Model(&model.CommentLike{}).
		Where("site_id = ? AND comment_id = ?", siteID, commentID).
		Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count comment likes: %w", err)
	}
	return count, nil
}

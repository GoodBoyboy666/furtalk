package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ThreadRepo 提供评论线程的持久化操作。
type ThreadRepo struct {
	db *gorm.DB
}

// ThreadBatchTarget 标识站点内的评论区目标。
// 即使 ID 全局唯一，目标仍保留 SiteID，确保批量写入显式执行站点隔离。
type ThreadBatchTarget struct {
	SiteID int64
	ID     int64
}

// NewThreadRepo 构建Thread repository。
func NewThreadRepo(db *gorm.DB) *ThreadRepo {
	return &ThreadRepo{db: db}
}

// ResolveOrCreate 按站点和页面键解析或创建评论线程。
func (r *ThreadRepo) ResolveOrCreate(ctx context.Context, siteID int64, pageKey string, pageURL, pageTitle *string) (*domain.Thread, error) {
	row := &model.Thread{SiteID: siteID, PageKey: pageKey, PageURL: pageURL, PageTitle: pageTitle}
	assignments := map[string]any{"updated_at": time.Now().UTC()}
	if pageURL != nil {
		assignments["page_url"] = *pageURL
	}
	if pageTitle != nil {
		assignments["page_title"] = *pageTitle
	}
	err := gormtx.DB(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "site_id"}, {Name: "page_key"}},
		DoUpdates: clause.Assignments(assignments),
	}).Create(row).Error
	if err != nil {
		return nil, fmt.Errorf("resolve or create thread: %w", err)
	}
	if row.ID == 0 {
		return r.GetBySiteAndKey(ctx, siteID, pageKey)
	}
	thread := row.ToThread()
	return &thread, nil
}

// GetBySiteAndKey 返回 (site_id, page_key) 对应的 thread。
func (r *ThreadRepo) GetBySiteAndKey(ctx context.Context, siteID int64, pageKey string) (*domain.Thread, error) {
	var row model.Thread
	err := gormtx.DB(ctx, r.db).
		Where("site_id = ? AND page_key = ?", siteID, pageKey).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get thread by site and key: %w", err)
	}
	thread := row.ToThread()
	return &thread, nil
}

// GetBySiteAndID 返回在某个站点内的一条 thread。
func (r *ThreadRepo) GetBySiteAndID(ctx context.Context, siteID, threadID int64) (*domain.Thread, error) {
	var row model.Thread
	err := gormtx.DB(ctx, r.db).
		Where("site_id = ? AND id = ?", siteID, threadID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get thread by site and id: %w", err)
	}
	thread := row.ToThread()
	return &thread, nil
}

// GetBySiteAndIDsLocked 按稳定 ID 顺序批量读取并锁定站点内的评论区。
func (r *ThreadRepo) GetBySiteAndIDsLocked(ctx context.Context, siteID int64, ids []int64) ([]domain.Thread, error) {
	// PostgreSQL 使用行锁；SQLite 分支省略 FOR UPDATE，沿用外层写事务的串行语义。
	if len(ids) == 0 {
		return []domain.Thread{}, nil
	}
	db := gormtx.DB(ctx, r.db)
	if db.Dialector.Name() != "sqlite" {
		db = db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var rows []model.Thread
	if err := db.Where("site_id = ? AND id IN ?", siteID, ids).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("get threads locked by ids: %w", err)
	}
	out := make([]domain.Thread, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ToThread())
	}
	return out, nil
}

// GetBySiteAndKeyLocked 在写事务内按 (site_id, page_key) 读取 thread，
func (r *ThreadRepo) GetBySiteAndKeyLocked(ctx context.Context, siteID int64, pageKey string) (*domain.Thread, error) {
	return r.threadLocked(ctx, func(db *gorm.DB) *gorm.DB {
		return db.Where("site_id = ? AND page_key = ?", siteID, pageKey)
	})
}

// GetBySiteAndIDLocked 在写事务内按 (site_id, thread_id) 读取 thread，
func (r *ThreadRepo) GetBySiteAndIDLocked(ctx context.Context, siteID, threadID int64) (*domain.Thread, error) {
	return r.threadLocked(ctx, func(db *gorm.DB) *gorm.DB {
		return db.Where("site_id = ? AND id = ?", siteID, threadID)
	})
}

// threadLocked 在当前事务中查询并锁定评论线程。
func (r *ThreadRepo) threadLocked(ctx context.Context, cond func(db *gorm.DB) *gorm.DB) (*domain.Thread, error) {
	db := gormtx.DB(ctx, r.db)
	if db.Dialector.Name() != "sqlite" {
		db = db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var row model.Thread
	err := cond(db).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get thread locked: %w", err)
	}
	thread := row.ToThread()
	return &thread, nil
}

// ListAdmin 按筛选条件列出管理端评论线程。
func (r *ThreadRepo) ListAdmin(ctx context.Context, filter domain.AdminThreadFilter) ([]domain.AdminThread, error) {
	query := gormtx.DB(ctx, r.db).
		Table("threads").
		Joins("JOIN sites ON sites.id = threads.site_id").
		Select("threads.*, sites.name AS site_name")
	query = applyAdminThreadFilters(query, filter)
	sort := filter.Sort
	if sort == "" {
		sort = domain.CommentSortDesc
	}
	query = query.Order(applyCursorOrder("threads", sort))
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	var rows []domain.AdminThread
	if err := query.Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list admin threads: %w", err)
	}
	return rows, nil
}

// CountAdmin 统计与 ListAdmin 完全相同的过滤条件匹配的线程总数。
func (r *ThreadRepo) CountAdmin(ctx context.Context, filter domain.AdminThreadFilter) (int64, error) {
	query := applyAdminThreadFilters(gormtx.DB(ctx, r.db).Table("threads"), filter)
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count admin threads: %w", err)
	}
	return count, nil
}

// applyAdminThreadFilters 把管理员线程列表的全部过滤条件应用到查询。
func applyAdminThreadFilters(query *gorm.DB, filter domain.AdminThreadFilter) *gorm.DB {
	if filter.SiteID != nil {
		query = query.Where("threads.site_id = ?", *filter.SiteID)
	}
	if filter.CommentsEnabled != nil {
		query = query.Where("threads.comments_enabled = ?", *filter.CommentsEnabled)
	}
	if filter.Q != "" {
		pattern := "%" + filter.Q + "%"
		query = query.Where("(threads.page_key LIKE ? OR threads.page_title LIKE ? OR threads.page_url LIKE ?)", pattern, pattern, pattern)
	}
	return query
}

// UpdateThread 更新线程元数据并返回最新线程。
func (r *ThreadRepo) UpdateThread(ctx context.Context, siteID, threadID int64, patch domain.ThreadPatch) (*domain.Thread, error) {
	db := gormtx.DB(ctx, r.db)
	var row model.Thread
	if err := db.Where("site_id = ? AND id = ?", siteID, threadID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get thread by site and id: %w", err)
	}
	updates := map[string]any{}
	if patch.PageKey != nil {
		updates["page_key"] = *patch.PageKey
	}
	if patch.PageTitle != nil {
		updates["page_title"] = *patch.PageTitle
	}
	if patch.ClearPageTitle {
		updates["page_title"] = nil
	}
	if patch.PageURL != nil {
		updates["page_url"] = *patch.PageURL
	}
	if patch.ClearPageURL {
		updates["page_url"] = nil
	}
	if patch.CommentsEnabled != nil {
		updates["comments_enabled"] = *patch.CommentsEnabled
	}
	if len(updates) == 0 {
		thread := row.ToThread()
		return &thread, nil
	}
	if err := db.Model(&model.Thread{}).
		Where("site_id = ? AND id = ?", siteID, threadID).
		Updates(updates).Error; err != nil {
		if gormtx.IsDuplicateKeyError(err) {
			return nil, fmt.Errorf("update thread: %w", domain.ErrConflict)
		}
		return nil, fmt.Errorf("update thread: %w", err)
	}
	// 更新后的行重新读取，使返回与持久化状态一致。
	if err := db.Where("site_id = ? AND id = ?", siteID, threadID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get thread by site and id: %w", err)
	}
	thread := row.ToThread()
	return &thread, nil
}

// UpdateCommentsEnabled 更新页面级评论开关，
func (r *ThreadRepo) UpdateCommentsEnabled(ctx context.Context, siteID, threadID int64, enabled bool) (*domain.Thread, error) {
	return r.UpdateThread(ctx, siteID, threadID, domain.ThreadPatch{CommentsEnabled: &enabled})
}

// UpdateCommentsEnabledMany 更新显式站点范围内的目标集合并返回影响行数。
func (r *ThreadRepo) UpdateCommentsEnabledMany(ctx context.Context, siteID int64, ids []int64, enabled bool) (int64, error) {
	// 调用前目标必须已由 service 加锁、校验并过滤 no-op。
	if len(ids) == 0 {
		return 0, nil
	}
	result := gormtx.DB(ctx, r.db).Model(&model.Thread{}).
		Where("site_id = ? AND id IN ?", siteID, ids).
		Update("comments_enabled", enabled)
	if result.Error != nil {
		return 0, fmt.Errorf("update thread comments enabled: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// DeleteThread 删除指定站点的评论线程。
func (r *ThreadRepo) DeleteThread(ctx context.Context, siteID, threadID int64) error {
	result := gormtx.DB(ctx, r.db).
		Where("site_id = ? AND id = ?", siteID, threadID).
		Delete(&model.Thread{})
	if result.Error != nil {
		return fmt.Errorf("delete thread: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// DeleteThreads 删除显式站点范围内的目标集合并返回影响行数。
func (r *ThreadRepo) DeleteThreads(ctx context.Context, siteID int64, ids []int64) (int64, error) {
	// 使用方必须已锁定并完整校验目标。
	if len(ids) == 0 {
		return 0, nil
	}
	result := gormtx.DB(ctx, r.db).
		Where("site_id = ? AND id IN ?", siteID, ids).
		Delete(&model.Thread{})
	if result.Error != nil {
		return 0, fmt.Errorf("delete threads: %w", result.Error)
	}
	return result.RowsAffected, nil
}

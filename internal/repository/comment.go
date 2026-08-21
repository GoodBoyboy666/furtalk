package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ThreadRepo 持久化 threads 行。
type ThreadRepo struct {
	db *gorm.DB
}

// NewThreadRepo 构建线程仓储。
func NewThreadRepo(db *gorm.DB) *ThreadRepo {
	return &ThreadRepo{db: db}
}

// ResolveOrCreate 返回 (site_id, page_key) 对应的 thread，不存在时插入。
// 冲突时按非 nil 元数据更新 page_url/page_title，并刷新 updated_at（写路径语义）。
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

// ResolveOrCreateLazy 返回 (site_id, page_key) 对应的 thread，不存在时插入，
// 冲突时什么都不做（不更新元数据与时间戳），供只读的惰性发现使用。
func (r *ThreadRepo) ResolveOrCreateLazy(ctx context.Context, siteID int64, pageKey string) (*domain.Thread, error) {
	row := &model.Thread{SiteID: siteID, PageKey: pageKey}
	err := gormtx.DB(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "site_id"}, {Name: "page_key"}},
		DoNothing: true,
	}).Create(row).Error
	if err != nil {
		return nil, fmt.Errorf("lazy resolve thread: %w", err)
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

// GetBySiteAndID 返回限定在某个站点内的一条 thread。
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

// GetBySiteAndKeyLocked 在写事务内按 (site_id, page_key) 读取 thread，
// 在 PostgreSQL 上对行加锁，SQLite 依赖事务忙等待。
func (r *ThreadRepo) GetBySiteAndKeyLocked(ctx context.Context, siteID int64, pageKey string) (*domain.Thread, error) {
	return r.threadLocked(ctx, func(db *gorm.DB) *gorm.DB {
		return db.Where("site_id = ? AND page_key = ?", siteID, pageKey)
	})
}

// GetBySiteAndIDLocked 在写事务内按 (site_id, thread_id) 读取 thread，
// 在 PostgreSQL 上对行加锁，SQLite 依赖事务忙等待。
func (r *ThreadRepo) GetBySiteAndIDLocked(ctx context.Context, siteID, threadID int64) (*domain.Thread, error) {
	return r.threadLocked(ctx, func(db *gorm.DB) *gorm.DB {
		return db.Where("site_id = ? AND id = ?", siteID, threadID)
	})
}

// threadLocked 应用方言感知的行锁并读取第一条 thread 行。
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

// ListAdmin 按管理员过滤条件列出线程并关联站点名。
// q 对 page_key、page_title 与 page_url 做包含匹配；结果使用 (created_at, id) 排序。
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
// ListAdmin 与 CountAdmin 共享此构建器，保证 total 与行查询条件一致。
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

// UpdateThread 以 site_id 与 thread_id 限定范围更新线程的元数据字段并返回
// 更新后的完整 thread。更新前先确认记录存在，因为 SQLite 只统计实际变更行，
// 同值更新时 RowsAffected 为 0；page_key 违反站点内唯一时返回 domain.ErrConflict。
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

// UpdateCommentsEnabled 以 site_id 与 thread_id 限定范围更新页面级评论开关，
// 返回更新后的完整 thread。
func (r *ThreadRepo) UpdateCommentsEnabled(ctx context.Context, siteID, threadID int64, enabled bool) (*domain.Thread, error) {
	return r.UpdateThread(ctx, siteID, threadID, domain.ThreadPatch{CommentsEnabled: &enabled})
}

// DeleteThread 以 site_id 与 thread_id 限定范围硬删除一条 thread。
// 依赖数据库复合外键 ON DELETE CASCADE 移除该线程下全部（含父子）评论，
// 作者用户、站点与其他线程不受影响；跨站点或缺失的 thread 返回
// domain.ErrNotFound，绝不删除其他站点数据。
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

// CommentRepo 持久化评论行。
type CommentRepo struct {
	db *gorm.DB
}

// NewCommentRepo 构建评论仓储。
func NewCommentRepo(db *gorm.DB) *CommentRepo {
	return &CommentRepo{db: db}
}

// Create 插入评论行，并把生成的 ID 与时间戳回填到业务实体。
func (r *CommentRepo) Create(ctx context.Context, comment *domain.Comment) error {
	row := fromComment(comment)
	if err := gormtx.DB(ctx, r.db).Create(row).Error; err != nil {
		return fmt.Errorf("create comment: %w", err)
	}
	comment.ID = row.ID
	comment.CreatedAt = row.CreatedAt
	comment.UpdatedAt = row.UpdatedAt
	return nil
}

// FindBySiteAndID 返回限定在某个站点内的一条评论。
func (r *CommentRepo) FindBySiteAndID(ctx context.Context, siteID, id int64) (*domain.Comment, error) {
	var row model.Comment
	err := gormtx.DB(ctx, r.db).
		Where("site_id = ? AND id = ?", siteID, id).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find comment by site and id: %w", err)
	}
	out := row.ToComment()
	return &out, nil
}

// FindGlobalByID 按全局主键返回一条评论，不限站点。
func (r *CommentRepo) FindGlobalByID(ctx context.Context, id int64) (*domain.Comment, error) {
	var row model.Comment
	err := gormtx.DB(ctx, r.db).
		Where("id = ?", id).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find comment by global id: %w", err)
	}
	out := row.ToComment()
	return &out, nil
}

// ListPublic 使用的递归 CTE 由下面三段 SQL 模板拼接：锚点 + 递归步进 + 投影。
// 占位符 ? 按顺序绑定 site_id/thread_id、site_id/thread_id、published 状态。

// publicListCteAnchor 遍历线程内全部状态的评论（不做状态过滤），从根评论出发，
// 初始携带 vis_parent_id/vis_root_id 均为 BIGINT 类型的 NULL，以便与递归步进中
// 的评论 id 保持一致（PostgreSQL 要求递归 CTE 的同一列类型一致）。
const publicListCteAnchor = `
	SELECT id, site_id, thread_id, user_id, reply_to_user_id, depth, body_markdown, status,
	       status_before_delete, ip_mode, ip_value, ua_mode, ua_raw, ua_browser, ua_os, ua_device,
	       created_at, updated_at, published_at, deleted_at,
	       CAST(NULL AS BIGINT) AS vis_parent_id, CAST(NULL AS BIGINT) AS vis_root_id
	  FROM comments
	 WHERE site_id = ? AND thread_id = ? AND parent_id IS NULL`

// publicListCteStep 向下递归：父节点为 published 时子节点连接到父节点
// （vis_parent_id=父 id，vis_root_id=父的可见根或父本身）；父节点不可见时继承父
// 节点携带的最近可见祖先，连续多层不可见被一次跨过。
const publicListCteStep = `
	UNION ALL
	SELECT c.id, c.site_id, c.thread_id, c.user_id, c.reply_to_user_id, c.depth, c.body_markdown, c.status,
	       c.status_before_delete, c.ip_mode, c.ip_value, c.ua_mode, c.ua_raw, c.ua_browser, c.ua_os, c.ua_device,
	       c.created_at, c.updated_at, c.published_at, c.deleted_at,
	       CASE WHEN v.status = 'published' THEN v.id ELSE v.vis_parent_id END AS vis_parent_id,
	       CASE WHEN v.status = 'published' THEN COALESCE(v.vis_root_id, v.id) ELSE v.vis_root_id END AS vis_root_id
	  FROM comments AS c
	  JOIN visible AS v ON c.parent_id = v.id AND c.site_id = v.site_id AND c.thread_id = v.thread_id
	 WHERE c.site_id = ? AND c.thread_id = ?`

// publicListProjection 只选择 published 行，把递归得到的 vis_parent_id/vis_root_id
// 投影为公开响应的 parent_id/root_id，并 join 作者与回复目标资料。
const publicListProjection = `
SELECT visible.id, visible.site_id, visible.thread_id, visible.user_id,
       visible.vis_parent_id AS parent_id, visible.vis_root_id AS root_id,
       visible.reply_to_user_id, visible.depth, visible.body_markdown, visible.status,
       visible.status_before_delete, visible.ip_mode, visible.ip_value,
       visible.ua_mode, visible.ua_raw, visible.ua_browser, visible.ua_os, visible.ua_device,
       visible.created_at, visible.updated_at, visible.published_at, visible.deleted_at,
       users.email_normalized AS author_email_normalized,
       users.nickname AS author_nickname,
       users.website_url AS author_website,
       users.role AS author_role,
       reply_users.nickname AS reply_to_nickname
  FROM visible
  JOIN users ON users.id = visible.user_id
  LEFT JOIN users AS reply_users ON reply_users.id = visible.reply_to_user_id
 WHERE visible.status = ?`

// ListPublic 按受控排序方向返回某个线程中已发布的评论。
// asc 使用 (created_at, id) 升序与 `>` keyset 谓词；desc 使用降序与 `<` 谓词。
// 排序方向必须先在服务层校验为受控枚举；仓储只根据该枚举构造固定 SQL 片段，
// 绝不拼接未校验的请求值。
// 软删除等非公开评论完全不进入响应，但其后代会被压缩到祖先链上最近的一个
// published 节点下（无可见祖先时成为公开树根）。数据库中的原始 parent_id /
// root_id / depth 保持不变，查询输出的 parent_id/root_id 是压缩后的可见树关系，
// depth 保留真实持久化值供回复深度校验使用。
// 规范化邮箱只在仓储/服务边界读取，用于派生头像 URL，绝不进入 HTTP DTO。
func (r *CommentRepo) ListPublic(ctx context.Context, siteID, threadID int64, sort domain.CommentSort, cursor *domain.Cursor, limit int) ([]domain.PublicComment, error) {
	sql := "WITH RECURSIVE visible AS (" + publicListCteAnchor + publicListCteStep + ") " + publicListProjection
	args := []any{siteID, threadID, siteID, threadID, string(domain.CommentStatusPublished)}
	switch sort {
	case domain.CommentSortDesc:
		if cursor != nil {
			sql += " AND (visible.created_at < ? OR (visible.created_at = ? AND visible.id < ?))"
			args = append(args, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
		}
		sql += " ORDER BY visible.created_at DESC, visible.id DESC"
	default:
		if cursor != nil {
			sql += " AND (visible.created_at > ? OR (visible.created_at = ? AND visible.id > ?))"
			args = append(args, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
		}
		sql += " ORDER BY visible.created_at ASC, visible.id ASC"
	}
	if limit <= 0 {
		limit = 50
	}
	sql += " LIMIT ?"
	args = append(args, limit)
	var rows []domain.PublicComment
	if err := gormtx.DB(ctx, r.db).Raw(sql, args...).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("list public comments: %w", err)
	}
	return rows, nil
}

// ListLatestPublic 返回某个站点中最新发布的评论，关联所属线程的页面元数据及作者当前公开资料。
// 固定按 (created_at DESC, id DESC) 稳定排序。
// 规范化邮箱只在仓储/服务边界读取，用于派生头像 URL，绝不进入 HTTP DTO。
func (r *CommentRepo) ListLatestPublic(ctx context.Context, siteID int64, limit int) ([]domain.LatestPublicComment, error) {
	if limit <= 0 {
		limit = 25
	}
	var rows []domain.LatestPublicComment
	err := gormtx.DB(ctx, r.db).
		Table("comments").
		Joins("JOIN users ON users.id = comments.user_id").
		Joins("LEFT JOIN users AS reply_users ON reply_users.id = comments.reply_to_user_id").
		Joins("JOIN threads ON threads.id = comments.thread_id AND threads.site_id = comments.site_id").
		Select("comments.*, users.email_normalized AS author_email_normalized, users.nickname AS author_nickname, users.website_url AS author_website, users.role AS author_role, reply_users.nickname AS reply_to_nickname, threads.page_key AS page_key, threads.page_url AS page_url, threads.page_title AS page_title").
		Where("comments.site_id = ? AND comments.status = ?", siteID, domain.CommentStatusPublished).
		Order(applyCursorOrder("comments", domain.CommentSortDesc)).
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list latest public comments: %w", err)
	}
	return rows, nil
}

// ListAdmin 返回符合管理员过滤条件、且与作者邮箱连接的评论。
// 规范化邮箱只在仓储/服务边界读取，用于派生头像 URL，绝不进入 HTTP DTO。
func (r *CommentRepo) ListAdmin(ctx context.Context, filter domain.AdminFilter) ([]domain.AdminComment, error) {
	query := gormtx.DB(ctx, r.db).
		Table("comments").
		Joins("JOIN users ON users.id = comments.user_id").
		Joins("LEFT JOIN users AS reply_users ON reply_users.id = comments.reply_to_user_id").
		Select("comments.*, users.email AS author_email, users.email_normalized AS author_email_normalized, users.nickname AS author_nickname, users.website_url AS author_website, users.role AS author_role, reply_users.nickname AS reply_to_nickname")
	query = applyAdminCommentFilters(query, filter)
	sort := filter.Sort
	if sort == "" {
		sort = domain.CommentSortDesc
	}
	query = query.Order(applyCursorOrder("comments", sort))
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	var rows []domain.AdminComment
	if err := query.Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list admin comments: %w", err)
	}
	return rows, nil
}

// CountAdmin 统计与 ListAdmin 完全相同的过滤条件匹配的管理员评论总数，
// 使分页 total 与行查询永不漂移。q 过滤引用作者字段，因此 count 也必须 join users。
func (r *CommentRepo) CountAdmin(ctx context.Context, filter domain.AdminFilter) (int64, error) {
	query := applyAdminCommentFilters(gormtx.DB(ctx, r.db).Table("comments").
		Joins("JOIN users ON users.id = comments.user_id"), filter)
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count admin comments: %w", err)
	}
	return count, nil
}

// applyAdminCommentFilters 把管理员评论列表的全部过滤条件应用到查询。
// q 对正文、作者邮箱与昵称做包含匹配；ListAdmin 与 CountAdmin 共享此构建器。
func applyAdminCommentFilters(query *gorm.DB, filter domain.AdminFilter) *gorm.DB {
	if filter.SiteID != nil {
		query = query.Where("comments.site_id = ?", *filter.SiteID)
	}
	if filter.ThreadID != nil {
		query = query.Where("comments.thread_id = ?", *filter.ThreadID)
	}
	if filter.Status != nil {
		query = query.Where("comments.status = ?", *filter.Status)
	}
	if filter.UserID != nil {
		query = query.Where("comments.user_id = ?", *filter.UserID)
	}
	if filter.Since != nil {
		query = query.Where("comments.created_at >= ?", *filter.Since)
	}
	if filter.Until != nil {
		query = query.Where("comments.created_at <= ?", *filter.Until)
	}
	if q := strings.TrimSpace(filter.Q); q != "" {
		pattern := "%" + q + "%"
		query = query.Where("(comments.body_markdown LIKE ? OR users.email LIKE ? OR users.email_normalized LIKE ? OR users.nickname LIKE ?)",
			pattern, pattern, pattern, pattern)
	}
	return query
}

// ownerVisibleStatus 是普通用户侧可见的评论审核状态集合。
// 软删除（deleted）评论对普通用户一律不可见；管理端使用完整四状态，不复用此集合。
func ownerVisibleStatus() []domain.CommentStatus {
	return []domain.CommentStatus{
		domain.CommentStatusPublished,
		domain.CommentStatusPending,
		domain.CommentStatusSpam,
	}
}

// ListByOwner 返回当前用户本人的评论，关联作者、站点与线程公开元数据。
// 所有行都必须命中 ownerID；仅返回 owner-visible 状态的评论；
// site/status 过滤在 offset 之前应用。
// 规范化邮箱只在仓储/服务边界读取，用于派生头像 URL，绝不进入 HTTP DTO。
func (r *CommentRepo) ListByOwner(ctx context.Context, ownerID int64, filter domain.OwnerFilter) ([]domain.OwnerComment, error) {
	query := gormtx.DB(ctx, r.db).
		Table("comments").
		Joins("JOIN users ON users.id = comments.user_id").
		Joins("LEFT JOIN users AS reply_users ON reply_users.id = comments.reply_to_user_id").
		Joins("JOIN sites ON sites.id = comments.site_id").
		Joins("JOIN threads ON threads.id = comments.thread_id").
		Select("comments.*, users.email_normalized AS author_email_normalized, users.nickname AS author_nickname, users.website_url AS author_website, users.role AS author_role, reply_users.nickname AS reply_to_nickname, sites.name AS site_name, threads.page_key AS page_key, threads.page_url AS page_url, threads.page_title AS page_title").
		Where("comments.user_id = ?", ownerID).
		Where("comments.status IN ?", ownerVisibleStatus())
	if filter.SiteID != nil {
		query = query.Where("comments.site_id = ?", *filter.SiteID)
	}
	if filter.Status != nil {
		query = query.Where("comments.status = ?", *filter.Status)
	}
	query = query.Order(applyCursorOrder("comments", domain.CommentSortAsc))
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	var rows []domain.OwnerComment
	if err := query.Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list owner comments: %w", err)
	}
	return rows, nil
}

// CountByOwner 统计当前用户本人且符合 site/status 过滤的评论总数。
func (r *CommentRepo) CountByOwner(ctx context.Context, ownerID int64, filter domain.OwnerFilter) (int64, error) {
	query := gormtx.DB(ctx, r.db).
		Table("comments").
		Where("comments.user_id = ?", ownerID).
		Where("comments.status IN ?", ownerVisibleStatus())
	if filter.SiteID != nil {
		query = query.Where("comments.site_id = ?", *filter.SiteID)
	}
	if filter.Status != nil {
		query = query.Where("comments.status = ?", *filter.Status)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count owner comments: %w", err)
	}
	return count, nil
}

// GetByOwnerAndID 返回当前用户本人一条评论，关联站点与线程公开元数据。
// 记录不属于 ownerID 时视为不存在，不披露他人评论。
func (r *CommentRepo) GetByOwnerAndID(ctx context.Context, ownerID, id int64) (*domain.OwnerComment, error) {
	var row domain.OwnerComment
	err := gormtx.DB(ctx, r.db).
		Table("comments").
		Joins("JOIN users ON users.id = comments.user_id").
		Joins("LEFT JOIN users AS reply_users ON reply_users.id = comments.reply_to_user_id").
		Joins("JOIN sites ON sites.id = comments.site_id").
		Joins("JOIN threads ON threads.id = comments.thread_id").
		Select("comments.*, users.email_normalized AS author_email_normalized, users.nickname AS author_nickname, users.website_url AS author_website, users.role AS author_role, reply_users.nickname AS reply_to_nickname, sites.name AS site_name, threads.page_key AS page_key, threads.page_url AS page_url, threads.page_title AS page_title").
		Where("comments.user_id = ? AND comments.id = ?", ownerID, id).
		Where("comments.status IN ?", ownerVisibleStatus()).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get owner comment: %w", err)
	}
	return &row, nil
}

// ListOwnerSites 返回当前用户发表过评论的站点（去重、按 id 升序）。
func (r *CommentRepo) ListOwnerSites(ctx context.Context, ownerID int64) ([]domain.OwnerSite, error) {
	var rows []domain.OwnerSite
	err := gormtx.DB(ctx, r.db).
		Table("sites").
		Joins("JOIN comments ON comments.site_id = sites.id").
		Where("comments.user_id = ?", ownerID).
		Where("comments.status IN ?", ownerVisibleStatus()).
		Distinct("sites.id, sites.name").
		Order("sites.id").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list owner sites: %w", err)
	}
	return rows, nil
}

// UpdateBody 替换一条评论的 Markdown 正文，保持其状态不变。
func (r *CommentRepo) UpdateBody(ctx context.Context, siteID, id int64, body string) error {
	result := gormtx.DB(ctx, r.db).
		Model(&model.Comment{}).
		Where("site_id = ? AND id = ?", siteID, id).
		Update("body_markdown", body)
	if result.Error != nil {
		return fmt.Errorf("update comment body: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// UpdateStatus 应用审核状态转换。
func (r *CommentRepo) UpdateStatus(ctx context.Context, siteID, id int64, status domain.CommentStatus, statusBeforeDelete *domain.CommentStatus, publishedAt, deletedAt *time.Time) error {
	result := gormtx.DB(ctx, r.db).
		Model(&model.Comment{}).
		Where("site_id = ? AND id = ?", siteID, id).
		Updates(map[string]any{
			"status":               status,
			"status_before_delete": statusBeforeDelete,
			"published_at":         publishedAt,
			"deleted_at":           deletedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("update comment status: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// DetachCommentChildren 解除保留评论对待删除评论的 parent_id / root_id 引用。
// 必须在删除目标行前执行，复合外键 ON DELETE CASCADE 否则会误删回复；
// 保留评论自身保持原状态与正文。同一事务内与 HardDelete 一起提交。
func (r *CommentRepo) DetachCommentChildren(ctx context.Context, siteID, id int64) error {
	db := gormtx.DB(ctx, r.db)
	if err := db.Model(&model.Comment{}).
		Where("site_id = ? AND parent_id = ?", siteID, id).
		Update("parent_id", nil).Error; err != nil {
		return fmt.Errorf("detach comment parent refs: %w", err)
	}
	if err := db.Model(&model.Comment{}).
		Where("site_id = ? AND root_id = ?", siteID, id).
		Update("root_id", nil).Error; err != nil {
		return fmt.Errorf("detach comment root refs: %w", err)
	}
	return nil
}

// HardDelete 只删除一条评论行，不触碰其回复。
// 调用方必须先在同一事务内解除保留回复对该评论的 parent_id / root_id 引用。
func (r *CommentRepo) HardDelete(ctx context.Context, siteID, id int64) error {
	result := gormtx.DB(ctx, r.db).
		Where("site_id = ? AND id = ?", siteID, id).
		Delete(&model.Comment{})
	if result.Error != nil {
		return fmt.Errorf("hard delete comment: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// SoftDeleteByUser 单行软删除某用户自己发表的全部评论。
// 只更新 comments.user_id 命中的行，其他用户的回复保持原状态；
// 已删除的节点保持不变。
func (r *CommentRepo) SoftDeleteByUser(ctx context.Context, userID int64, now time.Time) error {
	result := gormtx.DB(ctx, r.db).
		Model(&model.Comment{}).
		Where("user_id = ? AND status <> ?", userID, domain.CommentStatusDeleted).
		Updates(map[string]any{
			"status_before_delete": gorm.Expr("status"),
			"status":               domain.CommentStatusDeleted,
			"deleted_at":           now,
		})
	if result.Error != nil {
		return fmt.Errorf("soft delete user comments: %w", result.Error)
	}
	return nil
}

// DetachUserCommentChildren 在物理删除用户前解除保留评论对该用户评论的
// parent_id / root_id 引用。非目标用户的评论引用目标用户评论时，清空引用，
// 使删除用户只级联删除其本人评论，其他用户的回复保留。
func (r *CommentRepo) DetachUserCommentChildren(ctx context.Context, userID int64) error {
	db := gormtx.DB(ctx, r.db)
	if err := db.Model(&model.Comment{}).
		Where("user_id <> ? AND parent_id IN (SELECT id FROM comments WHERE user_id = ?)", userID, userID).
		Update("parent_id", nil).Error; err != nil {
		return fmt.Errorf("detach user parent refs: %w", err)
	}
	if err := db.Model(&model.Comment{}).
		Where("user_id <> ? AND root_id IN (SELECT id FROM comments WHERE user_id = ?)", userID, userID).
		Update("root_id", nil).Error; err != nil {
		return fmt.Errorf("detach user root refs: %w", err)
	}
	return nil
}

// applyCursor 向查询追加 (created_at, id) keyset 谓词。
// asc 使用 `>` 谓词，desc 使用 `<` 谓词，与请求方向的 ORDER BY 一致。
func applyCursor(db *gorm.DB, cursor *domain.Cursor, qualifier string, sort domain.CommentSort) *gorm.DB {
	if cursor == nil {
		return db
	}
	prefix := ""
	if qualifier != "" {
		prefix = qualifier + "."
	}
	if sort == domain.CommentSortDesc {
		return db.Where("("+prefix+"created_at < ? OR ("+prefix+"created_at = ? AND "+prefix+"id < ?))",
			cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
	}
	return db.Where("("+prefix+"created_at > ? OR ("+prefix+"created_at = ? AND "+prefix+"id > ?))",
		cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
}

// applyCursorOrder 返回与 keyset 谓词同向的 ORDER BY 片段。
func applyCursorOrder(qualifier string, sort domain.CommentSort) string {
	prefix := ""
	if qualifier != "" {
		prefix = qualifier + "."
	}
	if sort == domain.CommentSortDesc {
		return prefix + "created_at DESC, " + prefix + "id DESC"
	}
	return prefix + "created_at ASC, " + prefix + "id ASC"
}

// fromComment 把业务评论转为持久化行。
func fromComment(c *domain.Comment) *model.Comment {
	if c == nil {
		return nil
	}
	return &model.Comment{
		ID:                 c.ID,
		SiteID:             c.SiteID,
		ThreadID:           c.ThreadID,
		UserID:             c.UserID,
		ParentID:           c.ParentID,
		RootID:             c.RootID,
		ReplyToUserID:      c.ReplyToUserID,
		Depth:              c.Depth,
		BodyMarkdown:       c.BodyMarkdown,
		Status:             c.Status,
		StatusBeforeDelete: c.StatusBeforeDelete,
		IPMode:             c.IPMode,
		IPValue:            c.IPValue,
		UAMode:             c.UAMode,
		UARaw:              c.UARaw,
		UABrowser:          c.UABrowser,
		UAOS:               c.UAOS,
		UADevice:           c.UADevice,
		CreatedAt:          c.CreatedAt,
		UpdatedAt:          c.UpdatedAt,
		PublishedAt:        c.PublishedAt,
		DeletedAt:          c.DeletedAt,
	}
}

package repository

import (
	"context"
	"errors"
	"fmt"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

type SiteRepo struct {
	db *gorm.DB
}

// NewSiteRepo 构建站点仓储。
func NewSiteRepo(db *gorm.DB) *SiteRepo {
	return &SiteRepo{db: db}
}

// List 按 id 升序返回全部站点行。
func (r *SiteRepo) List(ctx context.Context) ([]domain.Site, error) {
	var rows []model.Site
	if err := gormtx.DB(ctx, r.db).Order("id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list sites: %w", err)
	}
	out := make([]domain.Site, 0, len(rows))
	for _, row := range rows {
		site := row.ToSite()
		out = append(out, site)
	}
	return out, nil
}

// Get 按 ID 查询站点；不存在时返回 domain.ErrNotFound。
func (r *SiteRepo) Get(ctx context.Context, id int64) (*domain.Site, error) {
	var row model.Site
	err := gormtx.DB(ctx, r.db).Where("id = ?", id).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get site: %w", err)
	}
	site := row.ToSite()
	return &site, nil
}

// Create 插入一条站点行，并把生成的 ID 与时间戳回填到业务站点。
func (r *SiteRepo) Create(ctx context.Context, s *domain.Site) error {
	row := model.Site{
		Name:         s.Name,
		CanonicalURL: s.CanonicalURL,
		Status:       s.Status,
	}
	if err := gormtx.DB(ctx, r.db).Create(&row).Error; err != nil {
		return fmt.Errorf("create site: %w", err)
	}
	s.ID = row.ID
	s.CreatedAt = row.CreatedAt
	s.UpdatedAt = row.UpdatedAt
	return nil
}

// Update 应用一次部分站点更新。
func (r *SiteRepo) Update(ctx context.Context, s *domain.Site) error {
	updates := map[string]any{}
	if s.Name != "" {
		updates["name"] = s.Name
	}
	if s.CanonicalURL != "" {
		updates["canonical_url"] = s.CanonicalURL
	}
	if s.Status != "" {
		updates["status"] = s.Status
	}
	if len(updates) == 0 {
		return nil
	}
	result := gormtx.DB(ctx, r.db).
		Model(&model.Site{}).
		Where("id = ?", s.ID).
		Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("update site: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// Delete 按 ID 删除站点行；不存在时返回 domain.ErrNotFound。
func (r *SiteRepo) Delete(ctx context.Context, id int64) error {
	result := gormtx.DB(ctx, r.db).
		Where("id = ?", id).
		Delete(&model.Site{})
	if result.Error != nil {
		return fmt.Errorf("delete site: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// ListOrigins 按 id 升序返回某个站点的全部 origin 记录。
func (r *SiteRepo) ListOrigins(ctx context.Context, siteID int64) ([]domain.Origin, error) {
	var rows []model.SiteOrigin
	if err := gormtx.DB(ctx, r.db).
		Where("site_id = ?", siteID).
		Order("id").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list site origins: %w", err)
	}
	out := make([]domain.Origin, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ToOrigin())
	}
	return out, nil
}

// GetOrigin 按 site_id 与 origin id 查询记录；不存在时返回 domain.ErrNotFound。
func (r *SiteRepo) GetOrigin(ctx context.Context, siteID, originID int64) (*domain.Origin, error) {
	var row model.SiteOrigin
	err := gormtx.DB(ctx, r.db).
		Where("site_id = ? AND id = ?", siteID, originID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get site origin: %w", err)
	}
	origin := row.ToOrigin()
	return &origin, nil
}

// AddOrigin 为站点插入一个 origin 并返回带生成 ID 的记录；重复时返回 domain.ErrConflict。
func (r *SiteRepo) AddOrigin(ctx context.Context, siteID int64, origin string) (*domain.Origin, error) {
	row := model.SiteOrigin{SiteID: siteID, Origin: origin}
	if err := gormtx.DB(ctx, r.db).Create(&row).Error; err != nil {
		if gormtx.IsDuplicateKeyError(err) {
			return nil, fmt.Errorf("create site origin: %w", domain.ErrConflict)
		}
		return nil, fmt.Errorf("create site origin: %w", err)
	}
	created := row.ToOrigin()
	return &created, nil
}

// UpdateOrigin 以 site_id 与 origin id 限定范围更新 origin 值，返回更新后的记录。
// 记录不存在时返回 domain.ErrNotFound，重复值返回 domain.ErrConflict。
func (r *SiteRepo) UpdateOrigin(ctx context.Context, siteID, originID int64, origin string) (*domain.Origin, error) {
	db := gormtx.DB(ctx, r.db)
	// 更新前以 site 作用域确认记录存在，因为不同数据库下 RowsAffected 语义不一致。
	var row model.SiteOrigin
	if err := db.Where("site_id = ? AND id = ?", siteID, originID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get site origin: %w", err)
	}
	result := db.Model(&model.SiteOrigin{}).
		Where("site_id = ? AND id = ?", siteID, originID).
		Update("origin", origin)
	if result.Error != nil {
		if gormtx.IsDuplicateKeyError(result.Error) {
			return nil, fmt.Errorf("update site origin: %w", domain.ErrConflict)
		}
		return nil, fmt.Errorf("update site origin: %w", result.Error)
	}
	updated := domain.Origin{ID: row.ID, Origin: origin}
	return &updated, nil
}

// RemoveOrigin 删除origin
func (r *SiteRepo) RemoveOrigin(ctx context.Context, siteID, originID int64) error {
	result := gormtx.DB(ctx, r.db).
		Where("site_id = ? AND id = ?", siteID, originID).
		Delete(&model.SiteOrigin{})
	if result.Error != nil {
		return fmt.Errorf("delete site origin: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// AllowedOrigins 返回活跃站点的规范 origins 白名单。
func (r *SiteRepo) AllowedOrigins(ctx context.Context, siteID int64) ([]string, error) {
	var origins []string
	err := gormtx.DB(ctx, r.db).
		Table("site_origins").
		Joins("JOIN sites ON sites.id = site_origins.site_id").
		Where("site_origins.site_id = ? AND sites.status = ?", siteID, domain.SiteStatusActive).
		Order("site_origins.id").
		Pluck("site_origins.origin", &origins).Error
	if err != nil {
		return nil, fmt.Errorf("allowed origins: %w", err)
	}
	return origins, nil
}

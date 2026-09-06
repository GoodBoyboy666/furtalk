// Package site 站点与 Origin 管理用例的业务层。
package site

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"furtalk/internal/domain"
	"furtalk/internal/platform/urlx"
	"furtalk/internal/repository"
)

// Service 实现站点与 origin 的 CRUD，并提供 CORS 中间件消费的 origin 白名单查询。
type Service struct {
	sites *repository.SiteRepo
}

// SiteUpdate 携带可选的 PATCH 更新字段；nil 表示该字段未提供。
type SiteUpdate struct {
	Name         *string
	CanonicalURL *string
	Status       *domain.SiteStatus
}

// NewService 构建站点服务。
func NewService(sites *repository.SiteRepo) *Service {
	return &Service{sites: sites}
}

// List 列出全部站点。
func (s *Service) List(ctx context.Context) ([]domain.Site, error) {
	rows, err := s.sites.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Site, 0, len(rows))
	for i := range rows {
		origins, err := s.sites.ListOrigins(ctx, rows[i].ID)
		if err != nil {
			return nil, err
		}
		rows[i].Origins = origins
		out = append(out, rows[i])
	}
	return out, nil
}

// Create 创建站点。
func (s *Service) Create(ctx context.Context, name, canonicalURL string) (*domain.Site, error) {
	name, canonical, err := normalizeSiteInput(name, canonicalURL)
	if err != nil {
		return nil, err
	}
	row := &domain.Site{
		Name:         name,
		CanonicalURL: canonical,
		Status:       domain.SiteStatusActive,
	}
	if err := s.sites.Create(ctx, row); err != nil {
		return nil, err
	}
	return s.Get(ctx, row.ID)
}

// Get 读取指定站点。
func (s *Service) Get(ctx context.Context, id int64) (*domain.Site, error) {
	row, err := s.sites.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	origins, err := s.sites.ListOrigins(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	row.Origins = origins
	return row, nil
}

// Update 按 PATCH 语义更新站点可选字段：名称、规范 URL 或状态。
func (s *Service) Update(ctx context.Context, id int64, patch SiteUpdate) (*domain.Site, error) {
	if patch.Status != nil {
		if *patch.Status != domain.SiteStatusActive && *patch.Status != domain.SiteStatusDisabled {
			return nil, fmt.Errorf("%w: site status must be active or disabled", domain.ErrValidation)
		}
	}
	updates := &domain.Site{ID: id}
	if patch.Name != nil {
		updates.Name = strings.TrimSpace(*patch.Name)
		if updates.Name == "" {
			return nil, fmt.Errorf("%w: site name must not be empty", domain.ErrValidation)
		}
	}
	if patch.CanonicalURL != nil {
		canonical, err := urlx.CanonicalOrigin(*patch.CanonicalURL)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid canonical url", domain.ErrValidation)
		}
		updates.CanonicalURL = canonical
	}
	if patch.Status != nil {
		updates.Status = *patch.Status
	}
	if err := s.sites.Update(ctx, updates); err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Delete 删除站点。
func (s *Service) Delete(ctx context.Context, id int64, confirm bool) error {
	if !confirm {
		return domain.ErrConfirmationRequired
	}
	return s.sites.Delete(ctx, id)
}

// AddOrigin 校验站点存在后规范化并添加一个 origin；
func (s *Service) AddOrigin(ctx context.Context, siteID int64, origin string) (*domain.Origin, error) {
	if _, err := s.sites.Get(ctx, siteID); err != nil {
		return nil, err
	}
	normalized, err := urlx.CanonicalOrigin(origin)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid origin", domain.ErrValidation)
	}
	created, err := s.sites.AddOrigin(ctx, siteID, normalized)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.ErrConflict
		}
		return nil, err
	}
	return created, nil
}

// UpdateOrigin 按 site 与 origin ID 更新 origin 值并返回更新后的记录；
func (s *Service) UpdateOrigin(ctx context.Context, siteID, originID int64, origin string) (*domain.Origin, error) {
	normalized, err := urlx.CanonicalOrigin(origin)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid origin", domain.ErrValidation)
	}
	updated, err := s.sites.UpdateOrigin(ctx, siteID, originID, normalized)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.ErrConflict
		}
		return nil, err
	}
	return updated, nil
}

// RemoveOrigin 删除站点内指定 ID 的 origin。
func (s *Service) RemoveOrigin(ctx context.Context, siteID, originID int64) error {
	return s.sites.RemoveOrigin(ctx, siteID, originID)
}

// AllowedOrigins 为活跃站点返回精确的 origin 白名单。
func (s *Service) AllowedOrigins(ctx context.Context, siteID int64) ([]string, error) {
	return s.sites.AllowedOrigins(ctx, siteID)
}

// normalizeSiteInput 校验并规范化站点名称与规范 URL。
func normalizeSiteInput(name, canonicalURL string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", fmt.Errorf("%w: site name is required", domain.ErrValidation)
	}
	canonical, err := urlx.CanonicalOrigin(canonicalURL)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid canonical url", domain.ErrValidation)
	}
	return name, canonical, nil
}

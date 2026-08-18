// Package site 是站点与 Origin 管理用例的业务层。
// 只依赖 domain 与 repository，不触碰 GORM；数据经 repository 读写。
package site

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
)

// Service 实现站点与 origin 的 CRUD，并提供 CORS 中间件消费的 origin 白名单查询。
type Service struct {
	sites *repository.SiteRepo
}

// NewService 构建站点服务，并注入站点仓储。
func NewService(sites *repository.SiteRepo) *Service {
	return &Service{sites: sites}
}

// List 返回全部站点及其 origins，按 id 升序排列。
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

// Create 规范化站点名称与规范 URL 后创建站点，并返回带 origins 的完整站点。
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

// Get 按 ID 返回站点及其 origins；站点不存在时返回 domain.ErrNotFound。
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

// SiteUpdate 携带可选的 PATCH 更新字段；nil 表示该字段未提供。
type SiteUpdate struct {
	Name         *string
	CanonicalURL *string
	Status       *domain.SiteStatus
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
		canonical, err := normalizeURL(*patch.CanonicalURL)
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

// Delete 需要显式确认后才执行破坏性级联删除。
func (s *Service) Delete(ctx context.Context, id int64, confirm bool) error {
	if !confirm {
		return domain.ErrConfirmationRequired
	}
	return s.sites.Delete(ctx, id)
}

// AddOrigin 校验站点存在后规范化并添加一个 origin；
// 站点不存在返回 domain.ErrNotFound，重复时返回 domain.ErrConflict。
func (s *Service) AddOrigin(ctx context.Context, siteID int64, origin string) (*domain.Origin, error) {
	if _, err := s.sites.Get(ctx, siteID); err != nil {
		return nil, err
	}
	normalized, err := normalizeURL(origin)
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
// 记录不存在返回 domain.ErrNotFound，重复值返回 domain.ErrConflict。
func (s *Service) UpdateOrigin(ctx context.Context, siteID, originID int64, origin string) (*domain.Origin, error) {
	normalized, err := normalizeURL(origin)
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
	canonical, err := normalizeURL(canonicalURL)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid canonical url", domain.ErrValidation)
	}
	return name, canonical, nil
}

// normalizeURL 规范化精确 origin 或 canonical URL。
func normalizeURL(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" || trimmed == "null" {
		return "", domain.ErrValidation
	}
	if strings.ContainsAny(trimmed, " \t\r\n,") {
		return "", domain.ErrValidation
	}
	if strings.Contains(trimmed, "*") {
		return "", domain.ErrValidation
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", domain.ErrValidation
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", domain.ErrValidation
	}
	if u.Host == "" {
		return "", domain.ErrValidation
	}
	if u.User != nil {
		return "", domain.ErrValidation
	}
	if u.Path != "" {
		return "", domain.ErrValidation
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", domain.ErrValidation
	}
	if strings.Contains(u.Host, "*") {
		return "", domain.ErrValidation
	}
	host, port, splitErr := net.SplitHostPort(u.Host)
	if splitErr != nil {
		host = u.Host
		port = ""
	}
	host = strings.ToLower(host)
	if host == "" {
		return "", domain.ErrValidation
	}
	if u.Scheme == "http" && !isLocalhost(host) {
		return "", domain.ErrValidation
	}
	switch port {
	case "":
	case "443":
		if u.Scheme != "https" {
			return "", domain.ErrValidation
		}
		port = ""
	case "80":
		if u.Scheme != "http" {
			return "", domain.ErrValidation
		}
		port = ""
	default:
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 1 || portNum > 65535 {
			return "", domain.ErrValidation
		}
	}
	if port == "" {
		return u.Scheme + "://" + host, nil
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port), nil
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

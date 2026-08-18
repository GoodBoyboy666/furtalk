package comment

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"furtalk/internal/domain"
	"furtalk/internal/platform/crypto"
	jwt "furtalk/internal/platform/token"
)

// IssueAuthorization 签发绑定 {site_id, origin, user_id, request_id} 的 60 秒一次性授权码。
// 授权矩阵按当前评论模式限制主体角色：匿名模式仅管理员，认证模式用户与管理员均可。
func (s *Service) IssueAuthorization(ctx context.Context, input IssueInput) (*AuthCodeResult, error) {
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if !popupAuthorizationAllowed(pol.Mode, input.Role) {
		return nil, domain.ErrForbidden
	}
	if err := s.validateSiteAndOrigin(ctx, input.SiteID, input.Origin); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.RequestID) == "" {
		return nil, fmt.Errorf("%w: request_id is required", domain.ErrValidation)
	}

	code, err := generateAuthCode()
	if err != nil {
		return nil, err
	}
	expiresAt := s.now().UTC().Add(s.codeTTL)
	record := AuthCodeRecord{
		SiteID:         input.SiteID,
		Origin:         input.Origin,
		UserID:         input.UserID,
		RequestID:      input.RequestID,
		ExpiresAt:      expiresAt,
		CredentialMode: pol.Mode,
	}
	if err := s.codes.SetAuthCode(ctx, cryptox.SHA256Hex([]byte(code)), record, s.codeTTL); err != nil {
		return nil, err
	}
	return &AuthCodeResult{Code: code, RequestID: input.RequestID, ExpiresAt: expiresAt}, nil
}

// ExchangeAuthorization 原子消费一次性授权码，在绑定、实时策略与活跃主体匹配时
// 签发 widget_authenticated 令牌。这是唯一把授权码兑换为 Widget 评论凭据的路径，
// 匿名模式只允许管理员，认证模式允许普通用户与管理员。
func (s *Service) ExchangeAuthorization(ctx context.Context, rawCode, requestOrigin string) (*SessionResult, error) {
	if strings.TrimSpace(rawCode) == "" {
		return nil, domain.ErrInvalidCredentials
	}
	record, err := s.codes.ConsumeAuthCode(ctx, cryptox.SHA256Hex([]byte(rawCode)))
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	if record.Origin != requestOrigin {
		return nil, domain.ErrInvalidCredentials
	}
	if s.now().UTC().After(record.ExpiresAt) {
		return nil, domain.ErrInvalidCredentials
	}
	if err := s.validateSiteAndOrigin(ctx, record.SiteID, requestOrigin); err != nil {
		if errors.Is(err, domain.ErrForbidden) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.requireActivePopupPrincipal(ctx, record, pol); err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	tokenValue, err := s.signer.SignWidget(record.UserID, record.SiteID, jwt.TokenKindWidgetAuthenticated, strconv.FormatInt(pol.Epoch, 10))
	if err != nil {
		return nil, err
	}
	return &SessionResult{Token: tokenValue, ExpiresAt: s.now().UTC().Add(s.signer.Lifetime())}, nil
}

// requireActivePopupPrincipal 解析授权记录的主体并复检其角色/状态满足记录模式的
// popup 授权矩阵。这是授权签发与消费之间角色/状态变化的最后一道门。
func (s *Service) requireActivePopupPrincipal(ctx context.Context, record AuthCodeRecord, pol domain.CommentPolicy) error {
	if record.CredentialMode != pol.Mode {
		return domain.ErrInvalidCredentials
	}
	principal, err := s.authz.Resolve(ctx, record.UserID)
	if err != nil {
		return domain.ErrInvalidCredentials
	}
	if principal.Status != domain.UserStatusActive {
		return domain.ErrInvalidCredentials
	}
	if !popupAuthorizationAllowed(record.CredentialMode, principal.Role) {
		return domain.ErrInvalidCredentials
	}
	return nil
}

// Probe 报告提交的 widget 令牌当前是否可用。live 评论模式只决定角色矩阵，
// 不能从令牌本身推导；令牌的 epoch、站点与实时模式角色都必须匹配。
func (s *Service) Probe(ctx context.Context, raw, requestOrigin string) *ProbeResult {
	if strings.TrimSpace(raw) == "" {
		return &ProbeResult{Valid: false}
	}
	cred, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		return &ProbeResult{Valid: false}
	}
	allowed, err := s.sites.AllowedOrigins(ctx, cred.SiteID())
	if err != nil || !slices.Contains(allowed, requestOrigin) {
		return &ProbeResult{Valid: false}
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return &ProbeResult{Valid: false}
	}
	if cred.Epoch() != pol.Epoch {
		return &ProbeResult{Valid: false}
	}
	principal, err := s.authz.Resolve(ctx, cred.UserID())
	if err != nil {
		return &ProbeResult{Valid: false}
	}
	if principal.Status != domain.UserStatusActive || !WidgetRoleAllowed(pol.Mode, principal.Role) {
		return &ProbeResult{Valid: false}
	}
	return &ProbeResult{
		Valid:          true,
		CredentialMode: domain.CommentModeAuthenticated,
		UserID:         cred.UserID(),
		SiteID:         cred.SiteID(),
		ExpiresAt:      cred.ExpiresAt(),
	}
}

// AuthorizationContext 只读返回授权页展示所需的 {site_id, site_name, origin} 上下文。
// 复用签发授权码的授权矩阵、站点活跃与允许 Origin 检查，但从不创建授权记录。
func (s *Service) AuthorizationContext(ctx context.Context, siteID int64, role domain.Role, origin string) (*AuthorizationContextView, error) {
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if !popupAuthorizationAllowed(pol.Mode, role) {
		return nil, domain.ErrForbidden
	}
	if err := s.validateSiteAndOrigin(ctx, siteID, origin); err != nil {
		return nil, err
	}
	site, err := s.sites.Get(ctx, siteID)
	if err != nil {
		return nil, err
	}
	return &AuthorizationContextView{SiteID: siteID, SiteName: site.Name, Origin: origin}, nil
}

// validateSiteAndOrigin 校验站点活跃且 origin 与其白名单中的一个值按字节精确匹配。
func (s *Service) validateSiteAndOrigin(ctx context.Context, siteID int64, origin string) error {
	site, err := s.sites.Get(ctx, siteID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrForbidden
		}
		return err
	}
	if site.Status != domain.SiteStatusActive {
		return domain.ErrForbidden
	}
	allowed, err := s.sites.AllowedOrigins(ctx, siteID)
	if err != nil {
		return err
	}
	if !slices.Contains(allowed, origin) {
		return domain.ErrForbidden
	}
	return nil
}

// generateAuthCode 返回编码为 URL 安全 base64 的 128 位 CSPRNG 授权码。
func generateAuthCode() (string, error) {
	return cryptox.RandomToken(authCodeBytes)
}

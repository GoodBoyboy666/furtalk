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
	"furtalk/internal/platform/logging"
	jwt "furtalk/internal/platform/token"
)

// IssueAuthorization 签发绑定 {site_id, origin, user_id, request_id} 的 60 秒一次性授权码。
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
		if errors.Is(err, errAuthCodeCapacity) {
			logging.FromContext(ctx, s.log).WarnContext(ctx, "ephemeral namespace capacity exhausted", "namespace", "widget_auth_code")
		}
		return nil, err
	}
	return &AuthCodeResult{Code: code, RequestID: input.RequestID, ExpiresAt: expiresAt}, nil
}

// ExchangeAuthorization 消费授权码并在主体校验通过后签发 Widget 凭据。
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

// requireActivePopupPrincipal 复核授权主体的实时角色与状态。
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

// Probe 校验 Widget 凭据并返回探测结果。
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
		Role:           principal.Role,
		ExpiresAt:      cred.ExpiresAt(),
	}
}

// AuthorizationContext 只读返回授权页展示所需的 {site_id, site_name, origin} 上下文。
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

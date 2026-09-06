package comment

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/token"
)

// WidgetJWTVerifier 针对固定的 platform/token 策略验证 widget JWT 凭证。
type WidgetJWTVerifier struct {
	svc *jwt.Service
}

// NewWidgetJWTVerifier 在共享 JWT 服务之上构建验证器。
func NewWidgetJWTVerifier(svc *jwt.Service) *WidgetJWTVerifier {
	return &WidgetJWTVerifier{svc: svc}
}

// Verify 验证原始 Widget 凭据。
func (v *WidgetJWTVerifier) Verify(ctx context.Context, raw string) (WidgetCredential, error) {
	if v.svc == nil {
		return nil, errors.New("comment: widget jwt verifier is not configured")
	}
	claims, err := v.svc.Parse(raw, jwt.AudienceWidgetAuthenticated, jwt.TokenKindWidgetAuthenticated)
	if err != nil {
		return nil, err
	}
	userID, err := claims.UserID()
	if err != nil {
		return nil, err
	}
	siteID, err := parseDecimalClaim(claims.SiteID, "site_id")
	if err != nil {
		return nil, err
	}
	epoch, err := parseDecimalClaim(claims.CredentialEpoch, "credential_epoch")
	if err != nil {
		return nil, err
	}
	var expiresAt time.Time
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	return &widgetCredential{userID: userID, siteID: siteID, epoch: epoch, expiresAt: expiresAt}, nil
}

type widgetCredential struct {
	userID    int64
	siteID    int64
	epoch     int64
	expiresAt time.Time
}

// UserID 返回凭证绑定的用户 id。
func (c *widgetCredential) UserID() int64 { return c.userID }

// SiteID 返回凭证绑定的站点 id。
func (c *widgetCredential) SiteID() int64 { return c.siteID }

// Epoch 返回签发凭证时的凭证代次。
func (c *widgetCredential) Epoch() int64 { return c.epoch }

// ExpiresAt 返回凭证过期时间。
func (c *widgetCredential) ExpiresAt() time.Time { return c.expiresAt }

// WidgetRoleAllowed 检查 Widget 主体角色是否允许当前评论模式。
func WidgetRoleAllowed(mode string, role domain.Role) bool {
	switch mode {
	case domain.CommentModeAnonymous:
		return role == domain.RoleAdmin
	case domain.CommentModeAuthenticated:
		return role == domain.RoleUser || role == domain.RoleAdmin
	default:
		return false
	}
}

// popupAuthorizationAllowed 检查第一方主体是否允许签发 Widget 授权。
func popupAuthorizationAllowed(mode string, role domain.Role) bool {
	switch mode {
	case domain.CommentModeAnonymous:
		return role == domain.RoleAdmin
	case domain.CommentModeAuthenticated:
		return role == domain.RoleUser || role == domain.RoleAdmin
	default:
		return false
	}
}

// parseDecimalClaim 解析 JWT 中的非负十进制业务 ID。
func parseDecimalClaim(raw, name string) (int64, error) {
	if raw == "" {
		return 0, fmt.Errorf("%w: missing %s", domain.ErrValidation, name)
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 0 {
		return 0, fmt.Errorf("%w: invalid %s", domain.ErrValidation, name)
	}
	return id, nil
}

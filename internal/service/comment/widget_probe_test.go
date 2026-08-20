package comment

import (
	"context"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
)

// probeVerifier 返回固定的已验证 widget 凭证。
type probeVerifier struct {
	cred WidgetCredential
}

func (v probeVerifier) Verify(context.Context, string) (WidgetCredential, error) {
	return v.cred, nil
}

// probePrincipalResolver 返回固定的当前主体。
type probePrincipalResolver struct {
	principal domain.Principal
}

func (r probePrincipalResolver) Resolve(context.Context, int64) (domain.Principal, error) {
	return r.principal, nil
}

// probeTestService 装配 Probe 所需的最小服务：真实站点白名单 + 固定策略/凭证/主体。
func probeTestService(t *testing.T, mode string, role domain.Role, status domain.UserStatus) *Service {
	t.Helper()
	db := newReplyTestDB(t)
	siteID := seedWidgetDomainSite(t, db)
	return NewService(Dependencies{
		Sites:    repository.NewSiteRepo(db),
		Settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{Mode: mode, Epoch: 1}},
		Verifier: probeVerifier{cred: &widgetCredential{
			userID: 1, siteID: siteID, epoch: 1, expiresAt: time.Now().Add(time.Hour),
		}},
		Authz: probePrincipalResolver{principal: domain.Principal{UserID: 1, Role: role, Status: status}},
	})
}

// TestProbeWidgetRoleAndStatusMatrix 锁定 Probe 的角色/状态判定：
// 认证模式下普通用户与管理员都可使用 widget 凭据；匿名模式下只允许活跃管理员；
// 非活跃主体一律无效。
func TestProbeWidgetRoleAndStatusMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mode   string
		role   domain.Role
		status domain.UserStatus
		want   bool
	}{
		{name: "authenticated admin", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, status: domain.UserStatusActive, want: true},
		{name: "authenticated user", mode: domain.CommentModeAuthenticated, role: domain.RoleUser, status: domain.UserStatusActive, want: true},
		{name: "anonymous admin", mode: domain.CommentModeAnonymous, role: domain.RoleAdmin, status: domain.UserStatusActive, want: true},
		{name: "anonymous user", mode: domain.CommentModeAnonymous, role: domain.RoleUser, status: domain.UserStatusActive, want: false},
		{name: "authenticated admin disabled", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, status: domain.UserStatusDisabled, want: false},
		{name: "authenticated admin deleted", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, status: domain.UserStatusDeleted, want: false},
		{name: "anonymous admin disabled", mode: domain.CommentModeAnonymous, role: domain.RoleAdmin, status: domain.UserStatusDisabled, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := probeTestService(t, tt.mode, tt.role, tt.status)
			result := svc.Probe(context.Background(), "raw-token", "https://widget.example.com")
			if result.Valid != tt.want {
				t.Fatalf("Probe valid = %v, want %v", result.Valid, tt.want)
			}
			if tt.want && result.CredentialMode != domain.CommentModeAuthenticated {
				t.Fatalf("CredentialMode = %q, want %q", result.CredentialMode, domain.CommentModeAuthenticated)
			}
			if tt.want && result.Role != tt.role {
				t.Fatalf("Role = %q, want %q", result.Role, tt.role)
			}
		})
	}
}

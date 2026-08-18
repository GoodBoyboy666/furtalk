package comment

import (
	"testing"

	"furtalk/internal/domain"
)

// TestPopupAuthorizationAllowedMatrix 锁定第一方 popup 授权矩阵：
// 匿名模式仅管理员可授权，认证模式用户与管理员均可，未知模式一律拒绝。
func TestPopupAuthorizationAllowedMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode string
		role domain.Role
		want bool
	}{
		{name: "anonymous user", mode: domain.CommentModeAnonymous, role: domain.RoleUser, want: false},
		{name: "anonymous admin", mode: domain.CommentModeAnonymous, role: domain.RoleAdmin, want: true},
		{name: "anonymous unknown role", mode: domain.CommentModeAnonymous, role: "supervisor", want: false},
		{name: "authenticated user", mode: domain.CommentModeAuthenticated, role: domain.RoleUser, want: true},
		{name: "authenticated admin", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, want: true},
		{name: "authenticated unknown role", mode: domain.CommentModeAuthenticated, role: "supervisor", want: false},
		{name: "unknown mode user", mode: "hybrid", role: domain.RoleUser, want: false},
		{name: "unknown mode admin", mode: "hybrid", role: domain.RoleAdmin, want: false},
		{name: "empty mode admin", mode: "", role: domain.RoleAdmin, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := popupAuthorizationAllowed(tt.mode, tt.role); got != tt.want {
				t.Fatalf("popupAuthorizationAllowed(%q, %q) = %v, want %v", tt.mode, tt.role, got, tt.want)
			}
		})
	}
}

// TestWidgetRoleAllowedMatrix 锁定 widget 角色判定矩阵：
// 认证模式允许普通用户与管理员；匿名模式下 widget 凭据只允许管理员；
// 未知模式一律拒绝。
func TestWidgetRoleAllowedMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode string
		role domain.Role
		want bool
	}{
		{name: "anonymous user", mode: domain.CommentModeAnonymous, role: domain.RoleUser, want: false},
		{name: "anonymous admin", mode: domain.CommentModeAnonymous, role: domain.RoleAdmin, want: true},
		{name: "anonymous unknown role", mode: domain.CommentModeAnonymous, role: "supervisor", want: false},
		{name: "authenticated user", mode: domain.CommentModeAuthenticated, role: domain.RoleUser, want: true},
		{name: "authenticated admin", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, want: true},
		{name: "authenticated unknown role", mode: domain.CommentModeAuthenticated, role: "supervisor", want: false},
		{name: "unknown mode user", mode: "hybrid", role: domain.RoleUser, want: false},
		{name: "unknown mode admin", mode: "hybrid", role: domain.RoleAdmin, want: false},
		{name: "empty mode user", mode: "", role: domain.RoleUser, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WidgetRoleAllowed(tt.mode, tt.role); got != tt.want {
				t.Fatalf("WidgetRoleAllowed(%q, %q) = %v, want %v", tt.mode, tt.role, got, tt.want)
			}
		})
	}
}

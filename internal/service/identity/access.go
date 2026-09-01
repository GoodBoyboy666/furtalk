package identity

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"furtalk/internal/domain"
)

const authzCacheTTL = 5 * time.Minute

// firstPartyAllowed 判断在给定评论模式下，非 admin 用户是否可以使用第一方 API。
// 匿名模式下普通用户返回 false，管理员在任何模式下都有第一方访问权限。
func firstPartyAllowed(mode string, role domain.Role) bool {
	return mode != domain.CommentModeAnonymous || role == domain.RoleAdmin
}

// authzKey 返回用户授权数据的缓存键。
func authzKey(userID int64) string {
	return "authz:user:" + strconv.FormatInt(userID, 10)
}

// Resolve 返回用户 id 的当前主体，优先从 authz 缓存读取。
func (s *Service) Resolve(ctx context.Context, userID int64) (domain.Principal, error) {
	unlock := s.authzLocks.lock(userID)
	defer unlock()

	var info domain.AuthzInfo
	key := authzKey(userID)
	err := s.cache.GetOrLoad(ctx, key, &info, authzCacheTTL, func() (any, error) {
		user, err := s.users.FindByID(ctx, userID)
		if err != nil {
			return nil, err
		}
		if err := validateInfo(user.Role, user.Status); err != nil {
			return nil, err
		}
		return domain.AuthzInfo{Role: user.Role, Status: user.Status, SessionVersion: user.SessionVersion}, nil
	})
	if err != nil {
		return domain.Principal{}, fmt.Errorf("identity: resolve %d: %w", userID, err)
	}
	return domain.Principal{UserID: userID, Role: info.Role, Status: info.Status, SessionVersion: info.SessionVersion}, nil
}

// RequireAdmin 检查主体是否活跃且拥有 admin 角色。
func (s *Service) RequireAdmin(ctx context.Context, p domain.Principal) error {
	if p.Status != domain.UserStatusActive {
		return domain.ErrDisabled
	}
	if p.Role != domain.RoleAdmin {
		return domain.ErrForbidden
	}
	return nil
}

// RequireUser 检查活跃主体是否可以使用第一方用户 API。
func (s *Service) RequireUser(ctx context.Context, p domain.Principal) error {
	if p.Status != domain.UserStatusActive {
		return domain.ErrDisabled
	}
	if p.Role == domain.RoleAdmin {
		return nil
	}
	_, mode, err := s.policy.Policy(ctx)
	if err != nil {
		return fmt.Errorf("identity: read comment mode: %w", err)
	}
	if !firstPartyAllowed(mode, p.Role) {
		return domain.ErrAnonymousRestricted
	}
	return nil
}

func validateInfo(role domain.Role, status domain.UserStatus) error {
	if role != domain.RoleAdmin && role != domain.RoleUser {
		return fmt.Errorf("identity: unknown role %q", role)
	}
	if status != domain.UserStatusActive && status != domain.UserStatusDisabled && status != domain.UserStatusDeleted {
		return fmt.Errorf("identity: unknown status %q", status)
	}
	return nil
}

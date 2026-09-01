package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"furtalk/internal/domain"
)

// IdentityKind 枚举 /me/identities 返回的登录方式种类。
const (
	IdentityKindPassword = "password"
	IdentityKindPasskey  = "passkey"
	IdentityKindExternal = "external"
)

// Identity 是 /me/identities 返回的登录方式数据。
type Identity struct {
	Kind       string
	ID         int64
	Name       string
	Provider   string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// ListIdentities 返回用户的登录方式元数据。
func (s *Service) ListIdentities(ctx context.Context, userID int64) ([]Identity, error) {
	out := []Identity{}
	if hasPassword, err := s.users.HasPassword(ctx, userID); err != nil {
		return nil, err
	} else if hasPassword {
		out = append(out, Identity{Kind: IdentityKindPassword})
	}
	passkeys, err := s.passkeys.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, row := range passkeys {
		out = append(out, Identity{
			Kind:       IdentityKindPasskey,
			ID:         row.ID,
			Name:       row.Name,
			CreatedAt:  row.CreatedAt,
			LastUsedAt: row.LastUsedAt,
		})
	}
	identities, err := s.identities.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, row := range identities {
		out = append(out, Identity{
			Kind:       IdentityKindExternal,
			ID:         row.ID,
			Provider:   row.ProviderKey,
			CreatedAt:  row.CreatedAt,
			LastUsedAt: row.LastLoginAt,
		})
	}
	return out, nil
}

// DeletePasskey 移除 passkey 凭证；若它是用户最后的登录方式则拒绝。
func (s *Service) DeletePasskey(ctx context.Context, userID, passkeyID int64) error {
	unlock := s.credentialLocks.lock(userID)
	defer unlock()
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		if _, err := s.users.FindByIDLocked(ctx, userID); err != nil {
			return err
		}
		row, err := s.passkeys.GetByUserIDAndID(ctx, userID, passkeyID)
		if err != nil {
			return err
		}
		remaining, err := s.loginMethodCount(ctx, userID)
		if err != nil {
			return err
		}
		if remaining <= 1 {
			return domain.ErrLastLoginMethod
		}
		return s.passkeys.DeleteByUserAndID(ctx, userID, row.ID)
	})
}

// RenamePasskey 更新用户 passkey 凭证的名称（1–100 字符，去除首尾空白）。
// 凭证归属由 repository 按 userID+id 校验；非法名称返回 domain.ErrValidation。
func (s *Service) RenamePasskey(ctx context.Context, userID, passkeyID int64, name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len([]rune(trimmed)) > 100 {
		return fmt.Errorf("%w: passkey name must be between 1 and 100 characters", domain.ErrValidation)
	}
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		row, err := s.passkeys.GetByUserIDAndID(ctx, userID, passkeyID)
		if err != nil {
			return err
		}
		return s.passkeys.RenameByUserAndID(ctx, userID, row.ID, trimmed)
	})
}

// DeleteExternalIdentity 解除外部身份绑定；若它是用户最后的登录方式则拒绝。
func (s *Service) DeleteExternalIdentity(ctx context.Context, userID, identityID int64) error {
	unlock := s.credentialLocks.lock(userID)
	defer unlock()
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		if _, err := s.users.FindByIDLocked(ctx, userID); err != nil {
			return err
		}
		row, err := s.identities.GetByUserIDAndID(ctx, userID, identityID)
		if err != nil {
			return err
		}
		remaining, err := s.loginMethodCount(ctx, userID)
		if err != nil {
			return err
		}
		if remaining <= 1 {
			return domain.ErrLastLoginMethod
		}
		return s.identities.DeleteByUserAndID(ctx, userID, row.ID)
	})
}

// loginMethodCount 统计用户的密码、passkey 与外部身份三种登录方式总数。
func (s *Service) loginMethodCount(ctx context.Context, userID int64) (int64, error) {
	var total int64
	if hasPassword, err := s.users.HasPassword(ctx, userID); err != nil {
		return 0, err
	} else if hasPassword {
		total++
	}
	passkeyCount, err := s.passkeys.CountByUserID(ctx, userID)
	if err != nil {
		return 0, err
	}
	identityCount, err := s.identities.CountByUserID(ctx, userID)
	if err != nil {
		return 0, err
	}
	return total + passkeyCount + identityCount, nil
}

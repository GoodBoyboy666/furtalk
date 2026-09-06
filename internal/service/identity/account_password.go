package identity

import (
	"context"

	"furtalk/internal/domain"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/logging"
)

// ChangePassword 设置或替换当前用户密码并返回更新后的会话。
func (s *Service) ChangePassword(ctx context.Context, userID int64, currentPassword *string, newPassword string) (*Session, error) {
	if len(newPassword) < minPasswordLength {
		return nil, domain.ErrValidation
	}
	has, err := s.users.HasPassword(ctx, userID)
	if err != nil {
		return nil, err
	}
	if has {
		if currentPassword == nil || *currentPassword == "" {
			return nil, domain.ErrInvalidCredentials
		}
		hash, err := s.users.PasswordHash(ctx, userID)
		if err != nil {
			return nil, err
		}
		if !verifyPassword(hash, *currentPassword) {
			return nil, domain.ErrInvalidCredentials
		}
	}
	var version int64
	err = s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		v, err := s.setPassword(ctx, userID, newPassword)
		if err != nil {
			return err
		}
		version = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.invalidateAuthz(ctx, userID); err != nil {
		return nil, err
	}
	token, err := s.signer.SignFirstParty(userID, version)
	if err != nil {
		return nil, err
	}
	csrfToken, err := cryptox.RandomToken(32)
	if err != nil {
		return nil, err
	}
	return &Session{
		Token:     token,
		CSRFToken: csrfToken,
		ExpiresAt: s.now().UTC().Add(s.signer.Lifetime()),
	}, nil
}

// invalidateAuthz 删除用户 authz 缓存，失败时记录错误并触发快速失败处理。
func (s *Service) invalidateAuthz(ctx context.Context, userID int64) error {
	unlock := s.authzLocks.lock(userID)
	defer unlock()

	if err := s.cache.Delete(ctx, authzKey(userID)); err != nil {
		logging.FromContext(ctx, s.log).ErrorContext(ctx, "authz cache invalidation failed", logging.ID("user_id", userID), logging.Error(err))
		s.failFast(err)
		return domain.ErrCacheInvalidation
	}
	return nil
}

// RevokeAllSessions 递增目标用户的会话代次并使全部已签发 JWT 失效。
func (s *Service) RevokeAllSessions(ctx context.Context, userID int64) error {
	err := s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		_, err := s.users.BumpSessionVersion(ctx, userID)
		return err
	})
	if err != nil {
		return err
	}
	return s.invalidateAuthz(ctx, userID)
}

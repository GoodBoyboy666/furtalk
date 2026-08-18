package identity

import (
	"context"

	"furtalk/internal/domain"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/logging"
)

// ChangePassword 设置或替换当前用户密码（个人中心命令），并返回重签的新会话。
//
// 无密码用户凭已认证会话首次设密，currentPassword 可缺省并被忽略；
// 已有密码用户必须提交正确的 currentPassword，错误时返回通用凭据错误且零写入。
// 成功在密码写入的同一数据库事务内递增会话代次、提交后失效 authz 缓存，
// 并为当前浏览器重签新版本的会话与 CSRF Cookie：其他设备失效，当前设备保持登录。
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

// invalidateAuthz 删除用户 authz 缓存，失败按 fail-fast 契约处理。
// 密码/会话代次变更提交后必须调用，旧缓存不能继续接受已失效的 JWT。
func (s *Service) invalidateAuthz(ctx context.Context, userID int64) error {
	if err := s.cache.Delete(ctx, authzKey(userID)); err != nil {
		logging.FromContext(ctx, s.log).ErrorContext(ctx, "authz cache invalidation failed", logging.ID("user_id", userID), logging.Error(err))
		s.failFast(err)
		return domain.ErrCacheInvalidation
	}
	return nil
}

// RevokeAllSessions 递增目标用户的会话代次并使全部已签发 JWT 失效。
// 成功提交后同步失效 authz 缓存；调用方（handler）负责清除当前浏览器 Cookie，
// 使当前设备也退出。不签发替代会话。
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

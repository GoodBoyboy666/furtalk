package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/value"
)

// OptionalNullableString 表示一个既可被省略又可被显式置空的字符串字段。
// Set=false 表示请求未提供该字段；Set=true 且 Value=nil 表示显式 null；
// Set=true 且 Value 非空表示普通字符串值。
type OptionalNullableString struct {
	Set   bool
	Value *string
}

// UnmarshalJSON 区分 JSON 中的缺失、null 与字符串三种状态。
func (o *OptionalNullableString) UnmarshalJSON(data []byte) error {
	o.Set = true
	if string(data) == "null" {
		o.Value = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	o.Value = &s
	return nil
}

// AdminCreateUserInput 是管理员创建用户命令的输入。
type AdminCreateUserInput struct {
	Email         string
	Nickname      string
	WebsiteURL    *string
	Role          domain.Role
	Password      *string
	EmailVerified bool
}

// AdminUpdateUserInput 是管理员更新用户命令的输入。
// 指针字段为 nil 表示"未提供"；WebsiteURL 通过 OptionalNullableString
// 区分省略、显式 null 与字符串三种状态。
type AdminUpdateUserInput struct {
	Email         *string
	Nickname      *string
	WebsiteURL    OptionalNullableString
	Role          *domain.Role
	Status        *domain.UserStatus
	EmailVerified *bool
}

// AdminCreateUser 原子创建用户：资料、可选密码哈希与可选验证时间在同一事务写入。
// 密码与验证开关相互独立：设置密码不自动验证邮箱，验证默认关闭。
func (s *Service) AdminCreateUser(ctx context.Context, input AdminCreateUserInput) (*Profile, error) {
	original, normalized, err := value.NormalizeEmail(input.Email)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	if input.Role != domain.RoleUser && input.Role != domain.RoleAdmin {
		return nil, fmt.Errorf("%w: role must be user or admin", domain.ErrValidation)
	}
	nickname := strings.TrimSpace(input.Nickname)
	if nickname == "" || len(nickname) > 100 {
		return nil, fmt.Errorf("%w: nickname must be between 1 and 100 characters", domain.ErrValidation)
	}
	if input.WebsiteURL != nil {
		website, err := value.NormalizeWebsite(*input.WebsiteURL)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", domain.ErrValidation, err)
		}
		input.WebsiteURL = &website
	}
	var passwordHash string
	var changedAt time.Time
	if input.Password != nil {
		if len(*input.Password) < minPasswordLength {
			return nil, domain.ErrValidation
		}
		hash, err := hashPassword(*input.Password)
		if err != nil {
			return nil, err
		}
		passwordHash = hash
		changedAt = s.now().UTC().Truncate(time.Microsecond)
	}

	user := &domain.User{
		Email:           original,
		EmailNormalized: normalized,
		Nickname:        nickname,
		WebsiteURL:      input.WebsiteURL,
		Role:            input.Role,
		Status:          domain.UserStatusActive,
	}
	if input.EmailVerified {
		verifiedAt := s.now().UTC().Truncate(time.Microsecond)
		user.EmailVerifiedAt = &verifiedAt
	}

	err = s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		if input.Password != nil {
			return s.users.CreateWithPassword(ctx, user, passwordHash, changedAt)
		}
		return s.users.Create(ctx, user)
	})
	if err != nil {
		return nil, err
	}
	return s.getWithPrefs(ctx, user.ID)
}

// AdminUpdateUser 合并写入管理端更新字段。
// 邮箱变化执行与创建一致的规范化/唯一性校验并默认保留验证状态；
// 角色/状态变化保持最后活跃管理员守卫，提交后同步失效 authz 缓存。
func (s *Service) AdminUpdateUser(ctx context.Context, targetID int64, input AdminUpdateUserInput) (*Profile, error) {
	var roleStatusChanged bool
	runInTx := s.txRunner.RunInTx
	if input.Role != nil || input.Status != nil {
		runInTx = s.runAdminMutation
	}
	err := runInTx(ctx, func(ctx context.Context) error {
		current, err := s.users.FindByID(ctx, targetID)
		if err != nil {
			return err
		}

		email := current.Email
		emailNormalized := current.EmailNormalized
		if input.Email != nil {
			original, normalized, err := value.NormalizeEmail(*input.Email)
			if err != nil {
				return fmt.Errorf("%w: %v", domain.ErrValidation, err)
			}
			email = original
			emailNormalized = normalized
		}

		nickname := current.Nickname
		if input.Nickname != nil {
			nickname = strings.TrimSpace(*input.Nickname)
			if nickname == "" || len(nickname) > 100 {
				return fmt.Errorf("%w: nickname must be between 1 and 100 characters", domain.ErrValidation)
			}
		}

		websiteURL := current.WebsiteURL
		if input.WebsiteURL.Set {
			if input.WebsiteURL.Value != nil {
				website, err := value.NormalizeWebsite(*input.WebsiteURL.Value)
				if err != nil {
					return fmt.Errorf("%w: %v", domain.ErrValidation, err)
				}
				websiteURL = &website
			} else {
				websiteURL = nil
			}
		}

		nextRole := current.Role
		if input.Role != nil {
			if *input.Role != domain.RoleUser && *input.Role != domain.RoleAdmin {
				return fmt.Errorf("%w: role must be user or admin", domain.ErrValidation)
			}
			nextRole = *input.Role
		}
		nextStatus := current.Status
		if input.Status != nil {
			if *input.Status != domain.UserStatusActive && *input.Status != domain.UserStatusDisabled {
				return fmt.Errorf("%w: status must be active or disabled", domain.ErrValidation)
			}
			nextStatus = *input.Status
		}

		// 最后活跃管理员守卫：活跃管理员被降级或禁用时必须仍有其他活跃管理员。
		if current.Role == domain.RoleAdmin && current.Status == domain.UserStatusActive &&
			(nextRole != domain.RoleAdmin || nextStatus != domain.UserStatusActive) {
			count, err := s.users.CountByRoleAndStatus(ctx, domain.RoleAdmin, domain.UserStatusActive)
			if err != nil {
				return err
			}
			if count <= 1 {
				return domain.ErrLastAdmin
			}
		}

		// 邮箱变化默认保留当前验证状态；显式 email_verified 才改变。
		verifiedAt := current.EmailVerifiedAt
		if input.EmailVerified != nil {
			if *input.EmailVerified {
				if verifiedAt == nil {
					now := s.now().UTC().Truncate(time.Microsecond)
					verifiedAt = &now
				}
			} else {
				verifiedAt = nil
			}
		}

		roleStatusChanged = nextRole != current.Role || nextStatus != current.Status

		fields := make(map[string]any)
		if email != current.Email || emailNormalized != current.EmailNormalized {
			fields["email"] = email
			fields["email_normalized"] = emailNormalized
		}
		if nickname != current.Nickname {
			fields["nickname"] = nickname
		}
		if !stringPtrEqual(websiteURL, current.WebsiteURL) {
			fields["website_url"] = websiteURL
		}
		if nextRole != current.Role {
			fields["role"] = nextRole
		}
		if nextStatus != current.Status {
			fields["status"] = nextStatus
		}
		if input.EmailVerified != nil {
			fields["email_verified_at"] = verifiedAt
		}
		if len(fields) == 0 {
			return nil
		}
		return s.users.UpdateAdmin(ctx, targetID, fields)
	})
	if err != nil {
		return nil, err
	}

	// 角色/状态实际变化并提交后，同步删除 authz 缓存，失败按 fail-fast 契约处理。
	if roleStatusChanged {
		if err := s.invalidateAuthz(ctx, targetID); err != nil {
			return nil, err
		}
	}
	return s.getWithPrefs(ctx, targetID)
}

// AdminResetPassword 直接为目标用户设置新密码，不要求旧密码。
// 只替换 Argon2id 密码状态，不改变资料与验证状态；在密码写入的同一事务内
// 递增会话代次，提交后失效 authz 缓存，使目标用户全部既有 JWT 失效。
// 不签发替代会话。
func (s *Service) AdminResetPassword(ctx context.Context, targetID int64, newPassword string) error {
	if len(newPassword) < minPasswordLength {
		return domain.ErrValidation
	}
	var err error
	err = s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		_, err := s.setPassword(ctx, targetID, newPassword)
		return err
	})
	if err != nil {
		return err
	}
	return s.invalidateAuthz(ctx, targetID)
}

// AdminDeleteUser 按 mode 软删除或硬删除目标用户。
// 管理员不能删除自己（ErrForbidden）；不能删除最后一名活跃管理员（ErrLastAdmin）；
// 硬删除需显式确认。软删除把用户改为 deleted 并只软删其本人评论；硬删除先解除
// 保留评论对目标用户评论的引用，再物理删除用户行并级联删除关联评论、passkey、
// 外部身份与通知偏好。提交后同步失效 authz 缓存。
func (s *Service) AdminDeleteUser(ctx context.Context, actingID, targetID int64, mode string, confirm bool) error {
	if actingID == targetID {
		return domain.ErrForbidden
	}
	if mode != domain.UserDeleteModeSoft && mode != domain.UserDeleteModeHard {
		return fmt.Errorf("%w: delete mode must be soft or hard", domain.ErrValidation)
	}
	if mode == domain.UserDeleteModeHard && !confirm {
		return domain.ErrConfirmationRequired
	}
	err := s.runAdminMutation(ctx, func(txCtx context.Context) error {
		target, findErr := s.users.FindByID(txCtx, targetID)
		if findErr != nil {
			return findErr
		}
		var err error
		_, err = s.applyAdminUserDeleteInTx(txCtx, actingID, target, mode, confirm, s.now().UTC().Truncate(time.Microsecond))
		return err
	})
	if err != nil {
		return err
	}
	// 提交后同步失效 authz 缓存，失败按 fail-fast 契约处理。
	return s.invalidateAuthz(ctx, targetID)
}

// AdminRestoreUser 恢复被软删除的用户账号：清除删除标记，回到删除前状态，
// 缺失历史状态时默认 active。恢复只改变账号生命周期，不恢复任何评论。
func (s *Service) AdminRestoreUser(ctx context.Context, targetID int64) (*Profile, error) {
	restored := false
	err := s.txRunner.RunInTx(ctx, func(txCtx context.Context) error {
		current, findErr := s.users.FindByID(txCtx, targetID)
		if findErr != nil {
			return findErr
		}
		var err error
		restored, err = s.restoreAdminUserInTx(txCtx, current)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !restored {
		return nil, domain.ErrConflict
	}
	if err := s.invalidateAuthz(ctx, targetID); err != nil {
		return nil, err
	}
	return s.getWithPrefs(ctx, targetID)
}

// stringPtrEqual 比较两个可空字符串的内容，nil 与 nil 相等、nil 与值不等。
func stringPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

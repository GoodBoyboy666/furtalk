package identity

import (
	"context"
	"strings"

	"furtalk/internal/domain"
)

// 编译期断言：identity.Service 满足 domain 写接口，供 comment/bootstrap 代写用户与偏好。
var (
	_ domain.UserWriter       = (*Service)(nil)
	_ domain.PreferenceWriter = (*Service)(nil)
)

// CreateUser 应用当前邮箱注册策略后创建用户，邮箱冲突时返回 domain.ErrConflict。
func (s *Service) CreateUser(ctx context.Context, user *domain.User) error {
	if user == nil || strings.TrimSpace(user.EmailNormalized) == "" {
		return domain.ErrValidation
	}
	if err := s.checkEmailDomainAllowed(ctx, user.EmailNormalized); err != nil {
		return err
	}
	return s.users.Create(ctx, user)
}

// CreateUserWithPassword 创建用户并随行写入 Argon2id 密码状态。
func (s *Service) CreateUserWithPassword(ctx context.Context, user *domain.User, plaintextPassword string) error {
	hash, err := hashPassword(plaintextPassword)
	if err != nil {
		return err
	}
	return s.users.CreateWithPassword(ctx, user, hash, s.now().UTC())
}

// FindUserByEmailNormalized 按规范化邮箱查找用户。
func (s *Service) FindUserByEmailNormalized(ctx context.Context, normalized string) (*domain.User, error) {
	return s.users.FindByEmailNormalized(ctx, normalized)
}

// UpdateUserProfile 更新昵称与网站。
func (s *Service) UpdateUserProfile(ctx context.Context, id int64, nickname string, websiteURL *string) error {
	return s.users.UpdateProfile(ctx, id, nickname, websiteURL)
}

// UpsertNotificationPreferences 插入或更新通知偏好。
func (s *Service) UpsertNotificationPreferences(ctx context.Context, prefs *domain.NotificationPreferences) error {
	return s.prefs.Upsert(ctx, prefs)
}

// ListActiveAdmins 返回活跃管理员，供通知消费者解析收件人。
func (s *Service) ListActiveAdmins(ctx context.Context) ([]domain.User, error) {
	return s.users.ListActiveAdmins(ctx)
}

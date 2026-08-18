package identity

import (
	"context"

	"furtalk/internal/domain"
)

// 编译期断言：identity.Service 满足 domain 写接口，供 comment/bootstrap 代写用户与偏好。
var (
	_ domain.UserWriter       = (*Service)(nil)
	_ domain.PreferenceWriter = (*Service)(nil)
)

// CreateUser 创建用户，邮箱冲突时返回 domain.ErrConflict。
// 满足 domain.UserWriter，供 bootstrap/comment 经写接口代写用户。
func (s *Service) CreateUser(ctx context.Context, user *domain.User) error {
	return s.users.Create(ctx, user)
}

// CreateUserWithPassword 创建用户并随行写入 Argon2id 密码状态。
// 供 bootstrap 首次初始化调用：哈希策略留在 identity，外层事务同时提交用户与 bootstrap 单例。
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

// GetNotificationPreferences 读取通知偏好。
func (s *Service) GetNotificationPreferences(ctx context.Context, userID int64) (*domain.NotificationPreferences, error) {
	return s.prefs.GetByUserID(ctx, userID)
}

// ListActiveAdmins 返回活跃管理员，供通知消费者解析收件人。
func (s *Service) ListActiveAdmins(ctx context.Context) ([]domain.User, error) {
	return s.users.ListActiveAdmins(ctx)
}

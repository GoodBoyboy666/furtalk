package domain

import "context"

// UserWriter 由 identity.Service 实现，供其他 service 代写用户数据。
type UserWriter interface {
	// CreateUser 由用户所有者校验当前注册策略后创建用户，邮箱冲突时返回 ErrConflict。
	CreateUser(ctx context.Context, user *User) error
	// UpdateUserProfile 更新昵称与网站，用户不存在时返回 ErrNotFound。
	UpdateUserProfile(ctx context.Context, id int64, nickname string, websiteURL *string) error
}

// PreferenceWriter 由 identity.Service 实现，供 notification 代写通知偏好。
type PreferenceWriter interface {
	// UpsertNotificationPreferences 插入或更新通知偏好。
	UpsertNotificationPreferences(ctx context.Context, prefs *NotificationPreferences) error
}

// CommentDeleter 由 comment.Service 实现，供 identity 在删除用户时协调评论清理：
// 软删除用户只处理其本人评论，硬删除前解除保留评论对目标用户评论的引用。
type CommentDeleter interface {
	// SoftDeleteUserComments 软删除用户发表的全部评论，不处理其他用户的回复。
	SoftDeleteUserComments(ctx context.Context, userID int64) error
	// SoftDeleteUsersComments 批量软删除多个用户发表的全部评论，不处理其他用户的回复。
	SoftDeleteUsersComments(ctx context.Context, userIDs []int64) error
	// PrepareUserHardDelete 在物理删除用户前解除保留评论对该用户评论的
	// parent_id / root_id 引用，须与用户行删除在同一事务内提交。
	PrepareUserHardDelete(ctx context.Context, userID int64) error
	// PrepareUsersHardDelete 批量解除保留评论对多个目标用户评论的引用。
	PrepareUsersHardDelete(ctx context.Context, userIDs []int64) error
}

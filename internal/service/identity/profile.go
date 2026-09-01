package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gravatar"
	"furtalk/internal/platform/value"
)

// Profile 返回给 HTTP 适配层的用户数据，不包含凭证机密。
type Profile struct {
	ID            int64
	Email         string
	Nickname      string
	WebsiteURL    *string
	Role          domain.Role
	Status        domain.UserStatus
	EmailVerified bool
	HasPassword   bool
	Preferences   domain.NotificationPreferences
	AvatarURL     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	// DeletedAt 软删除时间，nil 表示账号未被软删除。
	DeletedAt *time.Time
}

// Get 返回用户资料、角色与状态以及通知偏好。
func (s *Service) Get(ctx context.Context, userID int64) (*Profile, error) {
	return s.getWithPrefs(ctx, userID)
}

// UpdateProfile 只修改昵称与网站。
func (s *Service) UpdateProfile(ctx context.Context, userID int64, nickname string, websiteURL *string) (*Profile, error) {
	nickname = strings.TrimSpace(nickname)
	if nickname == "" || len(nickname) > 100 {
		return nil, fmt.Errorf("%w: nickname must be between 1 and 100 characters", domain.ErrValidation)
	}
	if websiteURL != nil {
		normalized, err := value.NormalizeWebsite(*websiteURL)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", domain.ErrValidation, err)
		}
		websiteURL = &normalized
	}
	if err := s.users.UpdateProfile(ctx, userID, nickname, websiteURL); err != nil {
		return nil, err
	}
	return s.getWithPrefs(ctx, userID)
}

// UpdateNotificationPreferences 更新用户的回复与审核邮件通知开关。
func (s *Service) UpdateNotificationPreferences(ctx context.Context, userID int64, replyEnabled, moderationEnabled bool) (domain.NotificationPreferences, error) {
	row := &domain.NotificationPreferences{
		UserID:            userID,
		ReplyEnabled:      replyEnabled,
		ModerationEnabled: moderationEnabled,
	}
	if err := s.prefs.Upsert(ctx, row); err != nil {
		return domain.NotificationPreferences{}, err
	}
	return domain.NotificationPreferences{ReplyEnabled: replyEnabled, ModerationEnabled: moderationEnabled}, nil
}

// List 按搜索词列出用户，供管理端使用。sort 控制 id 排序方向，page 控制页码。
func (s *Service) List(ctx context.Context, search string, sort domain.CommentSort, page, limit int) ([]Profile, error) {
	limit = normalizeUserLimit(limit)
	rows, err := s.users.List(ctx, search, sort, limit, domain.OffsetForPage(page, limit))
	if err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(rows))
	for i := range rows {
		profile, err := s.profileOf(ctx, &rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *profile)
	}
	return out, nil
}

// normalizeUserLimit 把管理端用户列表的每页数量限制在默认 50、上限 100，
// 与 UserRepo.List 的归一化保持一致，使 offset 计算与行数取用对齐。
func normalizeUserLimit(limit int) int {
	if limit <= 0 || limit > 100 {
		return 50
	}
	return limit
}

// ListResult 管理端用户列表及其与搜索条件匹配的总数。
type ListResult struct {
	Users []Profile
	Total int64
}

// ListWithTotal 按搜索词分页列出用户并统计与同一搜索条件匹配的总数，供管理端展示。
func (s *Service) ListWithTotal(ctx context.Context, search string, sort domain.CommentSort, page, limit int) (*ListResult, error) {
	users, err := s.List(ctx, search, sort, page, limit)
	if err != nil {
		return nil, err
	}
	total, err := s.users.Count(ctx, search)
	if err != nil {
		return nil, err
	}
	return &ListResult{Users: users, Total: total}, nil
}

// Create 预创建普通用户或额外的管理员。
func (s *Service) Create(ctx context.Context, email, nickname string, role domain.Role) (*Profile, error) {
	original, normalized, err := value.NormalizeEmail(email)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	if role != domain.RoleUser && role != domain.RoleAdmin {
		return nil, fmt.Errorf("%w: role must be user or admin", domain.ErrValidation)
	}
	nickname = strings.TrimSpace(nickname)
	if nickname == "" || len(nickname) > 100 {
		return nil, fmt.Errorf("%w: nickname must be between 1 and 100 characters", domain.ErrValidation)
	}
	user := &domain.User{
		Email:           original,
		EmailNormalized: normalized,
		Nickname:        nickname,
		Role:            role,
		Status:          domain.UserStatusActive,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	return s.getWithPrefs(ctx, user.ID)
}

// UpdateRoleStatus 修改用户的角色或状态，保护最后一名活跃管理员，并在提交后同步失效 authz 缓存。
func (s *Service) UpdateRoleStatus(ctx context.Context, targetID int64, role *domain.Role, status *domain.UserStatus) (*Profile, error) {
	return s.AdminUpdateUser(ctx, targetID, AdminUpdateUserInput{Role: role, Status: status})
}

func (s *Service) getWithPrefs(ctx context.Context, userID int64) (*Profile, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.profileOf(ctx, user)
}

func (s *Service) profileOf(ctx context.Context, user *domain.User) (*Profile, error) {
	prefs := domain.NotificationPreferences{ReplyEnabled: true, ModerationEnabled: true}
	if row, err := s.prefs.GetByUserID(ctx, user.ID); err == nil {
		prefs = domain.NotificationPreferences{ReplyEnabled: row.ReplyEnabled, ModerationEnabled: row.ModerationEnabled}
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	hasPassword, err := s.users.HasPassword(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	_, _, gravatarBase, err := s.policy.EmailPolicy(ctx)
	if err != nil {
		return nil, err
	}
	return &Profile{
		ID:            user.ID,
		Email:         user.Email,
		Nickname:      user.Nickname,
		WebsiteURL:    user.WebsiteURL,
		Role:          user.Role,
		Status:        user.Status,
		EmailVerified: user.EmailVerifiedAt != nil,
		HasPassword:   hasPassword,
		Preferences:   prefs,
		AvatarURL:     gravatar.URL(user.EmailNormalized, gravatarBase),
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		DeletedAt:     user.DeletedAt,
	}, nil
}

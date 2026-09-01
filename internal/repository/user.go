// Package repository 是唯一访问 GORM 的数据访问层。
// 本层负责 row ↔ domain 的防腐转换，service 只消费 domain 类型。
// repository 是 gorm 边界：任何包都不得绕过本层直接触碰 GORM。
package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserRepo 持久化 users 行。
type UserRepo struct {
	db *gorm.DB
}

// NewUserRepo 构建用户仓储。
func NewUserRepo(db *gorm.DB) *UserRepo {
	return &UserRepo{db: db}
}

// Create 插入用户行，并把生成的 ID 与时间戳回填到业务数据；邮箱冲突返回 domain.ErrConflict。
func (r *UserRepo) Create(ctx context.Context, user *domain.User) error {
	row := fromUser(user)
	if err := gormtx.DB(ctx, r.db).Create(row).Error; err != nil {
		if gormtx.IsDuplicateKeyError(err) {
			return fmt.Errorf("create user: %w", domain.ErrConflict)
		}
		return fmt.Errorf("create user: %w", err)
	}
	user.ID = row.ID
	user.CreatedAt = row.CreatedAt
	user.UpdatedAt = row.UpdatedAt
	user.SessionVersion = row.SessionVersion
	return nil
}

// FindByEmailNormalized 按规范化邮箱查询用户；不存在时返回 domain.ErrNotFound。
func (r *UserRepo) FindByEmailNormalized(ctx context.Context, normalized string) (*domain.User, error) {
	var row model.User
	err := gormtx.DB(ctx, r.db).
		Where("email_normalized = ?", normalized).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	user := row.ToUser()
	return &user, nil
}

// FindByID 按主键返回一个用户。
func (r *UserRepo) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	return r.findByID(ctx, id, false)
}

// FindByIDLocked 在写事务内按主键读取用户，并在支持的方言上锁定用户行。
// SQLite 不支持 FOR UPDATE，沿用事务的单写者与忙等待语义。
func (r *UserRepo) FindByIDLocked(ctx context.Context, id int64) (*domain.User, error) {
	return r.findByID(ctx, id, true)
}

// List 按 id 顺序返回用户，可用匹配规范化邮箱或昵称的搜索词收窄结果。
// sort 控制 id 排序方向：asc 表示最早的账号优先，desc 表示最新优先（缺省值）。
// offset 允许按页跳过已返回的行；Count 使用同一搜索词统计总数。
func (r *UserRepo) List(ctx context.Context, search string, sort domain.CommentSort, limit, offset int) ([]domain.User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if sort == "" {
		sort = domain.CommentSortDesc
	}
	order := "id ASC"
	if sort == domain.CommentSortDesc {
		order = "id DESC"
	}
	query := gormtx.DB(ctx, r.db).Order(order)
	if search = strings.TrimSpace(search); search != "" {
		like := "%" + search + "%"
		query = query.Where("email_normalized LIKE ? OR nickname LIKE ?", like, like)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}
	var rows []model.User
	if err := query.Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	out := make([]domain.User, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ToUser())
	}
	return out, nil
}

// UpdateProfile 只更新昵称与网站字段。
func (r *UserRepo) UpdateProfile(ctx context.Context, id int64, nickname string, websiteURL *string) error {
	result := gormtx.DB(ctx, r.db).
		Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"nickname":    nickname,
			"website_url": websiteURL,
		})
	if result.Error != nil {
		return fmt.Errorf("update user profile: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// UpdateRoleStatus 只更新角色与状态字段。
// 使用方必须强制"最后活跃管理员"守卫并同步失效 authz 缓存。
func (r *UserRepo) UpdateRoleStatus(ctx context.Context, id int64, role domain.Role, status domain.UserStatus) error {
	result := gormtx.DB(ctx, r.db).
		Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"role":   role,
			"status": status,
		})
	if result.Error != nil {
		return fmt.Errorf("update user role/status: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// UpdateAdmin 合并写入管理端用户更新字段（邮箱/昵称/网站/角色/状态/验证时间）。
// 更新前先确认用户行存在，因为 SQLite 只统计实际变更行，缺失行会造出假 not-found；
// 唯一约束（email_normalized）冲突映射为 domain.ErrConflict。
func (r *UserRepo) UpdateAdmin(ctx context.Context, id int64, fields map[string]any) error {
	var row model.User
	err := gormtx.DB(ctx, r.db).Where("id = ?", id).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("find user for admin update: %w", err)
	}
	result := gormtx.DB(ctx, r.db).
		Model(&model.User{}).
		Where("id = ?", id).
		Updates(fields)
	if result.Error != nil {
		if gormtx.IsDuplicateKeyError(result.Error) {
			return fmt.Errorf("admin update user: %w", domain.ErrConflict)
		}
		return fmt.Errorf("admin update user: %w", result.Error)
	}
	return nil
}

// CountByRoleAndStatus 精确统计匹配某角色与状态的用户数，支撑"最后活跃管理员"守卫。
func (r *UserRepo) CountByRoleAndStatus(ctx context.Context, role domain.Role, status domain.UserStatus) (int64, error) {
	var count int64
	err := gormtx.DB(ctx, r.db).
		Model(&model.User{}).
		Where("role = ? AND status = ?", role, status).
		Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("count users by role and status: %w", err)
	}
	return count, nil
}

// LockActiveAdmins 在写事务内按稳定 id 顺序锁定全部活跃管理员并返回行数。
// PostgreSQL 使用 FOR UPDATE；SQLite 不支持该子句，沿用事务的写者锁语义。
func (r *UserRepo) LockActiveAdmins(ctx context.Context) (int64, error) {
	db := gormtx.DB(ctx, r.db).Model(&model.User{}).Select("id")
	if db.Dialector.Name() != "sqlite" {
		db = db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var rows []struct {
		ID int64
	}
	if err := db.Where("role = ? AND status = ?", domain.RoleAdmin, domain.UserStatusActive).
		Order("id").Find(&rows).Error; err != nil {
		return 0, fmt.Errorf("lock active administrators: %w", err)
	}
	return int64(len(rows)), nil
}

// Count 按与 List 相同的搜索词统计匹配用户总数，与分页 limit 无关。
func (r *UserRepo) Count(ctx context.Context, search string) (int64, error) {
	query := gormtx.DB(ctx, r.db).Model(&model.User{})
	if search = strings.TrimSpace(search); search != "" {
		like := "%" + search + "%"
		query = query.Where("email_normalized LIKE ? OR nickname LIKE ?", like, like)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

// SoftDelete 软删除用户：记录删除时间与删除前的账户状态。
// 更新前先确认用户行存在，因为 SQLite 只统计实际变更行，缺失行会造出假 not-found。
func (r *UserRepo) SoftDelete(ctx context.Context, id int64, statusBefore domain.UserStatus, deletedAt time.Time) error {
	var row model.User
	err := gormtx.DB(ctx, r.db).Where("id = ?", id).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("find user for soft delete: %w", err)
	}
	result := gormtx.DB(ctx, r.db).
		Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":               domain.UserStatusDeleted,
			"status_before_delete": statusBefore,
			"deleted_at":           deletedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("soft delete user: %w", result.Error)
	}
	return nil
}

// Restore 恢复软删除的用户：回到删除前状态（缺失时默认 active），清除删除标记。
// 只恢复账号本身，不触碰任何评论。
func (r *UserRepo) Restore(ctx context.Context, id int64) error {
	var row model.User
	err := gormtx.DB(ctx, r.db).Where("id = ?", id).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("find user for restore: %w", err)
	}
	status := domain.UserStatusActive
	if row.StatusBeforeDelete != nil && (*row.StatusBeforeDelete == domain.UserStatusActive || *row.StatusBeforeDelete == domain.UserStatusDisabled) {
		status = *row.StatusBeforeDelete
	}
	result := gormtx.DB(ctx, r.db).
		Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":               status,
			"status_before_delete": nil,
			"deleted_at":           nil,
		})
	if result.Error != nil {
		return fmt.Errorf("restore user: %w", result.Error)
	}
	return nil
}

// Delete 物理删除用户行；passkey、外部身份、通知偏好与该用户本人的评论
// 经外键级联删除，其他用户对其评论的回复在调用方解除引用后保留。
func (r *UserRepo) Delete(ctx context.Context, id int64) error {
	result := gormtx.DB(ctx, r.db).Where("id = ?", id).Delete(&model.User{})
	if result.Error != nil {
		return fmt.Errorf("delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// ListActiveAdmins 按 id 顺序返回活跃的管理员用户。
func (r *UserRepo) ListActiveAdmins(ctx context.Context) ([]domain.User, error) {
	var rows []model.User
	err := gormtx.DB(ctx, r.db).
		Where("role = ? AND status = ?", domain.RoleAdmin, domain.UserStatusActive).
		Order("id").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list active admins: %w", err)
	}
	out := make([]domain.User, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ToUser())
	}
	return out, nil
}

// CreateWithPassword 插入用户行，并把密码哈希与变更时间随行写入。
// 与 Create 一样回填生成的 ID 与时间戳；邮箱冲突返回 domain.ErrConflict。
func (r *UserRepo) CreateWithPassword(ctx context.Context, user *domain.User, passwordHash string, changedAt time.Time) error {
	row := fromUser(user)
	hash := passwordHash
	row.PasswordHash = &hash
	row.PasswordChangedAt = &changedAt
	if err := gormtx.DB(ctx, r.db).Create(row).Error; err != nil {
		if gormtx.IsDuplicateKeyError(err) {
			return fmt.Errorf("create user with password: %w", domain.ErrConflict)
		}
		return fmt.Errorf("create user with password: %w", err)
	}
	user.ID = row.ID
	user.CreatedAt = row.CreatedAt
	user.UpdatedAt = row.UpdatedAt
	user.SessionVersion = row.SessionVersion
	return nil
}

// SetPassword 同时更新用户的密码哈希、变更时间并递增会话代次，返回递增后的
// 新代次。会话代次由数据库表达式原子递增，并从同一条 UPDATE 的 RETURNING
// 结果读取，避免并发事务丢失递增。调用方应在数据库事务内执行。
func (r *UserRepo) SetPassword(ctx context.Context, userID int64, passwordHash string, changedAt time.Time) (int64, error) {
	var row model.User
	result := gormtx.DB(ctx, r.db).
		Model(&row).
		Clauses(clause.Returning{Columns: []clause.Column{{Name: "session_version"}}}).
		Where("id = ?", userID).
		Updates(map[string]any{
			"password_hash":       passwordHash,
			"password_changed_at": changedAt,
			"session_version":     gorm.Expr("session_version + ?", 1),
		})
	if result.Error != nil {
		return 0, fmt.Errorf("set user password: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return 0, domain.ErrNotFound
	}
	return row.SessionVersion, nil
}

// BumpSessionVersion 只递增用户会话代次并返回新代次，用于主动注销全部设备。
// 会话代次由数据库表达式原子递增，并从同一条 UPDATE 的 RETURNING 结果读取，
// 避免并发事务丢失递增。调用方应在数据库事务内执行。
func (r *UserRepo) BumpSessionVersion(ctx context.Context, userID int64) (int64, error) {
	var row model.User
	result := gormtx.DB(ctx, r.db).
		Model(&row).
		Clauses(clause.Returning{Columns: []clause.Column{{Name: "session_version"}}}).
		Where("id = ?", userID).
		Updates(map[string]any{"session_version": gorm.Expr("session_version + ?", 1)})
	if result.Error != nil {
		return 0, fmt.Errorf("bump user session version: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return 0, domain.ErrNotFound
	}
	return row.SessionVersion, nil
}

// PasswordHash 返回用户用于认证的密码哈希；未配置密码或用户不存在时返回 domain.ErrNotFound。
func (r *UserRepo) PasswordHash(ctx context.Context, userID int64) (string, error) {
	var row model.User
	err := gormtx.DB(ctx, r.db).Where("id = ?", userID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", domain.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("find user for password hash: %w", err)
	}
	if row.PasswordHash == nil {
		return "", domain.ErrNotFound
	}
	return *row.PasswordHash, nil
}

// ResetPasswordByEmail 在单个语句中更新密码哈希、变更时间与会话代次，并只在
// 邮箱未验证时写入验证时间；已验证邮箱保留原验证时间。会话代次由数据库表达式
// 原子递增，并与目标用户 id 一起从同一条 UPDATE 的 RETURNING 结果读取。调用方
// 应在数据库事务内执行。
func (r *UserRepo) ResetPasswordByEmail(ctx context.Context, normalizedEmail, passwordHash string, changedAt, verifiedAt time.Time) (int64, int64, error) {
	var row model.User
	result := gormtx.DB(ctx, r.db).
		Model(&row).
		Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}, {Name: "session_version"}}}).
		Where("email_normalized = ?", normalizedEmail).
		Updates(map[string]any{
			"password_hash":       passwordHash,
			"password_changed_at": changedAt,
			"session_version":     gorm.Expr("session_version + ?", 1),
			"email_verified_at":   gorm.Expr("COALESCE(email_verified_at, ?)", verifiedAt),
		})
	if result.Error != nil {
		return 0, 0, fmt.Errorf("reset user password: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return 0, 0, domain.ErrNotFound
	}
	return row.ID, row.SessionVersion, nil
}

// MarkEmailVerified 幂等地把用户标记为邮箱已验证：只在邮箱尚未验证时写入
// verifiedAt，已验证用户保留原验证时间，不覆盖。返回是否实际写入了验证时间。
// 更新前先确认用户行存在，因为 SQLite 只统计实际变更行，缺失行会造出假
// not-found。
func (r *UserRepo) MarkEmailVerified(ctx context.Context, userID int64, verifiedAt time.Time) (bool, error) {
	var row model.User
	err := gormtx.DB(ctx, r.db).Where("id = ?", userID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, domain.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("find user for email verification: %w", err)
	}
	if row.EmailVerifiedAt != nil {
		return false, nil
	}
	result := gormtx.DB(ctx, r.db).
		Model(&model.User{}).
		Where("id = ?", userID).
		Update("email_verified_at", verifiedAt)
	if result.Error != nil {
		return false, fmt.Errorf("mark email verified: %w", result.Error)
	}
	return true, nil
}

// HasPassword 报告用户是否配置了密码登录，不返回哈希本身。
func (r *UserRepo) HasPassword(ctx context.Context, userID int64) (bool, error) {
	var row model.User
	err := gormtx.DB(ctx, r.db).Where("id = ?", userID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, domain.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("find user for password state: %w", err)
	}
	return row.PasswordHash != nil, nil
}

// findByID 按主键读取用户，可选地在 PostgreSQL 上锁定目标行。
func (r *UserRepo) findByID(ctx context.Context, id int64, locked bool) (*domain.User, error) {
	db := gormtx.DB(ctx, r.db)
	if locked && db.Dialector.Name() != "sqlite" {
		db = db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var row model.User
	err := db.
		Where("id = ?", id).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	user := row.ToUser()
	return &user, nil
}

// fromUser 把业务用户转为持久化行。
func fromUser(u *domain.User) *model.User {
	if u == nil {
		return nil
	}
	return &model.User{
		ID:                 u.ID,
		Email:              u.Email,
		EmailNormalized:    u.EmailNormalized,
		Nickname:           u.Nickname,
		WebsiteURL:         u.WebsiteURL,
		Role:               u.Role,
		Status:             u.Status,
		SessionVersion:     u.SessionVersion,
		EmailVerifiedAt:    u.EmailVerifiedAt,
		DeletedAt:          u.DeletedAt,
		StatusBeforeDelete: u.StatusBeforeDelete,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
}

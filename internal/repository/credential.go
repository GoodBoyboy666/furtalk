package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PasskeyRepo 持久化 passkey_credentials 行。
type PasskeyRepo struct {
	db *gorm.DB
}

// NewPasskeyRepo 构建 passkey 凭证仓储。
func NewPasskeyRepo(db *gorm.DB) *PasskeyRepo {
	return &PasskeyRepo{db: db}
}

// Create 插入一条 passkey 凭据；重复的 credential_id 报告为 domain.ErrConflict。
func (r *PasskeyRepo) Create(ctx context.Context, row *domain.PasskeyCredential) error {
	if err := gormtx.DB(ctx, r.db).Create(fromPasskeyCredential(row)).Error; err != nil {
		if gormtx.IsDuplicateKeyError(err) {
			return fmt.Errorf("create passkey credential: %w", domain.ErrConflict)
		}
		return fmt.Errorf("create passkey credential: %w", err)
	}
	return nil
}

// GetByUserIDAndID 返回属于该用户的一条 passkey 凭据。
func (r *PasskeyRepo) GetByUserIDAndID(ctx context.Context, userID, id int64) (*domain.PasskeyCredential, error) {
	var row model.PasskeyCredential
	err := gormtx.DB(ctx, r.db).
		Where("user_id = ? AND id = ?", userID, id).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get passkey credential: %w", err)
	}
	out := row.ToPasskeyCredential()
	return &out, nil
}

// GetByCredentialID 按全局唯一的 credential ID 返回 passkey 凭据。
func (r *PasskeyRepo) GetByCredentialID(ctx context.Context, credentialID string) (*domain.PasskeyCredential, error) {
	var row model.PasskeyCredential
	err := gormtx.DB(ctx, r.db).
		Where("credential_id = ?", credentialID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get passkey credential by id: %w", err)
	}
	out := row.ToPasskeyCredential()
	return &out, nil
}

// ListByUserID 按 id 顺序返回某个用户的全部 passkey 凭据。
func (r *PasskeyRepo) ListByUserID(ctx context.Context, userID int64) ([]domain.PasskeyCredential, error) {
	var rows []model.PasskeyCredential
	if err := gormtx.DB(ctx, r.db).
		Where("user_id = ?", userID).
		Order("id").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list passkey credentials: %w", err)
	}
	out := make([]domain.PasskeyCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ToPasskeyCredential())
	}
	return out, nil
}

// CountByUserID 返回某个用户的 passkey 凭据数量。
func (r *PasskeyRepo) CountByUserID(ctx context.Context, userID int64) (int64, error) {
	var count int64
	err := gormtx.DB(ctx, r.db).
		Model(&model.PasskeyCredential{}).
		Where("user_id = ?", userID).
		Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("count passkey credentials: %w", err)
	}
	return count, nil
}

// DeleteByUserAndID 删除属于该用户的一条 passkey 凭据。
func (r *PasskeyRepo) DeleteByUserAndID(ctx context.Context, userID, id int64) error {
	err := gormtx.DB(ctx, r.db).
		Where("user_id = ? AND id = ?", userID, id).
		Delete(&model.PasskeyCredential{}).Error
	if err != nil {
		return fmt.Errorf("delete passkey credential: %w", err)
	}
	return nil
}

// RenameByUserAndID 更新属于该用户的一条 passkey 凭据名称；未命中返回 domain.ErrNotFound。
func (r *PasskeyRepo) RenameByUserAndID(ctx context.Context, userID, id int64, name string) error {
	result := gormtx.DB(ctx, r.db).
		Model(&model.PasskeyCredential{}).
		Where("user_id = ? AND id = ?", userID, id).
		Update("name", name)
	if result.Error != nil {
		return fmt.Errorf("rename passkey credential: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// UpdateLoginState 在断言成功后刷新签名计数器、备份状态与最后使用时间戳。
func (r *PasskeyRepo) UpdateLoginState(ctx context.Context, id int64, signCount uint32, backupState bool, lastUsedAt time.Time) error {
	result := gormtx.DB(ctx, r.db).
		Model(&model.PasskeyCredential{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"sign_count":   signCount,
			"backup_state": backupState,
			"last_used_at": lastUsedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("update passkey login state: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// ExternalIdentityRepo 持久化 external_identities 行。
type ExternalIdentityRepo struct {
	db *gorm.DB
}

// NewExternalIdentityRepo 构建外部身份仓储。
func NewExternalIdentityRepo(db *gorm.DB) *ExternalIdentityRepo {
	return &ExternalIdentityRepo{db: db}
}

// Create 绑定一个外部身份。
func (r *ExternalIdentityRepo) Create(ctx context.Context, row *domain.ExternalIdentity) error {
	if err := gormtx.DB(ctx, r.db).Create(fromExternalIdentity(row)).Error; err != nil {
		if gormtx.IsDuplicateKeyError(err) {
			return fmt.Errorf("create external identity: %w", domain.ErrConflict)
		}
		return fmt.Errorf("create external identity: %w", err)
	}
	return nil
}

// GetByProviderSubject 返回绑定到某个 provider subject 的身份。
func (r *ExternalIdentityRepo) GetByProviderSubject(ctx context.Context, providerKey, subject string) (*domain.ExternalIdentity, error) {
	var row model.ExternalIdentity
	err := gormtx.DB(ctx, r.db).
		Where("provider_key = ? AND provider_subject = ?", providerKey, subject).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get external identity by subject: %w", err)
	}
	out := row.ToExternalIdentity()
	return &out, nil
}

// GetByUserIDAndID 返回属于该用户的身份。
func (r *ExternalIdentityRepo) GetByUserIDAndID(ctx context.Context, userID, id int64) (*domain.ExternalIdentity, error) {
	var row model.ExternalIdentity
	err := gormtx.DB(ctx, r.db).
		Where("user_id = ? AND id = ?", userID, id).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get external identity: %w", err)
	}
	out := row.ToExternalIdentity()
	return &out, nil
}

// ListByUserID 按 id 顺序返回某个用户的全部外部身份。
func (r *ExternalIdentityRepo) ListByUserID(ctx context.Context, userID int64) ([]domain.ExternalIdentity, error) {
	var rows []model.ExternalIdentity
	if err := gormtx.DB(ctx, r.db).
		Where("user_id = ?", userID).
		Order("id").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list external identities: %w", err)
	}
	out := make([]domain.ExternalIdentity, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ToExternalIdentity())
	}
	return out, nil
}

// CountByUserID 返回某个用户的外部身份数量。
func (r *ExternalIdentityRepo) CountByUserID(ctx context.Context, userID int64) (int64, error) {
	var count int64
	err := gormtx.DB(ctx, r.db).
		Model(&model.ExternalIdentity{}).
		Where("user_id = ?", userID).
		Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("count external identities: %w", err)
	}
	return count, nil
}

// DeleteByUserAndID 删除属于该用户的一个身份。
func (r *ExternalIdentityRepo) DeleteByUserAndID(ctx context.Context, userID, id int64) error {
	if err := gormtx.DB(ctx, r.db).
		Where("user_id = ? AND id = ?", userID, id).
		Delete(&model.ExternalIdentity{}).Error; err != nil {
		return fmt.Errorf("delete external identity: %w", err)
	}
	return nil
}

// TouchLastLogin 在 provider 登录成功后刷新 last_login_at 时间戳。
func (r *ExternalIdentityRepo) TouchLastLogin(ctx context.Context, id int64, at time.Time) error {
	result := gormtx.DB(ctx, r.db).
		Model(&model.ExternalIdentity{}).
		Where("id = ?", id).
		Update("last_login_at", at)
	if result.Error != nil {
		return fmt.Errorf("touch external identity last login: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// PreferenceRepo 持久化 notification_preferences 行。
type PreferenceRepo struct {
	db *gorm.DB
}

// NewPreferenceRepo 构建通知偏好仓储。
func NewPreferenceRepo(db *gorm.DB) *PreferenceRepo {
	return &PreferenceRepo{db: db}
}

// Upsert 插入通知偏好，或在 user_id 冲突时原地更新回复与审核开关。
func (r *PreferenceRepo) Upsert(ctx context.Context, row *domain.NotificationPreferences) error {
	err := gormtx.DB(ctx, r.db).
		Model(&model.NotificationPreferences{}).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"reply_enabled", "moderation_enabled", "updated_at"}),
		}).
		Create(map[string]any{
			"user_id":            row.UserID,
			"reply_enabled":      row.ReplyEnabled,
			"moderation_enabled": row.ModerationEnabled,
			"updated_at":         time.Now().UTC(),
		}).Error
	if err != nil {
		return fmt.Errorf("upsert notification preferences: %w", err)
	}
	return nil
}

// GetByUserID 返回某个用户的通知偏好。
func (r *PreferenceRepo) GetByUserID(ctx context.Context, userID int64) (*domain.NotificationPreferences, error) {
	var row model.NotificationPreferences
	err := gormtx.DB(ctx, r.db).
		Where("user_id = ?", userID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get notification preferences: %w", err)
	}
	out := row.ToNotificationPreferences()
	return &out, nil
}

// fromPasskeyCredential 把业务 passkey 凭证转为持久化行。
func fromPasskeyCredential(r *domain.PasskeyCredential) *model.PasskeyCredential {
	if r == nil {
		return nil
	}
	return &model.PasskeyCredential{
		ID:              r.ID,
		UserID:          r.UserID,
		CredentialID:    r.CredentialID,
		PublicKey:       r.PublicKey,
		AttestationType: r.AttestationType,
		Transports:      r.Transports,
		SignCount:       r.SignCount,
		BackupEligible:  r.BackupEligible,
		BackupState:     r.BackupState,
		Name:            r.Name,
		CreatedAt:       r.CreatedAt,
		LastUsedAt:      r.LastUsedAt,
	}
}

// fromExternalIdentity 把业务外部身份转为持久化行。
func fromExternalIdentity(r *domain.ExternalIdentity) *model.ExternalIdentity {
	if r == nil {
		return nil
	}
	return &model.ExternalIdentity{
		ID:              r.ID,
		UserID:          r.UserID,
		ProviderKey:     r.ProviderKey,
		ProviderSubject: r.ProviderSubject,
		VerifiedEmail:   r.VerifiedEmail,
		CreatedAt:       r.CreatedAt,
		LastLoginAt:     r.LastLoginAt,
	}
}

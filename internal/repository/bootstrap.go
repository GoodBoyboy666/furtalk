package repository

import (
	"context"
	"fmt"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

type BootstrapRepo struct {
	db *gorm.DB
}

// NewBootstrapRepo 构建 bootstrap repository。
func NewBootstrapRepo(db *gorm.DB) *BootstrapRepo {
	return &BootstrapRepo{db: db}
}

// IsInitialized 报告 bootstrap 单例行是否已存在。
func (r *BootstrapRepo) IsInitialized(ctx context.Context) (bool, error) {
	var count int64
	err := gormtx.DB(ctx, r.db).
		Model(&model.BootstrapState{}).
		Where("singleton_key = ?", 1).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("count bootstrap state: %w", err)
	}
	return count > 0, nil
}

// Create 插入 bootstrap 单例。
// 重复的 singleton_key 冲突报告为 domain.ErrConflict。
func (r *BootstrapRepo) Create(ctx context.Context, initializedAt time.Time, adminUserID int64) error {
	state := &model.BootstrapState{
		SingletonKey:  1,
		InitializedAt: initializedAt,
		AdminUserID:   adminUserID,
	}
	if err := gormtx.DB(ctx, r.db).Create(state).Error; err != nil {
		if gormtx.IsDuplicateKeyError(err) {
			return fmt.Errorf("create bootstrap state: %w", domain.ErrConflict)
		}
		return fmt.Errorf("create bootstrap state: %w", err)
	}
	return nil
}

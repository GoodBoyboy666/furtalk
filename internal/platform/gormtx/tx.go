// Package gormtx 提供跨各 feature 的 repo 包共享的事务运行器与事务句柄解析。
// GORM 事务传播的唯一实现：各 feature 的 repo 包通过 gormtx.DB
// 解析当前事务句柄，使同一事务在任意仓储之间共享。
package gormtx

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// txKey 是挂载事务句柄的私有上下文键。
// 私有类型限制上下文键的作用域，并隔离其他包的键。
type txKey struct{}

// Runner 隐式满足各 feature 自有的事务接口。
type Runner struct {
	db *gorm.DB
}

// NewRunner 构建基于 *gorm.DB 的事务运行器。
func NewRunner(db *gorm.DB) *Runner {
	return &Runner{db: db}
}

// RunInTx 在单个数据库事务内运行 fn。
func (r *Runner) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(*gorm.DB); ok {
		return fn(ctx)
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(context.WithValue(ctx, txKey{}, tx))
	})
}

// DB 返回 ctx 中的事务句柄；无事务时返回绑定 ctx 的默认 DB。
func DB(ctx context.Context, defaultDB *gorm.DB) *gorm.DB {
	if tx, ok := ctx.Value(txKey{}).(*gorm.DB); ok {
		return tx
	}
	return defaultDB.WithContext(ctx)
}

// IsDuplicateKeyError 报告被包装的 GORM 错误是否为唯一或主键约束违规。
func IsDuplicateKeyError(err error) bool {
	msg := strings.ToLower(fmt.Sprint(err))
	return strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique") ||
		strings.Contains(msg, "unique constraint") || strings.Contains(msg, "conflict")
}

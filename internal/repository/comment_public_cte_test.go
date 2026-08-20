package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// publicSQLCapture 记录 GORM 在 DryRun 下交给 PostgreSQL 方言的最终 SQL。
// 测试使用 PostgreSQL 方言但不需要连接真实 PostgreSQL 服务。
type publicSQLCapture struct {
	logger.Interface
	sql string
}

func (l *publicSQLCapture) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	l.sql, _ = fc()
}

// TestCommentRepoListPublicPostgresCteAnchorTypes 防止递归 CTE 锚点重新使用无类型 NULL。
// PostgreSQL 会先根据锚点确定递归列类型；vis_parent_id/vis_root_id 必须与递归步进中的
// bigint 评论 id 一致，否则公开评论查询会在规划阶段失败（SQLSTATE 42804）。
func TestCommentRepoListPublicPostgresCteAnchorTypes(t *testing.T) {
	sqliteDB := newSortTestDB(t)
	sqlDB, err := sqliteDB.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}

	capture := &publicSQLCapture{Interface: logger.Default}
	postgresDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn:                 sqlDB,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		DryRun: true,
		Logger: capture,
	})
	if err != nil {
		t.Fatalf("init postgres dry run db: %v", err)
	}

	// DryRun intentionally does not execute against the SQLite connection. The generated
	// SQL is still passed through GORM's PostgreSQL dialect and captured by the logger.
	_, _ = NewCommentRepo(postgresDB).ListPublic(
		context.Background(), 1, 1, domain.CommentSortAsc, nil, 1,
	)
	if capture.sql == "" {
		t.Fatal("expected ListPublic to generate PostgreSQL SQL")
	}
	for _, column := range []string{"vis_parent_id", "vis_root_id"} {
		cast := "CAST(NULL AS BIGINT) AS " + column
		if strings.Count(capture.sql, cast) != 1 {
			t.Fatalf("PostgreSQL CTE anchor must contain exactly one %q, SQL: %s", cast, capture.sql)
		}
		if strings.Contains(capture.sql, "NULL AS "+column) {
			t.Fatalf("PostgreSQL CTE anchor contains untyped NULL for %s, SQL: %s", column, capture.sql)
		}
	}
}

package comment

import (
	"context"
	"errors"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
	"gorm.io/gorm"
)

// createTrendComment 插入指定创建时间与状态的趋势测试评论。
func createTrendComment(t *testing.T, db *gorm.DB, siteID, threadID, userID int64, createdAt time.Time, status domain.CommentStatus) int64 {
	t.Helper()
	comment := &domain.Comment{
		SiteID: siteID, ThreadID: threadID, UserID: userID, Depth: 0,
		BodyMarkdown: "trend-" + string(status), Status: status,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	if status == domain.CommentStatusPublished {
		comment.PublishedAt = &createdAt
	}
	if status == domain.CommentStatusDeleted {
		comment.DeletedAt = &createdAt
		before := domain.CommentStatusPublished
		comment.StatusBeforeDelete = &before
	}
	if err := repository.NewCommentRepo(db).Create(context.Background(), comment); err != nil {
		t.Fatalf("create trend comment: %v", err)
	}
	return comment.ID
}

// TestAdminCommentTrendCountsStatesAndFillsZeros 验证趋势按 created_at 统计全部状态，
// 软删除仍计入，硬删除行不计入，并且缺失日期补零。
func TestAdminCommentTrendCountsStatesAndFillsZeros(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	svc.now = func() time.Time {
		return time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	}

	trend, err := svc.AdminCommentTrend(context.Background(), 7, "Asia/Shanghai")
	if err != nil {
		t.Fatalf("trend: %v", err)
	}
	if len(trend.Points) != 7 || trend.Points[0].Date != "2026-08-02" || trend.Points[6].Date != "2026-08-08" {
		t.Fatalf("trend points = %+v, want 7 ascending local dates", trend.Points)
	}
	if trend.Points[6].Count != 5 {
		t.Fatalf("existing four states plus other = %d, want 5", trend.Points[6].Count)
	}
	for _, point := range trend.Points[:6] {
		if point.Count != 0 {
			t.Fatalf("zero bucket %s = %d, want 0", point.Date, point.Count)
		}
	}

	hardDeleted := createTrendComment(t, db, fx.SiteID, mustTrendThread(t, db, fx.SiteID), fx.OwnerID,
		time.Date(2026, time.August, 8, 14, 0, 0, 0, time.UTC), domain.CommentStatusPublished)
	if err := repository.NewCommentRepo(db).HardDelete(context.Background(), fx.SiteID, hardDeleted); err != nil {
		t.Fatalf("hard delete trend comment: %v", err)
	}
	trend, err = svc.AdminCommentTrend(context.Background(), 7, "Asia/Shanghai")
	if err != nil {
		t.Fatalf("trend after hard delete: %v", err)
	}
	if trend.Points[6].Count != 5 {
		t.Fatalf("hard-deleted row was counted: %d", trend.Points[6].Count)
	}
}

// TestAdminCommentTrendHandlesDSTAndValidation 验证夏令时切换仍以当地午夜分桶，
// 且服务只接受 7/30 天与有效 IANA 时区。
func TestAdminCommentTrendHandlesDSTAndValidation(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedOwnerComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	svc.now = func() time.Time {
		return time.Date(2026, time.March, 8, 15, 0, 0, 0, time.UTC)
	}
	threadID := mustTrendThread(t, db, fx.SiteID)
	createTrendComment(t, db, fx.SiteID, threadID, fx.OwnerID,
		time.Date(2026, time.March, 8, 6, 0, 0, 0, time.UTC), domain.CommentStatusPublished)
	createTrendComment(t, db, fx.SiteID, threadID, fx.OwnerID,
		time.Date(2026, time.March, 8, 4, 59, 0, 0, time.UTC), domain.CommentStatusPending)

	trend, err := svc.AdminCommentTrend(context.Background(), 7, "America/New_York")
	if err != nil {
		t.Fatalf("DST trend: %v", err)
	}
	if trend.Points[6].Date != "2026-03-08" || trend.Points[6].Count != 1 {
		t.Fatalf("DST day = %+v, want one comment after local midnight", trend.Points[6])
	}
	if trend.Points[5].Date != "2026-03-07" || trend.Points[5].Count != 1 {
		t.Fatalf("pre-DST day = %+v, want one comment before local midnight", trend.Points[5])
	}
	trend30, err := svc.AdminCommentTrend(context.Background(), 30, "America/New_York")
	if err != nil {
		t.Fatalf("30-day trend: %v", err)
	}
	if len(trend30.Points) != 30 || trend30.Days != 30 {
		t.Fatalf("30-day trend points = %d, days = %d; want 30/30", len(trend30.Points), trend30.Days)
	}
	if _, err := svc.AdminCommentTrend(context.Background(), 6, "UTC"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid days error = %v, want validation", err)
	}
	if _, err := svc.AdminCommentTrend(context.Background(), 7, "Not/AZone"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid timezone error = %v, want validation", err)
	}
}

// mustTrendThread 返回趋势测试使用的站点线程。
func mustTrendThread(t *testing.T, db *gorm.DB, siteID int64) int64 {
	t.Helper()
	thread, err := repository.NewThreadRepo(db).GetBySiteAndKey(context.Background(), siteID, "page-key")
	if err != nil {
		t.Fatalf("get trend thread: %v", err)
	}
	return thread.ID
}

package comment

import (
	"context"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
)

// TestAdminListDefaultSortDesc 验证管理评论列表缺省按 (created_at, id) 降序，
// 即最新优先；显式 asc 反转方向。
func TestAdminListDefaultSortDesc(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	// 缺省不传 sort：按 desc 返回，最新（id 较大、同时间戳）优先。
	result, err := svc.AdminList(context.Background(), domain.AdminFilter{Limit: 50}, 1)
	if err != nil {
		t.Fatalf("admin list default: %v", err)
	}
	want := []int64{fx.IDs["pending"], fx.IDs["c"], fx.IDs["b"], fx.IDs["a"]}
	if !equalIDs(adminCommentViewIDs(result), want) {
		t.Fatalf("default ids = %v, want %v (desc)", adminCommentViewIDs(result), want)
	}

	// 显式 asc：最早优先。
	result, err = svc.AdminList(context.Background(), domain.AdminFilter{Sort: domain.CommentSortAsc, Limit: 50}, 1)
	if err != nil {
		t.Fatalf("admin list asc: %v", err)
	}
	want = []int64{fx.IDs["a"], fx.IDs["b"], fx.IDs["c"], fx.IDs["pending"]}
	if !equalIDs(adminCommentViewIDs(result), want) {
		t.Fatalf("asc ids = %v, want %v", adminCommentViewIDs(result), want)
	}
}

// TestAdminListThreadsDefaultSortDesc 验证管理线程列表缺省按 (created_at, id)
// 降序；显式 asc 反转方向。
func TestAdminListThreadsDefaultSortDesc(t *testing.T) {
	db := ownerTestDB(t)
	ctx := context.Background()
	threadRepo := repository.NewThreadRepo(db)
	siteRepo := repository.NewSiteRepo(db)
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	first, err := threadRepo.ResolveOrCreate(ctx, site.ID, "page-1", nil, nil)
	if err != nil {
		t.Fatalf("create thread 1: %v", err)
	}
	second, err := threadRepo.ResolveOrCreate(ctx, site.ID, "page-2", nil, nil)
	if err != nil {
		t.Fatalf("create thread 2: %v", err)
	}
	svc := ownerService(db, domain.UserDeleteModeSoft)

	result, err := svc.AdminListThreads(ctx, site.ID, nil, "", 1, domain.CommentSort(""), 50)
	if err != nil {
		t.Fatalf("admin list threads default: %v", err)
	}
	if len(result.Threads) != 2 || result.Threads[0].ID != second.ID || result.Threads[1].ID != first.ID {
		t.Fatalf("default threads = %+v, want newest-first", result.Threads)
	}

	result, err = svc.AdminListThreads(ctx, site.ID, nil, "", 1, domain.CommentSortAsc, 50)
	if err != nil {
		t.Fatalf("admin list threads asc: %v", err)
	}
	if len(result.Threads) != 2 || result.Threads[0].ID != first.ID || result.Threads[1].ID != second.ID {
		t.Fatalf("asc threads = %+v, want oldest-first", result.Threads)
	}
}

// adminCommentViewIDs 提取管理评论视图的 ID。
func adminCommentViewIDs(result *AdminListResult) []int64 {
	out := make([]int64, 0, len(result.Comments))
	for _, c := range result.Comments {
		out = append(out, c.ID)
	}
	return out
}

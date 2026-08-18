package repository

import (
	"context"
	"testing"

	"furtalk/internal/domain"
)

// TestCommentRepoCountAdminMatchesList 验证 CountAdmin 与 ListAdmin 使用完全
// 相同的过滤条件：无过滤、status 过滤与 q 搜索下总数恒等于行数。
func TestCommentRepoCountAdminMatchesList(t *testing.T) {
	db := newSortTestDB(t)
	siteID, _, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	for _, tt := range []struct {
		name   string
		filter domain.AdminFilter
	}{
		{name: "no filter", filter: domain.AdminFilter{SiteID: &siteID}},
		{name: "status filter", filter: domain.AdminFilter{SiteID: &siteID, Status: statusPtr(domain.CommentStatusPublished)}},
		{name: "q body", filter: domain.AdminFilter{SiteID: &siteID, Q: "body-c"}},
		{name: "q author email", filter: domain.AdminFilter{SiteID: &siteID, Q: "u@example.com"}},
		{name: "q author nickname", filter: domain.AdminFilter{SiteID: &siteID, Q: "u"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := repo.ListAdmin(ctx, tt.filter)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			total, err := repo.CountAdmin(ctx, tt.filter)
			if err != nil {
				t.Fatalf("count: %v", err)
			}
			if total != int64(len(rows)) {
				t.Fatalf("count = %d, want %d rows", total, len(rows))
			}
		})
	}

	// q 搜索命中单个正文。
	rows, err := repo.ListAdmin(ctx, domain.AdminFilter{SiteID: &siteID, Q: "body-c"})
	if err != nil {
		t.Fatalf("list q: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != ids["c"] {
		t.Fatalf("q=body-c rows = %+v, want only c", rows)
	}
}

// TestCommentRepoListAdminOffsetOutOfRange 验证越界 offset 返回空页，
// 而总数仍反映完整匹配集。
func TestCommentRepoListAdminOffsetOutOfRange(t *testing.T) {
	db := newSortTestDB(t)
	siteID, _, _ := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	rows, err := repo.ListAdmin(ctx, domain.AdminFilter{SiteID: &siteID, Offset: 100, Limit: 10})
	if err != nil {
		t.Fatalf("list out of range: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("out-of-range rows = %d, want 0", len(rows))
	}
	total, err := repo.CountAdmin(ctx, domain.AdminFilter{SiteID: &siteID})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 5 {
		t.Fatalf("count = %d, want 5", total)
	}
}

// TestCommentRepoCountByOwnerMatchesList 验证 CountByOwner 与 ListByOwner
// 条件一致，且 site/status 过滤与跨用户隔离都作用于 count。
func TestCommentRepoCountByOwnerMatchesList(t *testing.T) {
	db := newCommentOwnerTestDB(t)
	owner1, owner2 := seedOwnerFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	published := domain.CommentStatusPublished
	for _, tt := range []struct {
		name   string
		owner  int64
		filter domain.OwnerFilter
	}{
		{name: "owner1 all", owner: owner1, filter: domain.OwnerFilter{}},
		{name: "owner2 all", owner: owner2, filter: domain.OwnerFilter{}},
		{name: "owner1 published", owner: owner1, filter: domain.OwnerFilter{Status: &published}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := repo.ListByOwner(ctx, tt.owner, tt.filter)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			total, err := repo.CountByOwner(ctx, tt.owner, tt.filter)
			if err != nil {
				t.Fatalf("count: %v", err)
			}
			if total != int64(len(rows)) {
				t.Fatalf("count = %d, want %d rows", total, len(rows))
			}
		})
	}

	// 越界页空列表但总数不变。
	rows, err := repo.ListByOwner(ctx, owner1, domain.OwnerFilter{Offset: 50, Limit: 10})
	if err != nil {
		t.Fatalf("list out of range: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("out-of-range rows = %d, want 0", len(rows))
	}
	total, err := repo.CountByOwner(ctx, owner1, domain.OwnerFilter{})
	if err != nil {
		t.Fatalf("count owner1: %v", err)
	}
	if total != 3 {
		t.Fatalf("owner1 count = %d, want 3", total)
	}
}

// statusPtr 返回指向给定状态的指针。
func statusPtr(s domain.CommentStatus) *domain.CommentStatus {
	return &s
}

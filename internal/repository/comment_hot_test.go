package repository

import (
	"context"
	"testing"

	"furtalk/internal/domain"
)

// TestCommentRepoListPublicHotOrdering 验证 hot 排序按 (like_count, created_at, id)
// 降序：计数优先，随后时间与 id 决胜；不同计数按计数降序。
func TestCommentRepoListPublicHotOrdering(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 3)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	// a: 3 赞，b: 1 赞，c: 0 赞，d: 2 赞（时间与 id 按 a<b<c<d 递增）
	add := func(commentID int64, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := repo.AddLike(ctx, siteID, commentID, users[i]); err != nil {
				t.Fatalf("add like %d: %v", commentID, err)
			}
		}
	}
	add(ids["a"], 3)
	add(ids["b"], 1)
	add(ids["d"], 2)

	rows, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortHot, nil, 50, nil)
	if err != nil {
		t.Fatalf("list hot: %v", err)
	}
	want := []int64{ids["a"], ids["d"], ids["b"], ids["c"]}
	assertOrder(t, rows, want)
	// 验证每个节点的公开计数
	counts := map[int64]int64{ids["a"]: 3, ids["b"]: 1, ids["c"]: 0, ids["d"]: 2}
	for _, r := range rows {
		if r.LikeCount != counts[r.ID] {
			t.Fatalf("comment %d like_count = %d, want %d", r.ID, r.LikeCount, counts[r.ID])
		}
	}
}

// TestCommentRepoListPublicHotTies 验证同计数在 (created_at, id) 上按降序决胜。
// a 与 b 同时间戳，id 更大者在前；c 时间更晚但计数相同。
func TestCommentRepoListPublicHotTies(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 1)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	// a、b 同时间戳；c 更晚；三者各 1 赞 → 期望 c(时间最晚), b(id 更大), a
	for _, id := range []int64{ids["a"], ids["b"], ids["c"]} {
		if _, err := repo.AddLike(ctx, siteID, id, users[0]); err != nil {
			t.Fatalf("add like: %v", err)
		}
	}
	rows, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortHot, nil, 50, nil)
	if err != nil {
		t.Fatalf("list hot: %v", err)
	}
	want := []int64{ids["c"], ids["b"], ids["a"], ids["d"]}
	assertOrder(t, rows, want)
}

// TestCommentRepoListPublicHotPagination 验证 hot keyset 分页跨页无重复、无遗漏。
func TestCommentRepoListPublicHotPagination(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 3)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	add := func(commentID int64, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := repo.AddLike(ctx, siteID, commentID, users[i]); err != nil {
				t.Fatalf("add like %d: %v", commentID, err)
			}
		}
	}
	add(ids["a"], 3)
	add(ids["b"], 1)
	add(ids["d"], 2)

	all := make([]int64, 0, 4)
	var cursor *domain.Cursor
	for page := 0; ; page++ {
		rows, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortHot, cursor, 2, nil)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			all = append(all, r.ID)
		}
		if len(rows) < 2 {
			break
		}
		last := rows[len(rows)-1]
		cursor = &domain.Cursor{LikeCount: last.LikeCount, CreatedAt: last.CreatedAt, ID: last.ID, Hot: true}
		if page > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	want := []int64{ids["a"], ids["d"], ids["b"], ids["c"]}
	if len(all) != len(want) {
		t.Fatalf("ids = %v, want %v", all, want)
	}
	seen := map[int64]bool{}
	for i, id := range all {
		if seen[id] {
			t.Fatalf("duplicate id %d across pages", id)
		}
		seen[id] = true
		if id != want[i] {
			t.Fatalf("ids = %v, want %v", all, want)
		}
	}
}

// TestCommentRepoListPublicHotViewerState 验证 hot 模式下查看者状态与计数同屏输出。
func TestCommentRepoListPublicHotViewerState(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 1)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	if _, err := repo.AddLike(ctx, siteID, ids["b"], users[0]); err != nil {
		t.Fatalf("add like: %v", err)
	}
	viewer := users[0]
	rows, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortHot, nil, 50, &viewer)
	if err != nil {
		t.Fatalf("list hot with viewer: %v", err)
	}
	for _, r := range rows {
		if r.ID == ids["b"] && !r.LikedByMe {
			t.Fatal("liked_by_me should be true for the liker in hot mode")
		}
		if r.ID != ids["b"] && r.LikedByMe {
			t.Fatal("unliked comment reported liked_by_me")
		}
	}
}

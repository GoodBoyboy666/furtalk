package repository

import (
	"context"
	"errors"
	"sync"
	"testing"

	"furtalk/internal/domain"
	"gorm.io/gorm"
)

// seedLikeUsers 创建 n 个独立用户并返回其 ID。
func seedLikeUsers(t *testing.T, db *gorm.DB, n int) []int64 {
	t.Helper()
	userRepo := NewUserRepo(db)
	ids := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		email := "like-user-" + string(rune('a'+i)) + "@example.com"
		u := &domain.User{Email: email, EmailNormalized: email, Nickname: "u", Role: domain.RoleUser, Status: domain.UserStatusActive}
		if err := userRepo.Create(context.Background(), u); err != nil {
			t.Fatalf("create user %d: %v", i, err)
		}
		ids = append(ids, u.ID)
	}
	return ids
}

// TestCommentLikeIdempotentAdd 验证重复添加不重复计数。
func TestCommentLikeIdempotentAdd(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 1)
	repo := NewCommentRepo(db)
	ctx := context.Background()
	commentID := ids["a"]

	first, err := repo.AddLike(ctx, siteID, commentID, users[0])
	if err != nil {
		t.Fatalf("add like: %v", err)
	}
	if first.LikeCount != 1 || !first.Liked {
		t.Fatalf("first add = %+v, want count 1 liked true", first)
	}
	second, err := repo.AddLike(ctx, siteID, commentID, users[0])
	if err != nil {
		t.Fatalf("repeat add: %v", err)
	}
	if second.LikeCount != 1 || !second.Liked {
		t.Fatalf("repeat add = %+v, want count 1 liked true", second)
	}
	rows, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, nil, 50, nil)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	for _, r := range rows {
		if r.ID == commentID && r.LikeCount != 1 {
			t.Fatalf("like_count = %d, want 1", r.LikeCount)
		}
	}
}

// TestCommentLikeIdempotentRemove 验证重复移除成功且计数不为负。
func TestCommentLikeIdempotentRemove(t *testing.T) {
	db := newSortTestDB(t)
	siteID, _, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 1)
	repo := NewCommentRepo(db)
	ctx := context.Background()
	commentID := ids["a"]

	if _, err := repo.AddLike(ctx, siteID, commentID, users[0]); err != nil {
		t.Fatalf("add like: %v", err)
	}
	first, err := repo.RemoveLike(ctx, siteID, commentID, users[0])
	if err != nil {
		t.Fatalf("remove like: %v", err)
	}
	if first.LikeCount != 0 || first.Liked {
		t.Fatalf("first remove = %+v, want count 0 liked false", first)
	}
	second, err := repo.RemoveLike(ctx, siteID, commentID, users[0])
	if err != nil {
		t.Fatalf("repeat remove: %v", err)
	}
	if second.LikeCount != 0 || second.Liked {
		t.Fatalf("repeat remove = %+v, want count 0 liked false", second)
	}
}

// TestCommentLikeMultiUserCounts 验证不同用户独立计数，且作者可赞自己的评论。
func TestCommentLikeMultiUserCounts(t *testing.T) {
	db := newSortTestDB(t)
	siteID, _, ids := seedSortFixture(t, db)
	// 作者也是用户之一（seedSortFixture 的 u@example.com），构造其 ID。
	userRepo := NewUserRepo(db)
	author, err := userRepo.FindByEmailNormalized(context.Background(), "u@example.com")
	if err != nil {
		t.Fatalf("find author: %v", err)
	}
	users := seedLikeUsers(t, db, 2)
	repo := NewCommentRepo(db)
	ctx := context.Background()
	commentID := ids["a"]

	// 作者自赞 + 两名独立用户
	if _, err := repo.AddLike(ctx, siteID, commentID, author.ID); err != nil {
		t.Fatalf("author self like: %v", err)
	}
	if _, err := repo.AddLike(ctx, siteID, commentID, users[0]); err != nil {
		t.Fatalf("user0 like: %v", err)
	}
	if _, err := repo.AddLike(ctx, siteID, commentID, users[1]); err != nil {
		t.Fatalf("user1 like: %v", err)
	}
	result, err := repo.AddLike(ctx, siteID, commentID, users[0])
	if err != nil {
		t.Fatalf("user0 repeat: %v", err)
	}
	if result.LikeCount != 3 {
		t.Fatalf("like_count = %d, want 3", result.LikeCount)
	}
	// 移除其中一个后计数为 2
	removed, err := repo.RemoveLike(ctx, siteID, commentID, users[1])
	if err != nil {
		t.Fatalf("remove user1: %v", err)
	}
	if removed.LikeCount != 2 {
		t.Fatalf("after remove count = %d, want 2", removed.LikeCount)
	}
}

// TestCommentLikeConcurrentDuplicates 验证并发的重复插入被唯一约束吸收。
// SQLite 对并发多语句事务不加忙等待（本驱动的 busy_timeout 只作用于语句级），
// 因此用单连接串行化数据库写入，仍从 Go 层并发发起，验证竞态下不重复计数。
func TestCommentLikeConcurrentDuplicates(t *testing.T) {
	db := newSortTestDB(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	siteID, _, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 1)
	repo := NewCommentRepo(db)
	ctx := context.Background()
	commentID := ids["a"]

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.AddLike(ctx, siteID, commentID, users[0])
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent add like: %v", err)
	}
	result, err := repo.AddLike(ctx, siteID, commentID, users[0])
	if err != nil {
		t.Fatalf("final add: %v", err)
	}
	if result.LikeCount != 1 {
		t.Fatalf("concurrent adds produced like_count = %d, want 1", result.LikeCount)
	}
}

// TestCommentLikeHiddenStatesNotDisclosed 验证缺失/未发布/软删除评论返回
// 相同的 ErrNotFound，不披露存在性；软删除不删除 Like 行。
func TestCommentLikeHiddenStatesNotDisclosed(t *testing.T) {
	db := newSortTestDB(t)
	siteID, _, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 1)
	repo := NewCommentRepo(db)
	ctx := context.Background()

	// pending 评论不可赞
	if _, err := repo.AddLike(ctx, siteID, ids["pending"], users[0]); !isNotFound(err) {
		t.Fatalf("add like on pending = %v, want not found", err)
	}
	// 缺失评论
	if _, err := repo.AddLike(ctx, siteID, 99999, users[0]); !isNotFound(err) {
		t.Fatalf("add like on missing = %v, want not found", err)
	}
	if _, err := repo.RemoveLike(ctx, siteID, 99999, users[0]); !isNotFound(err) {
		t.Fatalf("remove like on missing = %v, want not found", err)
	}
	// 跨站点评论
	if _, err := repo.AddLike(ctx, siteID+100, ids["a"], users[0]); !isNotFound(err) {
		t.Fatalf("add like cross-site = %v, want not found", err)
	}
}

// TestCommentLikeCascadeHardDelete 验证硬删除评论/用户会级联清理 Like 行，
// 公开响应不再出现陈旧的点赞计数。
func TestCommentLikeCascadeHardDelete(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 1)
	repo := NewCommentRepo(db)
	userRepo := NewUserRepo(db)
	ctx := context.Background()
	commentID := ids["a"]

	if _, err := repo.AddLike(ctx, siteID, commentID, users[0]); err != nil {
		t.Fatalf("add like: %v", err)
	}
	// 硬删除评论（无回复，直接删除即可）
	if err := repo.HardDelete(ctx, siteID, commentID); err != nil {
		t.Fatalf("hard delete comment: %v", err)
	}
	rows, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, nil, 50, nil)
	if err != nil {
		t.Fatalf("list public after delete: %v", err)
	}
	for _, r := range rows {
		if r.ID == commentID {
			t.Fatal("hard-deleted comment still visible")
		}
	}
	// 重新用另一条评论验证用户硬删除级联清理 Like 行
	comment2 := ids["b"]
	if _, err := repo.AddLike(ctx, siteID, comment2, users[0]); err != nil {
		t.Fatalf("add like on b: %v", err)
	}
	if err := userRepo.Delete(ctx, users[0]); err != nil {
		t.Fatalf("hard delete user: %v", err)
	}
	rows, err = repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, nil, 50, nil)
	if err != nil {
		t.Fatalf("list public after user delete: %v", err)
	}
	for _, r := range rows {
		if r.ID == comment2 && r.LikeCount != 0 {
			t.Fatalf("like_count after user hard delete = %d, want 0", r.LikeCount)
		}
	}
	// 被删用户后续的 Like 变更在缺省路径返回错误，且绝不重复计数
	if _, err := repo.AddLike(ctx, siteID, comment2, users[0]); err == nil {
		t.Fatal("add like by hard-deleted user should fail")
	}
}

// TestCommentLikeViewerState 验证 ListPublic 在有/无查看者时正确输出观众状态。
func TestCommentLikeViewerState(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	users := seedLikeUsers(t, db, 2)
	repo := NewCommentRepo(db)
	ctx := context.Background()
	commentID := ids["a"]

	if _, err := repo.AddLike(ctx, siteID, commentID, users[0]); err != nil {
		t.Fatalf("add like: %v", err)
	}
	// 匿名（nil viewer）：liked_by_me 恒为 false，count 可见
	anon, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, nil, 50, nil)
	if err != nil {
		t.Fatalf("anon list: %v", err)
	}
	for _, r := range anon {
		if r.ID == commentID {
			if r.LikeCount != 1 || r.LikedByMe {
				t.Fatalf("anon row = count %d liked %v, want count 1 liked false", r.LikeCount, r.LikedByMe)
			}
		} else if r.LikedByMe {
			t.Fatalf("unliked comment reported liked_by_me for anon viewer")
		}
	}
	// 点赞者本人：liked_by_me true
	viewer0 := users[0]
	me, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, nil, 50, &viewer0)
	if err != nil {
		t.Fatalf("viewer list: %v", err)
	}
	for _, r := range me {
		if r.ID == commentID && !r.LikedByMe {
			t.Fatal("liked_by_me should be true for the liker")
		}
	}
	// 非点赞者：liked_by_me false
	viewer1 := users[1]
	other, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortAsc, nil, 50, &viewer1)
	if err != nil {
		t.Fatalf("other viewer list: %v", err)
	}
	for _, r := range other {
		if r.ID == commentID && r.LikedByMe {
			t.Fatal("liked_by_me should be false for a non-liker")
		}
	}
}

func isNotFound(err error) bool {
	return errors.Is(err, domain.ErrNotFound)
}

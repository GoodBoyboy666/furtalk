package comment

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
)

// TestServiceLikeCommentAuthoritative 验证服务层 Like/Unlike 返回权威结果且幂等。
func TestServiceLikeCommentAuthoritative(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	// 作者用户 u@example.com 赞 a
	userRepo := svc.users
	author, err := userRepo.FindByEmailNormalized(context.Background(), "u@example.com")
	if err != nil {
		t.Fatalf("find author: %v", err)
	}
	res, err := svc.LikeComment(context.Background(), fx.SiteID, fx.IDs["a"], author.ID)
	if err != nil {
		t.Fatalf("like: %v", err)
	}
	if res.CommentID != fx.IDs["a"] || res.LikeCount != 1 || !res.Liked {
		t.Fatalf("like result = %+v, want comment a count 1 liked true", res)
	}
	// 重复赞：计数不变
	res2, err := svc.LikeComment(context.Background(), fx.SiteID, fx.IDs["a"], author.ID)
	if err != nil {
		t.Fatalf("repeat like: %v", err)
	}
	if res2.LikeCount != 1 {
		t.Fatalf("repeat like count = %d, want 1", res2.LikeCount)
	}
	// 取消赞：计数 0
	res3, err := svc.UnlikeComment(context.Background(), fx.SiteID, fx.IDs["a"], author.ID)
	if err != nil {
		t.Fatalf("unlike: %v", err)
	}
	if res3.LikeCount != 0 || res3.Liked {
		t.Fatalf("unlike result = %+v, want count 0 liked false", res3)
	}
}

// TestServiceListPublicHotSort 验证显式 sort=hot 按计数排序，缺省 hot 回落到策略默认。
func TestServiceListPublicHotSort(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	author, err := svc.users.FindByEmailNormalized(context.Background(), "u@example.com")
	if err != nil {
		t.Fatalf("find author: %v", err)
	}
	// b 2 赞、a 1 赞、c 0 赞
	if _, err := svc.LikeComment(context.Background(), fx.SiteID, fx.IDs["a"], author.ID); err != nil {
		t.Fatalf("like a: %v", err)
	}
	if _, err := svc.LikeComment(context.Background(), fx.SiteID, fx.IDs["b"], author.ID); err != nil {
		t.Fatalf("like b: %v", err)
	}
	if _, err := svc.LikeComment(context.Background(), fx.SiteID, fx.IDs["b"], author.ID); err != nil {
		t.Fatalf("like b again: %v", err)
	}
	// 全部同 created_at，id 决胜 → hot 下 b(id大), a, c
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "hot", 50, nil)
	if err != nil {
		t.Fatalf("list hot: %v", err)
	}
	want := []int64{fx.IDs["b"], fx.IDs["a"], fx.IDs["c"]}
	if got := publicCommentIDs(view); !sameInts(got, want) {
		t.Fatalf("hot ids = %v, want %v", got, want)
	}
}

// TestServiceListPublicHotDefault 验证策略默认 comment_sort=hot 时缺省走 hot。
func TestServiceListPublicHotDefault(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	svc.settings = &staticCommentPolicyReader{policy: domain.CommentPolicy{
		Mode:            domain.CommentModeAuthenticated,
		Moderation:      domain.ModerationDirect,
		UserDeleteMode:  domain.UserDeleteModeSoft,
		MaxReplyDepth:   5,
		CaptchaPolicy:   map[string]bool{},
		GravatarBaseURL: "https://www.gravatar.com/avatar",
		Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		CommentSort:     string(domain.CommentSortHot),
	}}
	author, err := svc.users.FindByEmailNormalized(context.Background(), "u@example.com")
	if err != nil {
		t.Fatalf("find author: %v", err)
	}
	if _, err := svc.LikeComment(context.Background(), fx.SiteID, fx.IDs["a"], author.ID); err != nil {
		t.Fatalf("like a: %v", err)
	}
	// 缺省 sort 使用策略默认 hot → a(1 赞) 在最前；b/c 均 0 赞且同时间戳按 id 降序 → c 在 b 前
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50, nil)
	if err != nil {
		t.Fatalf("list default hot: %v", err)
	}
	want := []int64{fx.IDs["a"], fx.IDs["c"], fx.IDs["b"]}
	if got := publicCommentIDs(view); !sameInts(got, want) {
		t.Fatalf("default hot ids = %v, want %v", got, want)
	}
}

// TestServiceListPublicViewerState 验证公开读取携带查看者点赞状态，匿名恒 false。
func TestServiceListPublicViewerState(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	author, err := svc.users.FindByEmailNormalized(context.Background(), "u@example.com")
	if err != nil {
		t.Fatalf("find author: %v", err)
	}
	if _, err := svc.LikeComment(context.Background(), fx.SiteID, fx.IDs["a"], author.ID); err != nil {
		t.Fatalf("like a: %v", err)
	}
	// 匿名
	anon, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50, nil)
	if err != nil {
		t.Fatalf("anon list: %v", err)
	}
	if !hasLikeState(anon, fx.IDs["a"], 1, false) {
		t.Fatalf("anon state mismatch: %+v", anon.Comments)
	}
	// 点赞者本人
	viewer := author.ID
	me, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50, &viewer)
	if err != nil {
		t.Fatalf("viewer list: %v", err)
	}
	if !hasLikeState(me, fx.IDs["a"], 1, true) {
		t.Fatalf("viewer state mismatch: %+v", me.Comments)
	}
}

// TestServiceCursorSortAwareRejection 验证 hot 游标不能用于方向模式，
// 方向游标不能用于 hot；非法 sort 返回验证错误。
func TestServiceCursorSortAwareRejection(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	author, err := svc.users.FindByEmailNormalized(context.Background(), "u@example.com")
	if err != nil {
		t.Fatalf("find author: %v", err)
	}
	if _, err := svc.LikeComment(context.Background(), fx.SiteID, fx.IDs["a"], author.ID); err != nil {
		t.Fatalf("like a: %v", err)
	}

	// 生成一个 hot 游标
	hotView, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "hot", 1, nil)
	if err != nil {
		t.Fatalf("list hot: %v", err)
	}
	if hotView.NextCursor == nil {
		t.Fatal("expected a hot next cursor")
	}
	// hot 游标用于 asc → 验证错误
	if _, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", *hotView.NextCursor, "asc", 1, nil); !isValidationErr(err) {
		t.Fatalf("hot cursor reused for asc = %v, want validation", err)
	}
	// 方向游标用于 hot → 验证错误
	ascView, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "asc", 1, nil)
	if err != nil {
		t.Fatalf("list asc: %v", err)
	}
	if ascView.NextCursor == nil {
		t.Fatal("expected an asc next cursor")
	}
	if _, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", *ascView.NextCursor, "hot", 1, nil); !isValidationErr(err) {
		t.Fatalf("directional cursor reused for hot = %v, want validation", err)
	}
	// 非法 sort 值
	if _, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "sideways", 1, nil); !isValidationErr(err) {
		t.Fatalf("invalid sort = %v, want validation", err)
	}
	// 方向模式拒绝 hot 游标（含历史格式）
	legacyHot := "aG90OjE6MTc1MDAwMDAwMDAwMDA6MQ" // 构造畸形 hot 前缀
	if _, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", legacyHot, "asc", 1, nil); !isValidationErr(err) {
		t.Fatalf("legacy hot-shaped cursor for asc = %v, want validation", err)
	}
}

func sameInts(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasLikeState(view *ThreadView, id int64, count int64, liked bool) bool {
	for _, c := range view.Comments {
		if c.ID != id {
			continue
		}
		return c.LikeCount == count && c.LikedByMe == liked
	}
	return false
}

func isValidationErr(err error) bool {
	return err != nil && (err == domain.ErrValidation || errors.Is(err, domain.ErrValidation))
}

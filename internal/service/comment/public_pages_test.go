package comment

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/repository"
)

// TestPublicPagesIndependentQuotas 验证根与回复独立截断、游标位置和最终完整覆盖。
func TestPublicPagesIndependentQuotas(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished},
		{key: "r1", parent: "a", root: "a", status: domain.CommentStatusPublished, depth: 1},
		{key: "r2", parent: "r1", root: "a", status: domain.CommentStatusPublished, depth: 2},
		{key: "hidden", parent: "a", root: "a", status: domain.CommentStatusPending, depth: 1},
		{key: "r3", parent: "hidden", root: "a", status: domain.CommentStatusPublished, depth: 2},
		{key: "b", status: domain.CommentStatusPublished},
		{key: "c", status: domain.CommentStatusPublished},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()
	for _, limit := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("limit-%d", limit), func(t *testing.T) {
			var rootIDs, replyIDs []int64
			rootCursor := ""
			for page := 0; page < 5; page++ {
				view, err := svc.ListPublicRoots(ctx, fx.SiteID, "page-key", rootCursor, "asc", limit, nil)
				if err != nil || len(view.Comments) > limit {
					t.Fatalf("root page=%+v err=%v", view, err)
				}
				for _, row := range view.Comments {
					rootIDs = append(rootIDs, row.ID)
					if row.ParentID != nil || row.HasReplies != (row.ID == fx.IDs["a"]) {
						t.Fatalf("root relationships/flag=%+v", row)
					}
				}
				if view.NextCursor == nil {
					break
				}
				cursor, err := decodeRootCursor(*view.NextCursor, fx.SiteID, fx.ThreadID, domain.CommentSortAsc)
				if err != nil || cursor.ID != view.Comments[len(view.Comments)-1].ID {
					t.Fatalf("root cursor=%+v err=%v", cursor, err)
				}
				rootCursor = *view.NextCursor
			}
			if !reflect.DeepEqual(rootIDs, []int64{fx.IDs["a"], fx.IDs["b"], fx.IDs["c"]}) {
				t.Fatalf("root IDs=%v", rootIDs)
			}
			replyCursor := ""
			for page := 0; page < 5; page++ {
				view, err := svc.ListPublicReplies(ctx, fx.SiteID, fx.IDs["a"], "page-key", replyCursor, limit, nil)
				if err != nil || len(view.Comments) > limit || view.RootID != fx.IDs["a"] {
					t.Fatalf("reply page=%+v err=%v", view, err)
				}
				for _, row := range view.Comments {
					replyIDs = append(replyIDs, row.ID)
				}
				if view.NextCursor == nil {
					break
				}
				cursor, err := decodeReplyCursor(*view.NextCursor, fx.SiteID, fx.ThreadID, fx.IDs["a"])
				if err != nil || cursor.ID != view.Comments[len(view.Comments)-1].ID {
					t.Fatalf("reply cursor=%+v err=%v", cursor, err)
				}
				replyCursor = *view.NextCursor
			}
			if !reflect.DeepEqual(replyIDs, []int64{fx.IDs["r1"], fx.IDs["r2"], fx.IDs["r3"]}) {
				t.Fatalf("reply IDs=%v", replyIDs)
			}
			// 精确页面没有多余游标，少于页面大小也同样结束。
			if limit >= 3 && (rootCursor != "" || replyCursor != "") {
				t.Fatalf("exact/fewer pages unexpectedly had cursors: %q %q", rootCursor, replyCursor)
			}
		})
	}
	last, err := repository.NewCommentRepo(db).FindBySiteAndID(ctx, fx.SiteID, fx.IDs["r3"])
	if err != nil {
		t.Fatal(err)
	}
	exhausted := encodeReplyCursor(fx.SiteID, fx.ThreadID, fx.IDs["a"], domain.PublicComment{Comment: *last})
	view, err := svc.ListPublicReplies(ctx, fx.SiteID, fx.IDs["a"], "page-key", exhausted, 1, nil)
	if err != nil || view.Comments == nil || len(view.Comments) != 0 || view.NextCursor != nil {
		t.Fatalf("exhausted reply page=%+v err=%v", view, err)
	}
}

// TestPublicPagesLimitBounds 验证两个接口均使用默认 50 和上限 100。
func TestPublicPagesLimitBounds(t *testing.T) {
	db := ownerTestDB(t)
	seeds := []treeSeed{{key: "root", status: domain.CommentStatusPublished}}
	for i := 0; i < 103; i++ {
		seeds = append(seeds, treeSeed{key: fmt.Sprintf("root-%d", i), status: domain.CommentStatusPublished})
		seeds = append(seeds, treeSeed{key: fmt.Sprintf("reply-%d", i), parent: "root", root: "root", depth: 1, status: domain.CommentStatusPublished})
	}
	fx := seedPublicTreeComments(t, db, seeds)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	for _, tc := range []struct{ requested, want int }{{-1, 50}, {0, 50}, {1, 1}, {100, 100}, {101, 100}} {
		roots, err := svc.ListPublicRoots(context.Background(), fx.SiteID, "page-key", "", "", tc.requested, nil)
		if err != nil || len(roots.Comments) != tc.want || roots.NextCursor == nil {
			t.Fatalf("root limit=%d view=%+v err=%v", tc.requested, roots, err)
		}
		replies, err := svc.ListPublicReplies(context.Background(), fx.SiteID, fx.IDs["root"], "page-key", "", tc.requested, nil)
		if err != nil || len(replies.Comments) != tc.want || replies.NextCursor == nil {
			t.Fatalf("reply limit=%d view=%+v err=%v", tc.requested, replies, err)
		}
	}
}

// TestPublicPageCursorScopes 验证新增游标拒绝所有命名空间与请求作用域互换。
func TestPublicPageCursorScopes(t *testing.T) {
	at := time.Date(2026, 8, 12, 12, 0, 0, 123000, time.UTC)
	row := domain.PublicRootComment{PublicComment: domain.PublicComment{Comment: domain.Comment{ID: 4, CreatedAt: at, IsPinned: true}, LikeCount: 8}}
	root := encodeRootCursor(1, 2, domain.CommentSortHot, row)
	reply := encodeReplyCursor(1, 2, 3, row.PublicComment)
	validRoot, err := decodeRootCursor(root, 1, 2, domain.CommentSortHot)
	if err != nil || validRoot.ID != 4 || !validRoot.Pinned || validRoot.LikeCount != 8 || !validRoot.CreatedAt.Equal(at) {
		t.Fatalf("root roundtrip=%+v err=%v", validRoot, err)
	}
	validReply, err := decodeReplyCursor(reply, 1, 2, 3)
	if err != nil || validReply.ID != 4 || validReply.Pinned || validReply.LikeCount != 0 || !validReply.CreatedAt.Equal(at) {
		t.Fatalf("reply roundtrip=%+v err=%v", validReply, err)
	}
	for name, call := range map[string]func() error{
		"root-sort":      func() error { _, err := decodeRootCursor(root, 1, 2, domain.CommentSortAsc); return err },
		"root-site":      func() error { _, err := decodeRootCursor(root, 9, 2, domain.CommentSortHot); return err },
		"root-thread":    func() error { _, err := decodeRootCursor(root, 1, 9, domain.CommentSortHot); return err },
		"root-endpoint":  func() error { _, err := decodeRootCursor(reply, 1, 2, domain.CommentSortHot); return err },
		"reply-site":     func() error { _, err := decodeReplyCursor(reply, 9, 2, 3); return err },
		"reply-thread":   func() error { _, err := decodeReplyCursor(reply, 1, 9, 3); return err },
		"reply-root":     func() error { _, err := decodeReplyCursor(reply, 1, 2, 9); return err },
		"reply-endpoint": func() error { _, err := decodeReplyCursor(root, 1, 2, 3); return err },
		"legacy-to-root": func() error {
			_, err := decodeRootCursor(encodeCursor(false, at, 4), 1, 2, domain.CommentSortAsc)
			return err
		},
		"legacy-to-reply": func() error { _, err := decodeReplyCursor(encodeCursor(false, at, 4), 1, 2, 3); return err },
		"root-to-legacy":  func() error { _, err := decodeCursor(root, domain.CommentSortHot); return err },
		"reply-to-legacy": func() error { _, err := decodeCursor(reply, domain.CommentSortAsc); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(call(), domain.ErrValidation) {
				t.Fatal("scope mismatch must return validation")
			}
		})
	}
	for _, sort := range []domain.CommentSort{domain.CommentSortAsc, domain.CommentSortDesc} {
		raw := encodeRootCursor(1, 2, sort, row)
		other := domain.CommentSortAsc
		if sort == other {
			other = domain.CommentSortDesc
		}
		if _, err := decodeRootCursor(raw, 1, 2, other); !errors.Is(err, domain.ErrValidation) {
			t.Fatal("direction swap must fail")
		}
	}
	encode := func(payload string) string { return base64.RawURLEncoding.EncodeToString([]byte(payload)) }
	for _, payload := range []string{
		"roots:v2:1:2:hot:1:8:123:4", "roots:v1:1:2:hot:2:8:123:4", "roots:v1:1:2:invalid:1:8:123:4",
		"roots:v1:0:2:hot:1:8:123:4", "roots:v1:1:0:hot:1:8:123:4", "roots:v1:1:2:hot:1:-1:123:4",
		"roots:v1:1:2:hot:1:8:-1:4", "roots:v1:1:2:hot:1:8:123:0", "roots:v1:1:2:hot:1:8:123:4:extra",
		"roots:v1:1:2:hot:1:8:123:9223372036854775808", "roots:v1:1:2:hot:1:8:nan:4", "roots:v1:+1:2:hot:1:8:123:4",
	} {
		if _, err := decodeRootCursor(encode(payload), 1, 2, domain.CommentSortHot); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("accepted root payload %q", payload)
		}
	}
	for _, payload := range []string{
		"replies:v2:1:2:3:123:4", "replies:v1:0:2:3:123:4", "replies:v1:1:0:3:123:4", "replies:v1:1:2:0:123:4",
		"replies:v1:1:2:3:-1:4", "replies:v1:1:2:3:123:0", "replies:v1:1:2:3:123:4:extra", "replies:v1:1:2:3:nan:4",
	} {
		if _, err := decodeReplyCursor(encode(payload), 1, 2, 3); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("accepted reply payload %q", payload)
		}
	}
	for _, raw := range []string{"%%%", encode("garbage")} {
		if _, err := decodeRootCursor(raw, 1, 2, domain.CommentSortHot); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("accepted malformed cursor %q", raw)
		}
		if _, err := decodeReplyCursor(raw, 1, 2, 3); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("accepted malformed cursor %q", raw)
		}
	}
	if _, err := decodeRootCursor(encode("roots:v1:1:2:asc:0:8:123:4"), 1, 2, domain.CommentSortAsc); !errors.Is(err, domain.ErrValidation) {
		t.Fatal("directional root cursor must not carry hot score")
	}
}

// TestPublicPagesReadOnlyAndValidation 验证缺页只读、关闭线程可读以及参数错误。
func TestPublicPagesReadOnlyAndValidation(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{{key: "root", status: domain.CommentStatusPublished}})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		view, err := svc.ListPublicRoots(ctx, fx.SiteID, "missing-page", "", "", 10, nil)
		if err != nil || view.ID != 0 || !view.CommentsEnabled || view.Comments == nil || len(view.Comments) != 0 || view.NextCursor != nil {
			t.Fatalf("missing root page=%+v err=%v", view, err)
		}
		if _, err := svc.ListPublicReplies(ctx, fx.SiteID, fx.IDs["root"], "missing-page", "", 10, nil); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("missing reply thread err=%v", err)
		}
	}
	var count int64
	if err := db.Table("threads").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("public reads wrote threads count=%d err=%v", count, err)
	}
	if _, err := repository.NewThreadRepo(db).UpdateCommentsEnabled(ctx, fx.SiteID, fx.ThreadID, false); err != nil {
		t.Fatal(err)
	}
	closed, err := svc.ListPublicRoots(ctx, fx.SiteID, "page-key", "", "", 10, nil)
	if err != nil || closed.CommentsEnabled || len(closed.Comments) != 1 {
		t.Fatalf("closed roots=%+v err=%v", closed, err)
	}
	if _, err := svc.ListPublicReplies(ctx, fx.SiteID, fx.IDs["root"], "page-key", "", 10, nil); err != nil {
		t.Fatalf("closed replies err=%v", err)
	}
	for _, pageKey := range []string{"", strings.Repeat("x", 513)} {
		if _, err := svc.ListPublicRoots(ctx, fx.SiteID, pageKey, "", "", 10, nil); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("invalid root page key err=%v", err)
		}
		if _, err := svc.ListPublicReplies(ctx, fx.SiteID, fx.IDs["root"], pageKey, "", 10, nil); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("invalid reply page key err=%v", err)
		}
	}
	if _, err := svc.ListPublicRoots(ctx, fx.SiteID, "page-key", "", "invalid", 10, nil); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid root sort err=%v", err)
	}
}

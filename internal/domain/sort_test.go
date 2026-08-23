package domain

import (
	"errors"
	"testing"
)

// TestNormalizeAdminSort 验证管理列表排序契约：空值归一化为 desc，
// asc/desc 原样通过，非法值返回验证错误。
func TestNormalizeAdminSort(t *testing.T) {
	cases := []struct {
		raw  string
		want CommentSort
	}{
		{raw: "", want: CommentSortDesc},
		{raw: "asc", want: CommentSortAsc},
		{raw: "desc", want: CommentSortDesc},
	}
	for _, tc := range cases {
		got, err := NormalizeAdminSort(tc.raw)
		if err != nil {
			t.Fatalf("NormalizeAdminSort(%q) error = %v, want nil", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeAdminSort(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	for _, bad := range []string{"sideways", "DESC", "asc,desc", " asc", "hot"} {
		if _, err := NormalizeAdminSort(bad); !errors.Is(err, ErrValidation) {
			t.Fatalf("NormalizeAdminSort(%q) error = %v, want ErrValidation", bad, err)
		}
	}
}

// TestPublicSortValidators 验证公开排序契约与管理员排序契约分离：
// asc/desc/hot 均通过公开校验，管理列表校验只接受 asc/desc。
func TestPublicSortValidators(t *testing.T) {
	for _, raw := range []string{"asc", "desc", "hot"} {
		if !ValidPublicCommentSort(raw) {
			t.Fatalf("ValidPublicCommentSort(%q) = false, want true", raw)
		}
	}
	for _, bad := range []string{"sideways", "DESC", "asc,desc", ""} {
		if ValidPublicCommentSort(bad) {
			t.Fatalf("ValidPublicCommentSort(%q) = true, want false", bad)
		}
	}
	// 管理列表校验绝不接受 hot，避免无关列表被静默当作 asc 处理。
	if ValidCommentSort("hot") {
		t.Fatal("ValidCommentSort(hot) = true, want false")
	}
}

// TestOffsetForPage 验证页码到偏移的推导：第 1 页为 0、普通页为 (page-1)*limit、
// 非法页/非法 limit 不产生负偏移，且超大页码不会溢出。
func TestOffsetForPage(t *testing.T) {
	cases := []struct {
		page  int
		limit int
		want  int
	}{
		{page: 1, limit: 25, want: 0},
		{page: 2, limit: 25, want: 25},
		{page: 3, limit: 10, want: 20},
		{page: 0, limit: 25, want: 0},
		{page: -5, limit: 25, want: 0},
		{page: 2, limit: 0, want: 0},
	}
	for _, tc := range cases {
		if got := OffsetForPage(tc.page, tc.limit); got != tc.want {
			t.Fatalf("OffsetForPage(%d, %d) = %d, want %d", tc.page, tc.limit, got, tc.want)
		}
	}
	// 极大页码不会产生负偏移或 panic。
	max := int(^uint(0) >> 1)
	if got := OffsetForPage(max, 100); got < 0 {
		t.Fatalf("OffsetForPage(max, 100) = %d, want non-negative", got)
	}
	if got := OffsetForPage(2, max); got < 0 {
		t.Fatalf("OffsetForPage(2, max) = %d, want non-negative", got)
	}
}

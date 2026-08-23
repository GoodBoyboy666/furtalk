package comment

import (
	"context"
	"errors"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"

	"gorm.io/gorm"
)

// seedTiedTimestampComments 插入多条同一 created_at 的已发布评论（root），
// keyset 在相同时间戳上必须用 id 决胜；同时插入一条 pending 验证方向过滤。
func seedTiedTimestampComments(t *testing.T, db *gorm.DB) publicTreeFixture {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	userRepo := repository.NewUserRepo(db)
	siteRepo := repository.NewSiteRepo(db)
	threadRepo := repository.NewThreadRepo(db)
	commentRepo := repository.NewCommentRepo(db)

	user := &domain.User{Email: "u@example.com", EmailNormalized: "u@example.com", Nickname: "u", Role: domain.RoleUser, Status: domain.UserStatusActive}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	thread, err := threadRepo.ResolveOrCreate(ctx, site.ID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	fx := publicTreeFixture{SiteID: site.ID, ThreadID: thread.ID, IDs: map[string]int64{}}
	for _, key := range []string{"a", "b", "c", "pending"} {
		status := domain.CommentStatusPublished
		var publishedAt *time.Time
		if key == "pending" {
			status = domain.CommentStatusPending
		} else {
			ts := base
			publishedAt = &ts
		}
		c := &domain.Comment{
			SiteID: site.ID, ThreadID: thread.ID, UserID: user.ID, Depth: 0,
			BodyMarkdown: "body-" + key, Status: status,
			IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: base, UpdatedAt: base, PublishedAt: publishedAt,
		}
		if err := commentRepo.Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", key, err)
		}
		fx.IDs[key] = c.ID
	}
	return fx
}

// TestPublicListSortAscOrdersOldestFirst 验证默认 asc 方向按 (created_at, id)
// 升序返回，且同时间戳按 id 决胜。
func TestPublicListSortAscOrdersOldestFirst(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50, nil)
	if err != nil {
		t.Fatalf("list public asc: %v", err)
	}
	want := []int64{fx.IDs["a"], fx.IDs["b"], fx.IDs["c"]}
	got := publicCommentIDs(view)
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v (asc order with tied timestamps must break by id)", got, want)
		}
	}
}

// TestPublicListSortDescOrdersNewestFirst 验证显式 desc 方向按 (created_at, id)
// 降序返回，且同时间戳按 id 反向决胜；pending 始终隐藏。
func TestPublicListSortDescOrdersNewestFirst(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedTiedTimestampComments(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)

	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "desc", 50, nil)
	if err != nil {
		t.Fatalf("list public desc: %v", err)
	}
	want := []int64{fx.IDs["c"], fx.IDs["b"], fx.IDs["a"]}
	got := publicCommentIDs(view)
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v (desc order with tied timestamps must break by id descending)", got, want)
		}
	}
	for _, c := range view.Comments {
		if c.Status != domain.CommentStatusPublished {
			t.Fatalf("desc list contains non-published comment %d", c.ID)
		}
	}
}

// TestPublicListSortDefaultUsesPolicy 验证 sort 参数缺省时使用实例策略默认方向，
// 显式值只影响本次查询。
func TestPublicListSortDefaultUsesPolicy(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished, depth: 0},
		{key: "b", status: domain.CommentStatusPublished, depth: 0},
		{key: "c", status: domain.CommentStatusPublished, depth: 0},
	})
	svc := &Service{
		txRunner: gormtx.NewRunner(db),
		threads:  repository.NewThreadRepo(db),
		comments: repository.NewCommentRepo(db),
		sites:    repository.NewSiteRepo(db),
		users:    repository.NewUserRepo(db),
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:            domain.CommentModeAuthenticated,
			Moderation:      domain.ModerationDirect,
			UserDeleteMode:  domain.UserDeleteModeSoft,
			MaxReplyDepth:   5,
			CaptchaPolicy:   map[string]bool{},
			GravatarBaseURL: "https://www.gravatar.com/avatar",
			Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
			CommentSort:     string(domain.CommentSortDesc),
		}},
		captcha: &replyCaptchaVerifier{},
		bus:     &recordingEventBus{},
	}

	// 缺省走策略 desc。
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50, nil)
	if err != nil {
		t.Fatalf("list public default: %v", err)
	}
	want := []int64{fx.IDs["c"], fx.IDs["b"], fx.IDs["a"]}
	if got := publicCommentIDs(view); !equalIDs(got, want) {
		t.Fatalf("default ids = %v, want %v (policy default desc)", got, want)
	}
	// 显式 asc 覆盖本次查询。
	view, err = svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "asc", 50, nil)
	if err != nil {
		t.Fatalf("list public asc override: %v", err)
	}
	want = []int64{fx.IDs["a"], fx.IDs["b"], fx.IDs["c"]}
	if got := publicCommentIDs(view); !equalIDs(got, want) {
		t.Fatalf("override ids = %v, want %v", got, want)
	}
}

// TestPublicListSortDescPaginationNoDuplicates 验证 desc 方向多页游标无重复无遗漏。
func TestPublicListSortDescPaginationNoDuplicates(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished, depth: 0},
		{key: "x", status: domain.CommentStatusDeleted, depth: 0},
		{key: "b", status: domain.CommentStatusPublished, depth: 0},
		{key: "c", status: domain.CommentStatusPublished, depth: 0},
		{key: "d", status: domain.CommentStatusPublished, depth: 0},
		{key: "e", status: domain.CommentStatusPublished, depth: 0},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	var all []CommentView
	cursorRaw := ""
	for page := 0; ; page++ {
		view, err := svc.ListPublic(ctx, fx.SiteID, "page-key", cursorRaw, "desc", 2, nil)
		if err != nil {
			t.Fatalf("list public desc page %d: %v", page, err)
		}
		for _, c := range view.Comments {
			if c.Status != domain.CommentStatusPublished {
				t.Fatalf("page %d contains non-published comment %d (%s)", page, c.ID, c.Status)
			}
			all = append(all, c)
		}
		if view.NextCursor == nil {
			break
		}
		cursorRaw = *view.NextCursor
		if page > 10 {
			t.Fatal("desc pagination did not terminate")
		}
	}

	want := []int64{fx.IDs["e"], fx.IDs["d"], fx.IDs["c"], fx.IDs["b"], fx.IDs["a"]}
	got := make([]int64, 0, len(all))
	seen := map[int64]bool{}
	for _, c := range all {
		if seen[c.ID] {
			t.Fatalf("duplicate comment %d across desc pages", c.ID)
		}
		seen[c.ID] = true
		got = append(got, c.ID)
	}
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
}

// TestPublicListSortDescPreservesTreeCompression 验证 desc 方向不改变可见树压缩：
// 隐藏父节点后的可见后代仍连接到最近可见祖先，parent/root 反映可见树。
func TestPublicListSortDescPreservesTreeCompression(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished, depth: 0},
		{key: "b", parent: "a", root: "a", status: domain.CommentStatusDeleted, depth: 1},
		{key: "c", parent: "b", root: "a", status: domain.CommentStatusPublished, depth: 2},
		{key: "d", parent: "a", root: "a", status: domain.CommentStatusPublished, depth: 1},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "desc", 50, nil)
	if err != nil {
		t.Fatalf("list public desc: %v", err)
	}
	// desc 方向：d(最新) 在最前，其后 c，最后 a。
	want := []int64{fx.IDs["d"], fx.IDs["c"], fx.IDs["a"]}
	if got := publicCommentIDs(view); !equalIDs(got, want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	c := publicCommentByID(t, view, fx.IDs["c"])
	if c.ParentID == nil || *c.ParentID != fx.IDs["a"] {
		t.Fatalf("c parent = %v, want a(%d) (compression preserved in desc)", c.ParentID, fx.IDs["a"])
	}
	if c.RootID == nil || *c.RootID != fx.IDs["a"] {
		t.Fatalf("c root = %v, want a(%d)", c.RootID, fx.IDs["a"])
	}
	if c.Depth != 2 {
		t.Fatalf("c depth = %d, want persisted 2", c.Depth)
	}
	d := publicCommentByID(t, view, fx.IDs["d"])
	if d.ParentID == nil || *d.ParentID != fx.IDs["a"] {
		t.Fatalf("d parent = %v, want a(%d)", d.ParentID, fx.IDs["a"])
	}
}

// TestPublicListSortInvalid 验证非法 sort 值返回验证错误。
func TestPublicListSortInvalid(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished, depth: 0},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	for _, bad := range []string{"sideways", "DESC", "asc,desc", " asc"} {
		_, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", bad, 50, nil)
		if !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("sort %q error = %v, want ErrValidation", bad, err)
		}
	}
}

// equalIDs 报告两个 int64 切片逐元素相等。
func equalIDs(a, b []int64) bool {
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

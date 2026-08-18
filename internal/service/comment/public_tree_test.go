package comment

import (
	"context"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/repository"

	"gorm.io/gorm"
)

// treeSeed 描述一条要直接写入的评论层级关系：key 是本地标识，parent/root 是
// 对应父/根评论的 key，空串表示无引用。
type treeSeed struct {
	key    string
	parent string
	root   string
	status domain.CommentStatus
	depth  int
}

// publicTreeFixture 是公开树测试的种子结果。
type publicTreeFixture struct {
	SiteID   int64
	ThreadID int64
	IDs      map[string]int64
}

// seedPublicTreeComments 直接向仓储写入一组显式层级评论，按种子顺序递增
// created_at，返回每个 key 对应的 ID。
func seedPublicTreeComments(t *testing.T, db *gorm.DB, seeds []treeSeed) publicTreeFixture {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	userRepo := repository.NewUserRepo(db)
	siteRepo := repository.NewSiteRepo(db)
	threadRepo := repository.NewThreadRepo(db)
	commentRepo := repository.NewCommentRepo(db)

	users := make([]int64, 0, 3)
	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		u := &domain.User{Email: email, EmailNormalized: email, Nickname: email, Role: domain.RoleUser, Status: domain.UserStatusActive}
		if err := userRepo.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		users = append(users, u.ID)
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
	for i, seed := range seeds {
		var parentID, rootID *int64
		if seed.parent != "" {
			p := fx.IDs[seed.parent]
			parentID = &p
		}
		if seed.root != "" {
			r := fx.IDs[seed.root]
			rootID = &r
		}
		now := base.Add(time.Duration(i) * time.Second)
		var publishedAt *time.Time
		if seed.status == domain.CommentStatusPublished {
			publishedAt = &now
		}
		c := &domain.Comment{
			SiteID: site.ID, ThreadID: thread.ID, UserID: users[i%len(users)],
			ParentID: parentID, RootID: rootID, Depth: seed.depth,
			BodyMarkdown: "body-" + seed.key, Status: seed.status,
			IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: now, UpdatedAt: now, PublishedAt: publishedAt,
		}
		if err := commentRepo.Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", seed.key, err)
		}
		fx.IDs[seed.key] = c.ID
	}
	return fx
}

// publicCommentByID 在公开视图里按 ID 查找评论。
func publicCommentByID(t *testing.T, view *ThreadView, id int64) *CommentView {
	t.Helper()
	for i := range view.Comments {
		if view.Comments[i].ID == id {
			return &view.Comments[i]
		}
	}
	t.Fatalf("comment %d not in public view", id)
	return nil
}

// publicCommentIDs 返回公开视图评论按响应顺序的 ID 列表。
func publicCommentIDs(view *ThreadView) []int64 {
	ids := make([]int64, 0, len(view.Comments))
	for i := range view.Comments {
		ids = append(ids, view.Comments[i].ID)
	}
	return ids
}

// TestPublicListBridgesSingleHiddenParent 验证 AC1：单个软删除节点被跨过，
// 后代连接最近的可见祖先，且持久化关系保持不变。
func TestPublicListBridgesSingleHiddenParent(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished, depth: 0},
		{key: "b", parent: "a", root: "a", status: domain.CommentStatusDeleted, depth: 1},
		{key: "c", parent: "b", root: "a", status: domain.CommentStatusPublished, depth: 2},
		{key: "d", parent: "c", root: "a", status: domain.CommentStatusPublished, depth: 3},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	wantIDs := []int64{fx.IDs["a"], fx.IDs["c"], fx.IDs["d"]}
	gotIDs := publicCommentIDs(view)
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("ids = %v, want %v", gotIDs, wantIDs)
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("ids = %v, want %v", gotIDs, wantIDs)
		}
	}

	a := publicCommentByID(t, view, fx.IDs["a"])
	if a.ParentID != nil || a.RootID != nil {
		t.Fatalf("a parent/root = %v/%v, want nil/nil", a.ParentID, a.RootID)
	}
	c := publicCommentByID(t, view, fx.IDs["c"])
	if c.ParentID == nil || *c.ParentID != fx.IDs["a"] {
		t.Fatalf("c parent = %v, want a(%d)", c.ParentID, fx.IDs["a"])
	}
	if c.RootID == nil || *c.RootID != fx.IDs["a"] {
		t.Fatalf("c root = %v, want a(%d)", c.RootID, fx.IDs["a"])
	}
	if c.Depth != 2 {
		t.Fatalf("c depth = %d, want persisted 2", c.Depth)
	}
	d := publicCommentByID(t, view, fx.IDs["d"])
	if d.ParentID == nil || *d.ParentID != fx.IDs["c"] {
		t.Fatalf("d parent = %v, want c(%d)", d.ParentID, fx.IDs["c"])
	}
	if d.RootID == nil || *d.RootID != fx.IDs["a"] {
		t.Fatalf("d root = %v, want a(%d)", d.RootID, fx.IDs["a"])
	}
	if d.Depth != 3 {
		t.Fatalf("d depth = %d, want persisted 3", d.Depth)
	}

	repo := repository.NewCommentRepo(db)
	stored, err := repo.FindGlobalByID(context.Background(), fx.IDs["c"])
	if err != nil {
		t.Fatalf("find c: %v", err)
	}
	if stored.ParentID == nil || *stored.ParentID != fx.IDs["b"] {
		t.Fatalf("persisted c parent = %v, want still b(%d)", stored.ParentID, fx.IDs["b"])
	}
}

// TestPublicListPromotesHiddenRootChild 验证 AC2：可见根的直接父节点被删除后，
// 该评论成为公开树根且 root_id 为 null，其回复仍挂在它下面。
func TestPublicListPromotesHiddenRootChild(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusDeleted, depth: 0},
		{key: "b", parent: "a", root: "a", status: domain.CommentStatusPublished, depth: 1},
		{key: "c", parent: "b", root: "a", status: domain.CommentStatusPublished, depth: 2},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	wantIDs := []int64{fx.IDs["b"], fx.IDs["c"]}
	gotIDs := publicCommentIDs(view)
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("ids = %v, want %v", gotIDs, wantIDs)
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("ids = %v, want %v", gotIDs, wantIDs)
		}
	}

	b := publicCommentByID(t, view, fx.IDs["b"])
	if b.ParentID != nil || b.RootID != nil {
		t.Fatalf("b parent/root = %v/%v, want nil/nil", b.ParentID, b.RootID)
	}
	if b.Depth != 1 {
		t.Fatalf("b depth = %d, want persisted 1", b.Depth)
	}
	c := publicCommentByID(t, view, fx.IDs["c"])
	if c.ParentID == nil || *c.ParentID != fx.IDs["b"] {
		t.Fatalf("c parent = %v, want b(%d)", c.ParentID, fx.IDs["b"])
	}
	if c.RootID == nil || *c.RootID != fx.IDs["b"] {
		t.Fatalf("c root = %v, want b(%d)", c.RootID, fx.IDs["b"])
	}
}

// TestPublicListBridgesConsecutiveHiddenAncestors 验证 AC3：连续多层不可见祖先
// （deleted、pending、spam）被一次性跨过，后代连接最近可见祖先。
func TestPublicListBridgesConsecutiveHiddenAncestors(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished, depth: 0},
		{key: "b", parent: "a", root: "a", status: domain.CommentStatusPending, depth: 1},
		{key: "c", parent: "b", root: "a", status: domain.CommentStatusSpam, depth: 2},
		{key: "d", parent: "c", root: "a", status: domain.CommentStatusPublished, depth: 3},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	if ids := publicCommentIDs(view); len(ids) != 2 || ids[0] != fx.IDs["a"] || ids[1] != fx.IDs["d"] {
		t.Fatalf("ids = %v, want [a d]", ids)
	}
	d := publicCommentByID(t, view, fx.IDs["d"])
	if d.ParentID == nil || *d.ParentID != fx.IDs["a"] {
		t.Fatalf("d parent = %v, want a(%d)", d.ParentID, fx.IDs["a"])
	}
	if d.RootID == nil || *d.RootID != fx.IDs["a"] {
		t.Fatalf("d root = %v, want a(%d)", d.RootID, fx.IDs["a"])
	}
}

// TestPublicListKeepsSiblingBranchesNested 验证 AC4：同一隐藏节点下的多个可见
// 分支各自保留内部嵌套与服务端顺序，不会全部展平到最外层。
func TestPublicListKeepsSiblingBranchesNested(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusDeleted, depth: 0},
		{key: "b", parent: "a", root: "a", status: domain.CommentStatusPublished, depth: 1},
		{key: "c", parent: "a", root: "a", status: domain.CommentStatusPublished, depth: 1},
		{key: "d", parent: "b", root: "a", status: domain.CommentStatusPublished, depth: 2},
		{key: "e", parent: "c", root: "a", status: domain.CommentStatusPublished, depth: 2},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	ids := publicCommentIDs(view)
	if len(ids) != 4 || ids[0] != fx.IDs["b"] || ids[1] != fx.IDs["c"] || ids[2] != fx.IDs["d"] || ids[3] != fx.IDs["e"] {
		t.Fatalf("ids = %v, want [b c d e]", ids)
	}
	b := publicCommentByID(t, view, fx.IDs["b"])
	c := publicCommentByID(t, view, fx.IDs["c"])
	d := publicCommentByID(t, view, fx.IDs["d"])
	e := publicCommentByID(t, view, fx.IDs["e"])
	if b.ParentID != nil || b.RootID != nil {
		t.Fatalf("b parent/root = %v/%v, want nil/nil", b.ParentID, b.RootID)
	}
	if c.ParentID != nil || c.RootID != nil {
		t.Fatalf("c parent/root = %v/%v, want nil/nil", c.ParentID, c.RootID)
	}
	if d.ParentID == nil || *d.ParentID != fx.IDs["b"] {
		t.Fatalf("d parent = %v, want b(%d)", d.ParentID, fx.IDs["b"])
	}
	if e.ParentID == nil || *e.ParentID != fx.IDs["c"] {
		t.Fatalf("e parent = %v, want c(%d)", e.ParentID, fx.IDs["c"])
	}
	if d.RootID == nil || *d.RootID != fx.IDs["b"] {
		t.Fatalf("d root = %v, want b(%d)", d.RootID, fx.IDs["b"])
	}
	if e.RootID == nil || *e.RootID != fx.IDs["c"] {
		t.Fatalf("e root = %v, want c(%d)", e.RootID, fx.IDs["c"])
	}
}

// TestPublicListPaginationCountsVisibleOnly 验证 AC6：分页只按可见评论计数，
// 隐藏节点不占额度，边界前后无重复无遗漏，next_cursor 取本页最后可见评论。
func TestPublicListPaginationCountsVisibleOnly(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished, depth: 0},
		{key: "x", status: domain.CommentStatusDeleted, depth: 0},
		{key: "b", parent: "a", root: "a", status: domain.CommentStatusPublished, depth: 1},
		{key: "y", parent: "a", root: "a", status: domain.CommentStatusSpam, depth: 1},
		{key: "c", parent: "a", root: "a", status: domain.CommentStatusPublished, depth: 1},
		{key: "z", parent: "a", root: "a", status: domain.CommentStatusPending, depth: 1},
		{key: "d", parent: "a", root: "a", status: domain.CommentStatusPublished, depth: 1},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	var all []CommentView
	cursorRaw := ""
	for page := 0; ; page++ {
		view, err := svc.ListPublic(ctx, fx.SiteID, "page-key", cursorRaw, "", 2)
		if err != nil {
			t.Fatalf("list public page %d: %v", page, err)
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
			t.Fatal("pagination did not terminate")
		}
	}

	want := []int64{fx.IDs["a"], fx.IDs["b"], fx.IDs["c"], fx.IDs["d"]}
	got := make([]int64, 0, len(all))
	seen := map[int64]bool{}
	for _, c := range all {
		if seen[c.ID] {
			t.Fatalf("duplicate comment %d across pages", c.ID)
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

// TestPublicListNeverExposesNonPublished 验证 AC5：公开接口只返回 published，
// 不返回占位正文，软删除内容与作者信息不泄露。
func TestPublicListNeverExposesNonPublished(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedPublicTreeComments(t, db, []treeSeed{
		{key: "a", status: domain.CommentStatusPublished, depth: 0},
		{key: "b", parent: "a", root: "a", status: domain.CommentStatusDeleted, depth: 1},
		{key: "c", parent: "a", root: "a", status: domain.CommentStatusPending, depth: 1},
		{key: "d", parent: "a", root: "a", status: domain.CommentStatusSpam, depth: 1},
	})
	svc := ownerService(db, domain.UserDeleteModeSoft)
	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	if ids := publicCommentIDs(view); len(ids) != 1 || ids[0] != fx.IDs["a"] {
		t.Fatalf("ids = %v, want only [a]", ids)
	}
	for _, c := range view.Comments {
		if c.BodyMarkdown == "（该评论已被删除）" {
			t.Fatalf("public list exposes placeholder body on comment %d", c.ID)
		}
		if c.BodyMarkdown == "body-b" || c.BodyMarkdown == "body-c" || c.BodyMarkdown == "body-d" {
			t.Fatalf("public list exposes hidden body %q", c.BodyMarkdown)
		}
	}
}

// TestPublicListKeepsReplyTargetAfterParentDelete 验证回复目标字段不随展示父节点
// 重映射改写：父评论被软删除后，回复补位到根但仍指向实际被回复的作者。
func TestPublicListKeepsReplyTargetAfterParentDelete(t *testing.T) {
	db := ownerTestDB(t)
	fx := seedReplyFixture(t, db)
	svc := ownerService(db, domain.UserDeleteModeSoft)
	ctx := context.Background()

	reply, err := svc.CreateReplyFirstParty(ctx, fx.UserID, domain.RoleUser, fx.ParentID, "reply body", "", nil, "ua")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}
	if _, err := svc.AdminDelete(ctx, fx.ParentID, false, false); err != nil {
		t.Fatalf("soft delete parent: %v", err)
	}
	view, err := svc.ListPublic(ctx, fx.SiteID, "page-key", "", "", 50)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	got := publicCommentByID(t, view, reply.ID)
	if got.ParentID != nil || got.RootID != nil {
		t.Fatalf("reply parent/root = %v/%v, want nil/nil (promoted to root)", got.ParentID, got.RootID)
	}
	if got.ReplyToUserID == nil || *got.ReplyToUserID != fx.UserID {
		t.Fatalf("reply_to_user_id = %v, want parent author user %d", got.ReplyToUserID, fx.UserID)
	}
	if got.ReplyToNickname == nil || *got.ReplyToNickname != "actor" {
		t.Fatalf("reply_to_nickname = %v, want %q", got.ReplyToNickname, "actor")
	}
	if got.Depth != 1 {
		t.Fatalf("reply depth = %d, want persisted 1", got.Depth)
	}
}

package comment

import (
	"context"
	"errors"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/service/identity"

	"gorm.io/gorm"
)

// closedWidgetFixture 是 widget 创建用例所需的种子数据。
type closedWidgetFixture struct {
	SiteID   int64
	ThreadID int64
	UserID   int64
}

// seedClosedWidgetFixture 插入站点、用户与（默认开启的）线程。
func seedClosedWidgetFixture(t *testing.T, db *gorm.DB) closedWidgetFixture {
	t.Helper()
	ctx := context.Background()

	user := &domain.User{
		Email:           "widget@example.com",
		EmailNormalized: "widget@example.com",
		Nickname:        "widget",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repository.NewUserRepo(db).Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := repository.NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := repository.NewSiteRepo(db).AddOrigin(ctx, site.ID, "https://widget.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	thread, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, site.ID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	return closedWidgetFixture{SiteID: site.ID, ThreadID: thread.ID, UserID: user.ID}
}

// newWidgetService 装配匿名模式的 widget 评论服务。
func newWidgetService(db *gorm.DB, runner TxRunner, bus EventPublisher, verifier CaptchaVerifier) *Service {
	return &Service{
		txRunner: runner,
		threads:  repository.NewThreadRepo(db),
		comments: repository.NewCommentRepo(db),
		sites:    repository.NewSiteRepo(db),
		users:    repository.NewUserRepo(db),
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:          domain.CommentModeAnonymous,
			Moderation:    domain.ModerationDirect,
			MaxReplyDepth: 5,
			CaptchaPolicy: map[string]bool{},
			Privacy:       domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
			CommentSort:   string(domain.CommentSortAsc),
		}},
		captcha: verifier,
		userW: identity.NewService(identity.Dependencies{
			TxRunner: runner,
			Users:    repository.NewUserRepo(db),
		}),
		bus: bus,
		now: func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) },
	}
}

// TestCreateWidgetRejectsClosedThread 证明 widget 根评论在关闭线程上返回
// ErrThreadClosed，且不开启事务、不消耗 CAPTCHA、不发布事件。
func TestCreateWidgetRejectsClosedThread(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedClosedWidgetFixture(t, db)
	threadRepo := repository.NewThreadRepo(db)
	if _, err := threadRepo.UpdateCommentsEnabled(context.Background(), fx.SiteID, fx.ThreadID, false); err != nil {
		t.Fatalf("close thread: %v", err)
	}

	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	verifier := &replyCaptchaVerifier{}
	svc := newWidgetService(db, runner, bus, verifier)

	_, err := svc.Create(context.Background(), CreateInput{
		SiteID:       fx.SiteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "widget@example.com",
		Nickname:     "widget",
		BodyMarkdown: "a root comment",
	})
	if !errors.Is(err, domain.ErrThreadClosed) {
		t.Fatalf("err = %v, want ErrThreadClosed", err)
	}
	if runner.calls != 0 {
		t.Fatalf("transaction calls = %d, want 0 (closed check must precede transaction)", runner.calls)
	}
	if verifier.calls != 0 {
		t.Fatalf("captcha calls = %d, want 0 (closed check must precede CAPTCHA)", verifier.calls)
	}
	if bus.publishes != 0 {
		t.Fatalf("event publishes = %d, want 0", bus.publishes)
	}
}

// TestCreateWidgetOpenThreadSucceeds 证明开启线程上的根评论创建正常。
func TestCreateWidgetOpenThreadSucceeds(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedClosedWidgetFixture(t, db)

	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	verifier := &replyCaptchaVerifier{}
	svc := newWidgetService(db, runner, bus, verifier)

	view, err := svc.Create(context.Background(), CreateInput{
		SiteID:       fx.SiteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "widget@example.com",
		Nickname:     "widget",
		BodyMarkdown: "a root comment",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if view == nil {
		t.Fatal("view = nil, want a created comment")
	}
	if runner.calls != 1 {
		t.Fatalf("transaction calls = %d, want 1", runner.calls)
	}
	if bus.publishes != 1 {
		t.Fatalf("event publishes = %d, want 1 (created only)", bus.publishes)
	}
}

// TestCreateWidgetReplyRejectsClosedThread 证明 widget 回复在关闭线程上同样被拒，
// 且不创建评论、不发布事件。
func TestCreateWidgetReplyRejectsClosedThread(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedReplyFixture(t, db)
	threadRepo := repository.NewThreadRepo(db)
	if _, err := threadRepo.UpdateCommentsEnabled(context.Background(), fx.SiteID, fx.ThreadID, false); err != nil {
		t.Fatalf("close thread: %v", err)
	}

	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	verifier := &replyCaptchaVerifier{}
	svc := newWidgetService(db, runner, bus, verifier)
	parentID := fx.ParentID

	_, err := svc.Create(context.Background(), CreateInput{
		SiteID:       fx.SiteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "widget@example.com",
		Nickname:     "widget",
		ParentID:     &parentID,
		BodyMarkdown: "a widget reply",
	})
	if !errors.Is(err, domain.ErrThreadClosed) {
		t.Fatalf("err = %v, want ErrThreadClosed", err)
	}
	if bus.publishes != 0 {
		t.Fatalf("event publishes = %d, want 0", bus.publishes)
	}
	if _, gerr := repository.NewCommentRepo(db).FindGlobalByID(context.Background(), fx.ParentID+1); !errors.Is(gerr, domain.ErrNotFound) {
		t.Fatalf("reply row exists or unexpected error: %v", gerr)
	}
}

// TestCreateReplyFirstPartyRejectsClosedThread 证明第一方回复在关闭线程上返回
// ErrThreadClosed，且不创建评论、不发布事件。
func TestCreateReplyFirstPartyRejectsClosedThread(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedReplyFixture(t, db)
	threadRepo := repository.NewThreadRepo(db)
	if _, err := threadRepo.UpdateCommentsEnabled(context.Background(), fx.SiteID, fx.ThreadID, false); err != nil {
		t.Fatalf("close thread: %v", err)
	}

	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	verifier := &replyCaptchaVerifier{}
	svc := newReplyService(db, map[string]bool{}, verifier, runner, bus)

	_, err := svc.CreateReplyFirstParty(
		context.Background(),
		fx.UserID,
		domain.RoleUser,
		fx.ParentID,
		"a reply body",
		"",
		nil,
		"test-agent",
	)
	if !errors.Is(err, domain.ErrThreadClosed) {
		t.Fatalf("err = %v, want ErrThreadClosed", err)
	}
	if bus.publishes != 0 {
		t.Fatalf("event publishes = %d, want 0", bus.publishes)
	}
	if _, gerr := repository.NewCommentRepo(db).FindGlobalByID(context.Background(), fx.ParentID+1); !errors.Is(gerr, domain.ErrNotFound) {
		t.Fatalf("reply row exists or unexpected error: %v", gerr)
	}
}

// TestCreateReplyFirstPartyAdminDoesNotBypassClosed 证明管理员身份不绕过线程关闭状态。
func TestCreateReplyFirstPartyAdminDoesNotBypassClosed(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedReplyFixture(t, db)
	threadRepo := repository.NewThreadRepo(db)
	if _, err := threadRepo.UpdateCommentsEnabled(context.Background(), fx.SiteID, fx.ThreadID, false); err != nil {
		t.Fatalf("close thread: %v", err)
	}

	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	verifier := &replyCaptchaVerifier{}
	svc := newReplyService(db, map[string]bool{}, verifier, runner, bus)

	_, err := svc.CreateReplyFirstParty(
		context.Background(),
		fx.UserID,
		domain.RoleAdmin,
		fx.ParentID,
		"a reply body",
		"",
		nil,
		"test-agent",
	)
	if !errors.Is(err, domain.ErrThreadClosed) {
		t.Fatalf("err = %v, want ErrThreadClosed (admin must not bypass)", err)
	}
	if bus.publishes != 0 {
		t.Fatalf("event publishes = %d, want 0", bus.publishes)
	}
}

// TestListPublicMissingThreadIsReadOnlyUntilCommentCreate 证明公开读取缺失页面时
// 返回合成空线程且零写入；首次评论创建才持久化真实线程，后续读取返回该线程与评论。
func TestListPublicMissingThreadIsReadOnlyUntilCommentCreate(t *testing.T) {
	db := newReplyTestDB(t)
	ctx := context.Background()
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	siteRepo := repository.NewSiteRepo(db)
	if err := siteRepo.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := siteRepo.AddOrigin(ctx, site.ID, "https://widget.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	user := &domain.User{
		Email:           "missing-page@example.com",
		EmailNormalized: "missing-page@example.com",
		Nickname:        "reader",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repository.NewUserRepo(db).Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	svc := newWidgetService(db, runner, bus, &replyCaptchaVerifier{})
	threadRepo := repository.NewThreadRepo(db)

	for i := 0; i < 2; i++ {
		view, err := svc.ListPublic(ctx, site.ID, "missing-page", "", "", 50, nil)
		if err != nil {
			t.Fatalf("read %d: %v", i+1, err)
		}
		if view.ID != 0 || !view.CommentsEnabled || len(view.Comments) != 0 || view.NextCursor != nil {
			t.Fatalf("synthetic view = %+v, want ID=0 enabled empty with no cursor", view)
		}
		if _, err := threadRepo.GetBySiteAndKey(ctx, site.ID, "missing-page"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("read %d persisted a thread: %v", i+1, err)
		}
	}

	created, err := svc.Create(ctx, CreateInput{
		SiteID:       site.ID,
		PageKey:      "missing-page",
		Origin:       "https://widget.example.com",
		Email:        user.Email,
		Nickname:     user.Nickname,
		BodyMarkdown: "first comment",
	})
	if err != nil {
		t.Fatalf("create comment: %v", err)
	}
	thread, err := threadRepo.GetBySiteAndKey(ctx, site.ID, "missing-page")
	if err != nil {
		t.Fatalf("get persisted thread: %v", err)
	}
	if thread.ID <= 0 || created.ThreadID != thread.ID {
		t.Fatalf("created thread/comment ids = %d/%d, want matching positive ids", thread.ID, created.ThreadID)
	}
	var count int64
	if err := db.Table("threads").Where("site_id = ? AND page_key = ?", site.ID, "missing-page").Count(&count).Error; err != nil {
		t.Fatalf("count persisted threads: %v", err)
	}
	if count != 1 {
		t.Fatalf("persisted thread count = %d, want 1", count)
	}

	view, err := svc.ListPublic(ctx, site.ID, "missing-page", "", "", 50, nil)
	if err != nil {
		t.Fatalf("read persisted thread: %v", err)
	}
	if view.ID != thread.ID || len(view.Comments) != 1 || view.Comments[0].ID != created.ID {
		t.Fatalf("persisted view = %+v, want thread %d and comment %d", view, thread.ID, created.ID)
	}
}

// TestListPublicClosedStillReadable 证明关闭线程仍返回历史公开评论且携带开关状态。
func TestListPublicClosedStillReadable(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedReplyFixture(t, db)
	threadRepo := repository.NewThreadRepo(db)
	if _, err := threadRepo.UpdateCommentsEnabled(context.Background(), fx.SiteID, fx.ThreadID, false); err != nil {
		t.Fatalf("close thread: %v", err)
	}
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	svc := newWidgetService(db, runner, bus, &replyCaptchaVerifier{})

	view, err := svc.ListPublic(context.Background(), fx.SiteID, "page-key", "", "", 50, nil)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	if view.CommentsEnabled {
		t.Fatal("comments_enabled = true, want false for closed thread")
	}
	if len(view.Comments) != 1 {
		t.Fatalf("comments = %d, want 1 (history must remain readable)", len(view.Comments))
	}
}

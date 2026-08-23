package comment

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	pkgcaptcha "furtalk/internal/platform/captcha"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newReplyTestDB 打开临时 SQLite 数据库并迁移评论相关表。
func newReplyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "reply-captcha-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.Site{}, &model.SiteOrigin{}, &model.Thread{}, &model.Comment{}, &model.CommentLike{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// recordingTxRunner 记录事务开启次数并转发给内层运行器。
type recordingTxRunner struct {
	inner TxRunner
	calls int
}

func (r *recordingTxRunner) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	r.calls++
	return r.inner.RunInTx(ctx, fn)
}

// recordingEventBus 记录评论事件发布次数。
type recordingEventBus struct {
	publishes int
}

func (b *recordingEventBus) Publish(domain.CommentEvent) error {
	b.publishes++
	return nil
}

// replyCaptchaVerifier 记录调用参数并返回固定的 platform CAPTCHA 错误。
type replyCaptchaVerifier struct {
	err    error
	calls  int
	action string
	token  string
}

func (v *replyCaptchaVerifier) Verify(ctx context.Context, action, token string) error {
	v.calls++
	v.action = action
	v.token = token
	return v.err
}

// replyTestFixture 是创建第一方回复所需的种子数据。
type replyTestFixture struct {
	SiteID   int64
	ThreadID int64
	UserID   int64
	ParentID int64
}

// seedReplyFixture 插入站点、用户、线程与父评论。
func seedReplyFixture(t *testing.T, db *gorm.DB) replyTestFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

	user := &domain.User{
		Email:           "actor@example.com",
		EmailNormalized: "actor@example.com",
		Nickname:        "actor",
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
	parent := &domain.Comment{
		SiteID:       site.ID,
		ThreadID:     thread.ID,
		UserID:       user.ID,
		Depth:        0,
		BodyMarkdown: "parent comment",
		Status:       domain.CommentStatusPublished,
		IPMode:       domain.PrivacyModeNone,
		UAMode:       domain.PrivacyModeNone,
		CreatedAt:    now,
		UpdatedAt:    now,
		PublishedAt:  &now,
	}
	if err := repository.NewCommentRepo(db).Create(ctx, parent); err != nil {
		t.Fatalf("create parent comment: %v", err)
	}
	return replyTestFixture{SiteID: site.ID, ThreadID: thread.ID, UserID: user.ID, ParentID: parent.ID}
}

// newReplyService 装配带真实仓储与记录型事务/事件总线的评论服务。
func newReplyService(db *gorm.DB, policy map[string]bool, verifier CaptchaVerifier, runner *recordingTxRunner, bus *recordingEventBus) *Service {
	return &Service{
		txRunner: runner,
		threads:  repository.NewThreadRepo(db),
		comments: repository.NewCommentRepo(db),
		sites:    repository.NewSiteRepo(db),
		users:    repository.NewUserRepo(db),
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:          domain.CommentModeAuthenticated,
			Moderation:    domain.ModerationDirect,
			MaxReplyDepth: 5,
			CaptchaPolicy: policy,
			Privacy:       domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		}},
		captcha: verifier,
		bus:     bus,
		now:     func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) },
	}
}

// replyPolicyWithComment 返回开启 comment action 的策略。
func replyPolicyWithComment() map[string]bool {
	return map[string]bool{CommentAction: true}
}

func TestCreateReplyFirstPartyCaptchaMatrix(t *testing.T) {
	tests := []struct {
		name       string
		policy     map[string]bool
		verifier   CaptchaVerifier
		token      string
		wantErr    error
		wantAction string
		wantTx     int
		wantEvents int
	}{
		{
			name:       "policy off stays compatible",
			policy:     map[string]bool{},
			verifier:   &replyCaptchaVerifier{},
			token:      "",
			wantErr:    nil,
			wantTx:     1,
			wantEvents: 1,
		},
		{
			name:     "policy on blank token requires captcha",
			policy:   replyPolicyWithComment(),
			verifier: &replyCaptchaVerifier{},
			token:    "",
			wantErr:  domain.ErrCaptchaRequired,
			wantTx:   0,
		},
		{
			name:     "verifier failure maps to ErrCaptchaFailed",
			policy:   replyPolicyWithComment(),
			verifier: &replyCaptchaVerifier{err: pkgcaptcha.ErrFailed},
			token:    "token",
			wantErr:  domain.ErrCaptchaFailed,
			wantTx:   0,
		},
		{
			name:     "provider unavailable maps to ErrCaptchaUnavailable",
			policy:   replyPolicyWithComment(),
			verifier: &replyCaptchaVerifier{err: pkgcaptcha.ErrUnavailable},
			token:    "token",
			wantErr:  domain.ErrCaptchaUnavailable,
			wantTx:   0,
		},
		{
			name:     "nil verifier fails closed",
			policy:   replyPolicyWithComment(),
			verifier: nil,
			token:    "token",
			wantErr:  domain.ErrCaptchaUnavailable,
			wantTx:   0,
		},
		{
			name:       "verifier success proceeds to create reply",
			policy:     replyPolicyWithComment(),
			verifier:   &replyCaptchaVerifier{},
			token:      "token",
			wantErr:    nil,
			wantAction: CommentAction,
			wantTx:     1,
			wantEvents: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newReplyTestDB(t)
			fx := seedReplyFixture(t, db)
			runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
			bus := &recordingEventBus{}
			verifier := tt.verifier
			svc := newReplyService(db, tt.policy, verifier, runner, bus)

			view, err := svc.CreateReplyFirstParty(
				context.Background(),
				fx.UserID,
				domain.RoleUser,
				fx.ParentID,
				"a reply body",
				tt.token,
				nil,
				"test-agent",
			)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && view == nil {
				t.Fatal("view = nil, want a created reply")
			}
			if runner.calls != tt.wantTx {
				t.Fatalf("transaction calls = %d, want %d", runner.calls, tt.wantTx)
			}
			if bus.publishes != tt.wantEvents {
				t.Fatalf("event publishes = %d, want %d", bus.publishes, tt.wantEvents)
			}
			if tt.wantAction != "" {
				rec, ok := verifier.(*replyCaptchaVerifier)
				if !ok {
					t.Fatal("verifier is not replyCaptchaVerifier")
				}
				if rec.calls != 1 {
					t.Fatalf("verifier calls = %d, want 1", rec.calls)
				}
				if rec.action != tt.wantAction {
					t.Fatalf("verifier action = %q, want %q", rec.action, tt.wantAction)
				}
				if rec.token != tt.token {
					t.Fatalf("verifier token = %q, want %q", rec.token, tt.token)
				}
			}
		})
	}
}

// TestCreateReplyFirstPartyCaptchaFailureWritesNothing 证明 CAPTCHA 失败时
// 不创建评论行、不发布事件，回复仍不存在。
func TestCreateReplyFirstPartyCaptchaFailureWritesNothing(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedReplyFixture(t, db)
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	verifier := &replyCaptchaVerifier{err: pkgcaptcha.ErrFailed}
	svc := newReplyService(db, replyPolicyWithComment(), verifier, runner, bus)

	_, err := svc.CreateReplyFirstParty(
		context.Background(),
		fx.UserID,
		domain.RoleUser,
		fx.ParentID,
		"a reply body",
		"token",
		nil,
		"test-agent",
	)
	if !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("err = %v, want ErrCaptchaFailed", err)
	}
	if runner.calls != 0 {
		t.Fatalf("transaction calls = %d, want 0", runner.calls)
	}
	if bus.publishes != 0 {
		t.Fatalf("event publishes = %d, want 0", bus.publishes)
	}
	if _, gerr := repository.NewCommentRepo(db).FindGlobalByID(context.Background(), fx.ParentID+1); !errors.Is(gerr, domain.ErrNotFound) {
		t.Fatalf("reply row exists or unexpected error: %v", gerr)
	}
}

// TestCreateReplyFirstPartyGatesBeforeParentLookup 证明 CAPTCHA 门禁在父评论
// 查询之前执行：父评论 ID 不存在时返回的是 CAPTCHA 错误而非 ErrParentNotFound。
func TestCreateReplyFirstPartyGatesBeforeParentLookup(t *testing.T) {
	db := newReplyTestDB(t)
	_ = seedReplyFixture(t, db)
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	verifier := &replyCaptchaVerifier{err: pkgcaptcha.ErrFailed}
	svc := newReplyService(db, replyPolicyWithComment(), verifier, runner, bus)

	_, err := svc.CreateReplyFirstParty(
		context.Background(),
		1,
		domain.RoleUser,
		999999,
		"a reply body",
		"token",
		nil,
		"test-agent",
	)
	if !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("err = %v, want ErrCaptchaFailed (gate must run before parent lookup)", err)
	}
}

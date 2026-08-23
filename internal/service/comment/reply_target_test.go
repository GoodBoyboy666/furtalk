package comment

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"

	"gorm.io/gorm"
)

// newReplyTargetTestDB 打开临时 SQLite 数据库并迁移评论相关表。
func newReplyTargetTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "reply-target-test.db")
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

// replyTargetFixture 插入父评论作者与回复作者、站点与父评论。
type replyTargetFixture struct {
	SiteID      int64
	ThreadID    int64
	ParentUser  int64
	ReplyUser   int64
	ParentID    int64
	ParentNick  string
	ReplyNick   string
	ParentEmail string
	ReplyEmail  string
}

func seedReplyTargetFixture(t *testing.T, db *gorm.DB) replyTargetFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)

	parentUser := &domain.User{
		Email: "parent@example.com", EmailNormalized: "parent@example.com",
		Nickname: "parent", Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	replyUser := &domain.User{
		Email: "reply@example.com", EmailNormalized: "reply@example.com",
		Nickname: "reply", Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	if err := repository.NewUserRepo(db).Create(ctx, parentUser); err != nil {
		t.Fatalf("create parent user: %v", err)
	}
	if err := repository.NewUserRepo(db).Create(ctx, replyUser); err != nil {
		t.Fatalf("create reply user: %v", err)
	}
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := repository.NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := repository.NewSiteRepo(db).AddOrigin(ctx, site.ID, "https://example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	thread, err := repository.NewThreadRepo(db).ResolveOrCreate(ctx, site.ID, "page-key", nil, nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	parent := &domain.Comment{
		SiteID: site.ID, ThreadID: thread.ID, UserID: parentUser.ID, Depth: 0,
		BodyMarkdown: "parent", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
		CreatedAt: now, UpdatedAt: now, PublishedAt: &now,
	}
	if err := repository.NewCommentRepo(db).Create(ctx, parent); err != nil {
		t.Fatalf("create parent comment: %v", err)
	}
	return replyTargetFixture{
		SiteID: site.ID, ThreadID: thread.ID,
		ParentUser: parentUser.ID, ReplyUser: replyUser.ID, ParentID: parent.ID,
		ParentNick: "parent", ReplyNick: "reply",
		ParentEmail: "parent@example.com", ReplyEmail: "reply@example.com",
	}
}

// replyTargetService 装配带真实仓储与认证模式策略的评论服务。
func replyTargetService(db *gorm.DB) *Service {
	return &Service{
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
			CommentSort:     string(domain.CommentSortAsc),
		}},
		captcha: &replyCaptchaVerifier{},
		bus:     &recordingEventBus{},
		now:     func() time.Time { return time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC) },
	}
}

// TestCreateReplyFirstPartyPersistsReplyTo 验证第一方回复创建时把父评论作者
// 保存为 reply_to_user_id，创建返回的视图携带目标用户 id 与当前昵称。
func TestCreateReplyFirstPartyPersistsReplyTo(t *testing.T) {
	db := newReplyTargetTestDB(t)
	fx := seedReplyTargetFixture(t, db)
	svc := replyTargetService(db)
	ctx := context.Background()

	view, err := svc.CreateReplyFirstParty(ctx, fx.ReplyUser, domain.RoleUser, fx.ParentID, "reply body", "", nil, "")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}
	if view.ReplyToUserID == nil || *view.ReplyToUserID != fx.ParentUser {
		t.Fatalf("reply_to_user_id = %v, want parent user %d", view.ReplyToUserID, fx.ParentUser)
	}
	if view.ReplyToNickname == nil || *view.ReplyToNickname != fx.ParentNick {
		t.Fatalf("reply_to_nickname = %v, want %q", view.ReplyToNickname, fx.ParentNick)
	}

	stored, err := svc.comments.FindGlobalByID(ctx, view.ID)
	if err != nil {
		t.Fatalf("read stored reply: %v", err)
	}
	if stored.ReplyToUserID == nil || *stored.ReplyToUserID != fx.ParentUser {
		t.Fatalf("stored reply_to_user_id = %v, want parent user %d", stored.ReplyToUserID, fx.ParentUser)
	}
}

// TestWidgetCreateReplyPersistsReplyTo 验证 widget 创建回复（Create 路径）
// 同样持久化 reply_to_user_id。
func TestWidgetCreateReplyPersistsReplyTo(t *testing.T) {
	db := newReplyTargetTestDB(t)
	fx := seedReplyTargetFixture(t, db)
	svc := &Service{
		txRunner: gormtx.NewRunner(db),
		threads:  repository.NewThreadRepo(db),
		comments: repository.NewCommentRepo(db),
		sites:    repository.NewSiteRepo(db),
		users:    repository.NewUserRepo(db),
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:            domain.CommentModeAnonymous,
			Moderation:      domain.ModerationDirect,
			UserDeleteMode:  domain.UserDeleteModeSoft,
			MaxReplyDepth:   5,
			CaptchaPolicy:   map[string]bool{},
			GravatarBaseURL: "https://www.gravatar.com/avatar",
			Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
			CommentSort:     string(domain.CommentSortAsc),
		}},
		captcha: &replyCaptchaVerifier{},
		userW: identity.NewService(identity.Dependencies{
			TxRunner: gormtx.NewRunner(db),
			Users:    repository.NewUserRepo(db),
		}),
		bus: &recordingEventBus{},
		now: func() time.Time { return time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC) },
	}
	ctx := context.Background()

	view, err := svc.Create(ctx, CreateInput{
		SiteID:       fx.SiteID,
		PageKey:      "page-key",
		ParentID:     &fx.ParentID,
		BodyMarkdown: "widget reply",
		Origin:       "https://example.com",
		Email:        fx.ReplyEmail,
		Nickname:     fx.ReplyNick,
	})
	if err != nil {
		t.Fatalf("widget create reply: %v", err)
	}
	if view.ReplyToUserID == nil || *view.ReplyToUserID != fx.ParentUser {
		t.Fatalf("reply_to_user_id = %v, want parent user %d", view.ReplyToUserID, fx.ParentUser)
	}
	if view.ReplyToNickname == nil || *view.ReplyToNickname != fx.ParentNick {
		t.Fatalf("reply_to_nickname = %v, want %q", view.ReplyToNickname, fx.ParentNick)
	}
}

// TestPublicListCarriesReplyToNickname 验证公开列表返回回复目标用户 id 与当前昵称。
func TestPublicListCarriesReplyToNickname(t *testing.T) {
	db := newReplyTargetTestDB(t)
	fx := seedReplyTargetFixture(t, db)
	svc := replyTargetService(db)
	ctx := context.Background()

	if _, err := svc.CreateReplyFirstParty(ctx, fx.ReplyUser, domain.RoleUser, fx.ParentID, "reply body", "", nil, ""); err != nil {
		t.Fatalf("create reply: %v", err)
	}
	view, err := svc.ListPublic(ctx, fx.SiteID, "page-key", "", "", 50, nil)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	if len(view.Comments) != 2 {
		t.Fatalf("comments = %d, want 2", len(view.Comments))
	}
	var reply *CommentView
	for i := range view.Comments {
		if view.Comments[i].ParentID != nil {
			reply = &view.Comments[i]
		}
	}
	if reply == nil {
		t.Fatal("reply comment missing from public list")
	}
	if reply.ReplyToUserID == nil || *reply.ReplyToUserID != fx.ParentUser {
		t.Fatalf("reply_to_user_id = %v, want parent user %d", reply.ReplyToUserID, fx.ParentUser)
	}
	if reply.ReplyToNickname == nil || *reply.ReplyToNickname != fx.ParentNick {
		t.Fatalf("reply_to_nickname = %v, want %q", reply.ReplyToNickname, fx.ParentNick)
	}
	if reply.AuthorAvatarURL == "" {
		t.Fatal("reply avatar must be derived")
	}
}

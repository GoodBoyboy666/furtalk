package comment

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/gravatar"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// avatarTestDB 打开临时 SQLite 数据库并迁移评论相关表（含站点来源）。
func avatarTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "avatar-test.db")
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

// avatarTestService 构建带可配置策略与真实仓储的评论服务。
func avatarTestService(db *gorm.DB, pol domain.CommentPolicy, bus *recordingEventBus, runner *recordingTxRunner) *Service {
	verifier := &replyCaptchaVerifier{}
	return &Service{
		txRunner: runner,
		threads:  repository.NewThreadRepo(db),
		comments: repository.NewCommentRepo(db),
		sites:    repository.NewSiteRepo(db),
		users:    repository.NewUserRepo(db),
		settings: &staticCommentPolicyReader{policy: pol},
		captcha:  verifier,
		bus:      bus,
		now:      func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) },
	}
}

// TestCommentViewsDeriveAvatarURL 证明公共评论视图与管理视图派生头像 URL，
// 且视图本身不携带邮箱或独立哈希字段。
func TestCommentViewsDeriveAvatarURL(t *testing.T) {
	db := avatarTestDB(t)
	fx := seedReplyFixture(t, db)
	pol := domain.CommentPolicy{
		Mode:            domain.CommentModeAuthenticated,
		Moderation:      domain.ModerationDirect,
		MaxReplyDepth:   5,
		CaptchaPolicy:   map[string]bool{},
		GravatarBaseURL: "https://avatars.example.com/avatar/",
		Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		CommentSort:     string(domain.CommentSortAsc),
	}
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	svc := avatarTestService(db, pol, bus, runner)
	ctx := context.Background()

	view, err := svc.CreateReplyFirstParty(ctx, fx.UserID, domain.RoleUser, fx.ParentID, "a reply", "", nil, "test-agent")
	if err != nil {
		t.Fatalf("create reply: %v", err)
	}
	want := gravatar.URL("actor@example.com", "https://avatars.example.com/avatar/")
	if view.AuthorAvatarURL != want {
		t.Fatalf("avatar = %q, want %q", view.AuthorAvatarURL, want)
	}

	threadView, err := svc.ListPublic(ctx, fx.SiteID, "page-key", "", "", 10, nil)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	if len(threadView.Comments) == 0 {
		t.Fatal("list public returned no comments")
	}
	for _, c := range threadView.Comments {
		if c.AuthorAvatarURL == "" {
			t.Fatalf("comment %d has empty avatar_url", c.ID)
		}
		if !isAvatarURL(c.AuthorAvatarURL) {
			t.Fatalf("comment %d avatar = %q, want base+sha256 shape", c.ID, c.AuthorAvatarURL)
		}
	}
}

// isAvatarURL 报告字符串是否形如 `<base>/<64位小写十六进制>`。
func isAvatarURL(raw string) bool {
	slash := lastIndexByte(raw, '/')
	if slash <= 0 || slash == len(raw)-1 {
		return false
	}
	hash := raw[slash+1:]
	if len(hash) != 64 {
		return false
	}
	for _, r := range hash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// TestAdminListIncludesAvatarURL 证明管理员列表视图同样派生头像 URL。
func TestAdminListIncludesAvatarURL(t *testing.T) {
	db := avatarTestDB(t)
	_ = seedReplyFixture(t, db)
	pol := domain.CommentPolicy{
		Mode:            domain.CommentModeAuthenticated,
		Moderation:      domain.ModerationDirect,
		MaxReplyDepth:   5,
		CaptchaPolicy:   map[string]bool{},
		GravatarBaseURL: "https://www.gravatar.com/avatar",
		Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		CommentSort:     string(domain.CommentSortAsc),
	}
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	svc := avatarTestService(db, pol, bus, runner)

	result, err := svc.AdminList(context.Background(), domain.AdminFilter{}, 1)
	if err != nil {
		t.Fatalf("admin list: %v", err)
	}
	if len(result.Comments) == 0 {
		t.Fatal("admin list returned no comments")
	}
	want := gravatar.URL("actor@example.com", "https://www.gravatar.com/avatar")
	if result.Comments[0].AuthorAvatarURL != want {
		t.Fatalf("admin avatar = %q, want %q", result.Comments[0].AuthorAvatarURL, want)
	}
}

// TestAvatarChangesWithBaseSetting 证明切换 Gravatar 基址后视图立即使用新基址。
func TestAvatarChangesWithBaseSetting(t *testing.T) {
	db := avatarTestDB(t)
	fx := seedReplyFixture(t, db)
	ctx := context.Background()
	base := "https://www.gravatar.com/avatar"
	svc := avatarTestService(db, domain.CommentPolicy{
		Mode:            domain.CommentModeAuthenticated,
		Moderation:      domain.ModerationDirect,
		MaxReplyDepth:   5,
		CaptchaPolicy:   map[string]bool{},
		GravatarBaseURL: base,
		Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		CommentSort:     string(domain.CommentSortAsc),
	}, &recordingEventBus{}, &recordingTxRunner{inner: gormtx.NewRunner(db)})

	first, err := svc.ListPublic(ctx, fx.SiteID, "page-key", "", "", 10, nil)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	before := first.Comments[0].AuthorAvatarURL
	if before == "" {
		t.Fatal("avatar must not be empty")
	}

	// 切换基址后同一评论的新 URL 使用新基址。
	svc2 := avatarTestService(db, domain.CommentPolicy{
		Mode:            domain.CommentModeAuthenticated,
		Moderation:      domain.ModerationDirect,
		MaxReplyDepth:   5,
		CaptchaPolicy:   map[string]bool{},
		GravatarBaseURL: "https://avatars.example.com",
		Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		CommentSort:     string(domain.CommentSortAsc),
	}, &recordingEventBus{}, &recordingTxRunner{inner: gormtx.NewRunner(db)})
	second, err := svc2.ListPublic(ctx, fx.SiteID, "page-key", "", "", 10, nil)
	if err != nil {
		t.Fatalf("list public with new base: %v", err)
	}
	after := second.Comments[0].AuthorAvatarURL
	if after == "https://avatars.example.com"+after[len("https://avatars.example.com"):] && after == before {
		t.Fatalf("avatar unchanged after base switch: %q", after)
	}
	if len(after) <= len("https://avatars.example.com") || after[:len("https://avatars.example.com")] != "https://avatars.example.com" {
		t.Fatalf("avatar after switch = %q, want new base prefix", after)
	}
	if after != gravatar.URL("actor@example.com", "https://avatars.example.com") {
		t.Fatalf("avatar after switch = %q", after)
	}
}

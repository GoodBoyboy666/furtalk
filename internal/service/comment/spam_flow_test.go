package comment

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/service/identity"

	"gorm.io/gorm"
)

// countingSpamReader 记录 EnabledSpamProviders 调用次数，用于管理员绕过断言。
type countingSpamReader struct {
	calls     int
	providers []SpamProviderConfig
}

func (c *countingSpamReader) EnabledSpamProviders(context.Context) ([]SpamProviderConfig, error) {
	c.calls++
	return c.providers, nil
}

// spamFlowFixture 是垃圾检测流程测试的种子数据。
type spamFlowFixture struct {
	SiteID   int64
	UserID   int64
	AdminID  int64
	ThreadID int64
}

// seedSpamFlowFixture 插入普通用户、管理员、站点（含 Origin）与线程。
func seedSpamFlowFixture(t *testing.T, db *gorm.DB) spamFlowFixture {
	t.Helper()
	ctx := context.Background()
	users := repository.NewUserRepo(db)
	sites := repository.NewSiteRepo(db)
	threads := repository.NewThreadRepo(db)

	user := &domain.User{
		Email: "user@example.com", EmailNormalized: "user@example.com",
		Nickname: "user", Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	admin := &domain.User{
		Email: "admin@example.com", EmailNormalized: "admin@example.com",
		Nickname: "admin", Role: domain.RoleAdmin, Status: domain.UserStatusActive,
	}
	if err := users.Create(ctx, admin); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := sites.Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := sites.AddOrigin(ctx, site.ID, "https://widget.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	thread, err := threads.ResolveOrCreate(ctx, site.ID, "page-key", strPtr("https://example.com/post"), nil)
	if err != nil {
		t.Fatalf("resolve thread: %v", err)
	}
	return spamFlowFixture{SiteID: site.ID, UserID: user.ID, AdminID: admin.ID, ThreadID: thread.ID}
}

// writeSpamKeywords 写入临时词库文件。
func writeSpamKeywords(t *testing.T, keywords string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spam-words.txt")
	if err := os.WriteFile(path, []byte(keywords), 0o644); err != nil {
		t.Fatalf("write keywords: %v", err)
	}
	return path
}

// newSpamFlowWidgetService 装配匿名模式下带垃圾检测网关的 widget 服务。
func newSpamFlowWidgetService(t *testing.T, db *gorm.DB, fx spamFlowFixture, reader *countingSpamReader) (*Service, *recordingTxRunner) {
	t.Helper()
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	pol := domain.CommentPolicy{
		Mode: domain.CommentModeAnonymous, Moderation: domain.ModerationDirect,
		MaxReplyDepth: 5, Epoch: 1,
		CaptchaPolicy: map[string]bool{},
		Privacy:       domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		CommentSort:   string(domain.CommentSortAsc),
	}
	svc := NewService(Dependencies{
		TxRunner: runner,
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    repository.NewSiteRepo(db),
		Users:    repository.NewUserRepo(db),
		Settings: &staticCommentPolicyReader{policy: pol},
		UserW: identity.NewService(identity.Dependencies{
			TxRunner: gormtx.NewRunner(db),
			Users:    repository.NewUserRepo(db),
		}),
		Captcha: &countingCaptchaVerifier{},
		Authz:   adminAuthzResolver{users: repository.NewUserRepo(db)},
		Spam:    NewSpamGateway(reader, nil),
		Bus:     &recordingEventBus{},
	})
	return svc, runner
}

// widgetCredentialFor 构造绑定指定用户的 widget 凭证。
func widgetCredentialFor(userID, siteID, epoch int64) WidgetCredential {
	return &widgetCredential{userID: userID, siteID: siteID, epoch: epoch, expiresAt: time.Now().Add(time.Hour)}
}

// TestWidgetCreateSpamHit 验证普通用户正文命中本地词库时评论以 pending/spam 状态落库，
// published_at 为 nil。
func TestWidgetCreateSpamHit(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedSpamFlowFixture(t, db)
	reader := &countingSpamReader{providers: []SpamProviderConfig{
		{ProviderKey: "spam.local", Enabled: true, Configured: true, FilePath: writeSpamKeywords(t, "广告\n"), Action: "pending"},
	}}
	svc, _ := newSpamFlowWidgetService(t, db, fx, reader)

	created, err := svc.Create(context.Background(), CreateInput{
		SiteID: fx.SiteID, PageKey: "page-key", Origin: "https://widget.example.com",
		Email: "user@example.com", Nickname: "user",
		BodyMarkdown: "这里有广告", IP: net.ParseIP("1.2.3.4"), UA: "UA",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Status != domain.CommentStatusPending {
		t.Fatalf("status = %s, want pending", created.Status)
	}
	if created.PublishedAt != nil {
		t.Fatalf("published_at = %v, want nil for pending", created.PublishedAt)
	}
	if reader.calls == 0 {
		t.Fatal("spam gateway reader was not invoked for ordinary user")
	}

	// spam action 命中时状态为 spam。
	reader2 := &countingSpamReader{providers: []SpamProviderConfig{
		{ProviderKey: "spam.local", Enabled: true, Configured: true, FilePath: writeSpamKeywords(t, "广告\n"), Action: "spam"},
	}}
	svc2, _ := newSpamFlowWidgetService(t, db, fx, reader2)
	created2, err := svc2.Create(context.Background(), CreateInput{
		SiteID: fx.SiteID, PageKey: "page-key", Origin: "https://widget.example.com",
		Email: "user@example.com", Nickname: "user", BodyMarkdown: "有广告",
	})
	if err != nil {
		t.Fatalf("create spam hit: %v", err)
	}
	if created2.Status != domain.CommentStatusSpam {
		t.Fatalf("status = %s, want spam", created2.Status)
	}
	if created2.PublishedAt != nil {
		t.Fatalf("published_at = %v, want nil for spam", created2.PublishedAt)
	}
}

// TestWidgetCreateSpamPass 验证无命中时沿用全局策略（direct → published）。
func TestWidgetCreateSpamPass(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedSpamFlowFixture(t, db)
	reader := &countingSpamReader{providers: []SpamProviderConfig{
		{ProviderKey: "spam.local", Enabled: true, Configured: true, FilePath: writeSpamKeywords(t, "广告\n"), Action: "spam"},
	}}
	svc, _ := newSpamFlowWidgetService(t, db, fx, reader)

	created, err := svc.Create(context.Background(), CreateInput{
		SiteID: fx.SiteID, PageKey: "page-key", Origin: "https://widget.example.com",
		Email: "user@example.com", Nickname: "user", BodyMarkdown: "普通内容",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Status != domain.CommentStatusPublished {
		t.Fatalf("status = %s, want published", created.Status)
	}
	if created.PublishedAt == nil {
		t.Fatal("published_at = nil, want set for published")
	}
}

// TestWidgetCreateAdminBypass 验证管理员作者的 widget 根评论/回复不调用检测器。
func TestWidgetCreateAdminBypass(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedSpamFlowFixture(t, db)
	reader := &countingSpamReader{providers: []SpamProviderConfig{
		{ProviderKey: "spam.local", Enabled: true, Configured: true, FilePath: writeSpamKeywords(t, "广告\n"), Action: "spam"},
	}}
	svc, _ := newSpamFlowWidgetService(t, db, fx, reader)

	cred := widgetCredentialFor(fx.AdminID, fx.SiteID, 1)
	created, err := svc.Create(context.Background(), CreateInput{
		SiteID: fx.SiteID, PageKey: "page-key", Origin: "https://widget.example.com",
		Email: "admin@example.com", Nickname: "admin",
		BodyMarkdown: "有广告", Credential: cred,
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if created.Status != domain.CommentStatusPublished {
		t.Fatalf("status = %s, want published (admin bypass)", created.Status)
	}
	if reader.calls != 0 {
		t.Fatalf("spam reader calls = %d, want 0 for admin", reader.calls)
	}
}

// TestFirstPartyReplySpam 验证第一方回复普通用户执行检测、管理员绕过。
func TestFirstPartyReplySpam(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedSpamFlowFixture(t, db)
	comments := repository.NewCommentRepo(db)

	root := &domain.Comment{
		SiteID: fx.SiteID, ThreadID: fx.ThreadID, UserID: fx.UserID,
		BodyMarkdown: "root", Status: domain.CommentStatusPublished,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		PublishedAt: ptrTime(time.Now().UTC()),
	}
	if err := comments.Create(context.Background(), root); err != nil {
		t.Fatalf("create root: %v", err)
	}

	// 普通用户回复命中词库 → pending。
	reader := &countingSpamReader{providers: []SpamProviderConfig{
		{ProviderKey: "spam.local", Enabled: true, Configured: true, FilePath: writeSpamKeywords(t, "广告\n"), Action: "pending"},
	}}
	pol := domain.CommentPolicy{
		Mode: domain.CommentModeAuthenticated, Moderation: domain.ModerationDirect,
		MaxReplyDepth: 5, CaptchaPolicy: map[string]bool{},
		Privacy:     domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		CommentSort: string(domain.CommentSortAsc),
	}
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	svc := NewService(Dependencies{
		TxRunner: runner,
		Threads:  repository.NewThreadRepo(db),
		Comments: comments,
		Sites:    repository.NewSiteRepo(db),
		Users:    repository.NewUserRepo(db),
		Settings: &staticCommentPolicyReader{policy: pol},
		UserW: identity.NewService(identity.Dependencies{
			TxRunner: gormtx.NewRunner(db), Users: repository.NewUserRepo(db),
		}),
		Captcha: &countingCaptchaVerifier{},
		Authz:   adminAuthzResolver{users: repository.NewUserRepo(db)},
		Spam:    NewSpamGateway(reader, nil),
		Bus:     &recordingEventBus{},
	})
	reply, err := svc.CreateReplyFirstParty(context.Background(), fx.UserID, domain.RoleUser, root.ID, "回复有广告", "", nil, "")
	if err != nil {
		t.Fatalf("first-party reply: %v", err)
	}
	if reply.Status != domain.CommentStatusPending {
		t.Fatalf("reply status = %s, want pending", reply.Status)
	}

	// 管理员回复 → 绕过检测，直接发布。
	reader2 := &countingSpamReader{providers: []SpamProviderConfig{
		{ProviderKey: "spam.local", Enabled: true, Configured: true, FilePath: writeSpamKeywords(t, "广告\n"), Action: "spam"},
	}}
	svc2 := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Threads:  repository.NewThreadRepo(db),
		Comments: comments,
		Sites:    repository.NewSiteRepo(db),
		Users:    repository.NewUserRepo(db),
		Settings: &staticCommentPolicyReader{policy: pol},
		UserW: identity.NewService(identity.Dependencies{
			TxRunner: gormtx.NewRunner(db), Users: repository.NewUserRepo(db),
		}),
		Captcha: &countingCaptchaVerifier{},
		Authz:   adminAuthzResolver{users: repository.NewUserRepo(db)},
		Spam:    NewSpamGateway(reader2, nil),
		Bus:     &recordingEventBus{},
	})
	adminReply, err := svc2.CreateReplyFirstParty(context.Background(), fx.AdminID, domain.RoleAdmin, root.ID, "管理员回复有广告", "", nil, "")
	if err != nil {
		t.Fatalf("admin first-party reply: %v", err)
	}
	if adminReply.Status != domain.CommentStatusPublished {
		t.Fatalf("admin reply status = %s, want published", adminReply.Status)
	}
	if reader2.calls != 0 {
		t.Fatalf("spam reader calls = %d, want 0 for admin reply", reader2.calls)
	}
}

// TestWidgetCreateNoProviders 验证未配置垃圾检测渠道时行为与现有版本一致（direct → published）。
func TestWidgetCreateNoProviders(t *testing.T) {
	db := newReplyTestDB(t)
	fx := seedSpamFlowFixture(t, db)
	reader := &countingSpamReader{}
	svc, _ := newSpamFlowWidgetService(t, db, fx, reader)

	created, err := svc.Create(context.Background(), CreateInput{
		SiteID: fx.SiteID, PageKey: "page-key", Origin: "https://widget.example.com",
		Email: "user@example.com", Nickname: "user", BodyMarkdown: "普通内容",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Status != domain.CommentStatusPublished {
		t.Fatalf("status = %s, want published", created.Status)
	}
}

func ptrTime(v time.Time) *time.Time { return &v }

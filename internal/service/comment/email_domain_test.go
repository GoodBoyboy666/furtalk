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

// widgetDomainTestSigner 签发固定 widget token 的替身。
type widgetDomainTestSigner struct{}

func (widgetDomainTestSigner) SignWidget(userID, siteID int64, kind, epoch string) (string, error) {
	return "widget-token", nil
}

func (widgetDomainTestSigner) Lifetime() time.Duration { return time.Hour }

// widgetDomainTestVerifier 恒通过的 CAPTCHA 验证器替身。
type widgetDomainTestVerifier struct{}

func (widgetDomainTestVerifier) Verify(context.Context, string, string) error { return nil }

// seedWidgetDomainSite 插入一个带允许来源的活跃站点。
func seedWidgetDomainSite(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	ctx := context.Background()
	site := &domain.Site{Name: "Widget Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := repository.NewSiteRepo(db).Create(ctx, site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := repository.NewSiteRepo(db).AddOrigin(ctx, site.ID, "https://widget.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	return site.ID
}

// widgetDomainCommentService 装配匿名评论创建用例所需的评论服务与真实用户仓储。
func widgetDomainCommentService(t *testing.T, db *gorm.DB, pol domain.CommentPolicy) *Service {
	t.Helper()
	userW := identity.NewService(identity.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
	})
	return NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    repository.NewSiteRepo(db),
		Users:    repository.NewUserRepo(db),
		Settings: &staticCommentPolicyReader{policy: pol},
		UserW:    userW,
		Captcha:  widgetDomainTestVerifier{},
		Signer:   widgetDomainTestSigner{},
	})
}

// TestCreateAnonymousRejectsDisallowedDomain 证明匿名评论创建对未知邮箱的域名被
// 名单拒绝时在用户写入之前返回 ErrEmailDomainNotAllowed，不创建用户、不创建评论。
func TestCreateAnonymousRejectsDisallowedDomain(t *testing.T) {
	db := newReplyTestDB(t)
	siteID := seedWidgetDomainSite(t, db)
	svc := widgetDomainCommentService(t, db, domain.CommentPolicy{
		Mode:                 domain.CommentModeAnonymous,
		PublicRegistration:   true,
		CaptchaPolicy:        map[string]bool{},
		EmailDomainBlacklist: []string{"blocked.com"},
		Privacy:              domain.PrivacyPolicy{IPMode: "none", UAMode: "none"},
	})

	_, err := svc.Create(context.Background(), CreateInput{
		SiteID:       siteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "new@blocked.com",
		Nickname:     "visitor",
		BodyMarkdown: "a comment",
	})
	if !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("err = %v, want ErrEmailDomainNotAllowed", err)
	}
	if _, ferr := repository.NewUserRepo(db).FindByEmailNormalized(context.Background(), "new@blocked.com"); !errors.Is(ferr, domain.ErrNotFound) {
		t.Fatalf("user must not be created: %v", ferr)
	}
}

// TestCreateAnonymousAllowsWhitelistedDomain 证明白名单命中的未知邮箱照常创建
// 普通用户并发布评论；已存在的用户即使域名当前被禁止仍可发布评论。
func TestCreateAnonymousAllowsWhitelistedDomain(t *testing.T) {
	db := newReplyTestDB(t)
	siteID := seedWidgetDomainSite(t, db)
	ctx := context.Background()
	svc := widgetDomainCommentService(t, db, domain.CommentPolicy{
		Mode:                 domain.CommentModeAnonymous,
		PublicRegistration:   true,
		CaptchaPolicy:        map[string]bool{},
		EmailDomainWhitelist: []string{"ok.com"},
		EmailDomainBlacklist: []string{"blocked.com"},
		Privacy:              domain.PrivacyPolicy{IPMode: "none", UAMode: "none"},
	})

	view, err := svc.Create(ctx, CreateInput{
		SiteID:       siteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "new@ok.com",
		Nickname:     "visitor",
		BodyMarkdown: "a comment",
	})
	if err != nil {
		t.Fatalf("allowed create error = %v, want nil", err)
	}
	if view == nil || view.UserID == 0 {
		t.Fatalf("view = %+v, want a created comment with author", view)
	}

	// 已存在用户不受名单限制。
	existing := &domain.User{
		Email:           "old@blocked.com",
		EmailNormalized: "old@blocked.com",
		Nickname:        "old",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := repository.NewUserRepo(db).Create(ctx, existing); err != nil {
		t.Fatalf("create existing user: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{
		SiteID:       siteID,
		PageKey:      "page-key",
		Origin:       "https://widget.example.com",
		Email:        "old@blocked.com",
		Nickname:     "old",
		BodyMarkdown: "a comment",
	}); err != nil {
		t.Fatalf("existing user create error = %v, want nil", err)
	}
}

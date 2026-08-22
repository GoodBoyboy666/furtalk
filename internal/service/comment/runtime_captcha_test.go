package comment

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/repository"

	"gorm.io/gorm"
)

// staticCaptchaProviderReader 返回固定的 CAPTCHA provider 配置或错误。
type staticCaptchaProviderReader struct {
	cfg *CaptchaConfig
	err error
}

func (r staticCaptchaProviderReader) SelectedCaptcha(context.Context) (*CaptchaConfig, error) {
	return r.cfg, r.err
}

// seedRuntimeConfigSite 插入一个活跃站点并返回其 id。
func seedRuntimeConfigSite(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	site := &domain.Site{Name: "Site", CanonicalURL: "https://example.com", Status: domain.SiteStatusActive}
	if err := repository.NewSiteRepo(db).Create(context.Background(), site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	return site.ID
}

func TestBuildRuntimeCaptcha(t *testing.T) {
	t.Parallel()

	capCfg := &CaptchaConfig{Provider: "cap", SiteKey: "cap-site", Endpoint: "https://cap.example.com"}
	recaptchaCfg := &CaptchaConfig{Provider: "recaptcha", SiteKey: "rc-site"}

	t.Run("action disabled", func(t *testing.T) {
		rc := buildRuntimeCaptcha(map[string]bool{}, nil)
		if rc == nil || rc.Comment == nil {
			t.Fatalf("projection = %+v, want comment key present", rc)
		}
		if rc.Comment.Required {
			t.Fatalf("required = %+v, want false", rc)
		}
	})

	t.Run("required action with cap provider include widget endpoint", func(t *testing.T) {
		policy := map[string]bool{CommentAction: true}
		rc := buildRuntimeCaptcha(policy, capCfg)
		if rc.Comment.Required != true || rc.Comment.Provider != "cap" || rc.Comment.SiteKey != "cap-site" {
			t.Fatalf("comment projection = %+v", rc.Comment)
		}
		if rc.Comment.APIEndpoint != "https://cap.example.com/cap-site/" {
			t.Fatalf("comment api_endpoint = %q, want derived widget endpoint", rc.Comment.APIEndpoint)
		}
	})

	t.Run("non-cap provider omits api endpoint", func(t *testing.T) {
		rc := buildRuntimeCaptcha(map[string]bool{CommentAction: true}, recaptchaCfg)
		if rc.Comment.Required != true || rc.Comment.Provider != "recaptcha" || rc.Comment.SiteKey != "rc-site" {
			t.Fatalf("comment projection = %+v", rc.Comment)
		}
		if rc.Comment.APIEndpoint != "" {
			t.Fatalf("api_endpoint = %q, want empty for non-cap", rc.Comment.APIEndpoint)
		}
	})

	t.Run("required action without provider marks required only", func(t *testing.T) {
		rc := buildRuntimeCaptcha(map[string]bool{CommentAction: true}, nil)
		if !rc.Comment.Required {
			t.Fatalf("required = false, want true (fail-closed render hint)")
		}
		if rc.Comment.Provider != "" || rc.Comment.SiteKey != "" || rc.Comment.APIEndpoint != "" {
			t.Fatalf("projection = %+v, want no provider details when unconfigured", rc.Comment)
		}
	})
}

func TestRuntimeConfigIncludesActionCaptchaProjections(t *testing.T) {
	db := newReplyTestDB(t)
	siteID := seedRuntimeConfigSite(t, db)
	svc := &Service{
		sites: repository.NewSiteRepo(db),
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:           domain.CommentModeAuthenticated,
			Moderation:     domain.ModerationDirect,
			UserDeleteMode: domain.UserDeleteModeSoft,
			MaxReplyDepth:  5,
			CaptchaPolicy:  map[string]bool{CommentAction: true},
			CommentSort:    string(domain.CommentSortAsc),
		}},
		providers: staticCaptchaProviderReader{cfg: &CaptchaConfig{Provider: "cap", SiteKey: "cap-site", Endpoint: "https://cap.example.com"}},
	}

	rc, err := svc.RuntimeConfig(context.Background(), siteID)
	if err != nil {
		t.Fatalf("runtime config: %v", err)
	}
	if rc == nil || rc.Captcha == nil || rc.Captcha.Comment == nil {
		t.Fatalf("captcha projection missing: %+v", rc)
	}
	if !rc.Captcha.Comment.Required || rc.Captcha.Comment.Provider != "cap" || rc.Captcha.Comment.APIEndpoint != "https://cap.example.com/cap-site/" {
		t.Fatalf("comment projection = %+v", rc.Captcha.Comment)
	}
}

func TestRuntimeConfigKeepsDisabledActions(t *testing.T) {
	db := newReplyTestDB(t)
	siteID := seedRuntimeConfigSite(t, db)
	svc := &Service{
		sites: repository.NewSiteRepo(db),
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode:          domain.CommentModeAnonymous,
			Moderation:    domain.ModerationDirect,
			CaptchaPolicy: map[string]bool{CommentAction: true},
			CommentSort:   string(domain.CommentSortDesc),
		}},
		providers: staticCaptchaProviderReader{cfg: &CaptchaConfig{Provider: "turnstile", SiteKey: "ts-site"}},
	}

	rc, err := svc.RuntimeConfig(context.Background(), siteID)
	if err != nil {
		t.Fatalf("runtime config: %v", err)
	}
	if rc.Captcha.Comment.Required != true || rc.Captcha.Comment.Provider != "turnstile" {
		t.Fatalf("comment projection = %+v", rc.Captcha.Comment)
	}
}

// TestRuntimeConfigIncludesCommentSort 验证运行时配置携带实例默认排序方向，
// 且不依赖 CAPTCHA provider 是否存在。
func TestRuntimeConfigIncludesCommentSort(t *testing.T) {
	db := newReplyTestDB(t)
	siteID := seedRuntimeConfigSite(t, db)
	for _, tt := range []struct {
		name string
		sort string
	}{
		{name: "asc default", sort: string(domain.CommentSortAsc)},
		{name: "desc configured", sort: string(domain.CommentSortDesc)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{
				sites: repository.NewSiteRepo(db),
				settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
					Mode:           domain.CommentModeAnonymous,
					Moderation:     domain.ModerationDirect,
					UserDeleteMode: domain.UserDeleteModeSoft,
					MaxReplyDepth:  5,
					CaptchaPolicy:  map[string]bool{},
					CommentSort:    tt.sort,
				}},
				providers: staticCaptchaProviderReader{},
			}
			rc, err := svc.RuntimeConfig(context.Background(), siteID)
			if err != nil {
				t.Fatalf("runtime config: %v", err)
			}
			if rc.CommentSort != tt.sort {
				t.Fatalf("comment_sort = %q, want %q", rc.CommentSort, tt.sort)
			}
		})
	}
}

// TestRuntimeConfigIncludesEmojiCatalogURL 验证运行时配置携带可选的
// emoji_catalog_url 投影，空值保持空串且不依赖 CAPTCHA provider。
func TestRuntimeConfigIncludesEmojiCatalogURL(t *testing.T) {
	db := newReplyTestDB(t)
	siteID := seedRuntimeConfigSite(t, db)
	for _, tt := range []struct {
		name string
		url  string
	}{
		{name: "unconfigured", url: ""},
		{name: "configured", url: "https://cdn.example/emoji.json"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{
				sites: repository.NewSiteRepo(db),
				settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
					Mode:            domain.CommentModeAnonymous,
					Moderation:      domain.ModerationDirect,
					UserDeleteMode:  domain.UserDeleteModeSoft,
					MaxReplyDepth:   5,
					CaptchaPolicy:   map[string]bool{},
					CommentSort:     string(domain.CommentSortAsc),
					EmojiCatalogURL: tt.url,
				}},
				providers: staticCaptchaProviderReader{},
			}
			rc, err := svc.RuntimeConfig(context.Background(), siteID)
			if err != nil {
				t.Fatalf("runtime config: %v", err)
			}
			if rc.EmojiCatalogURL != tt.url {
				t.Fatalf("emoji_catalog_url = %q, want %q", rc.EmojiCatalogURL, tt.url)
			}
		})
	}
}

func TestAuthorizationContext(t *testing.T) {
	db := newReplyTestDB(t)
	siteID := seedRuntimeConfigSite(t, db)
	siteRepo := repository.NewSiteRepo(db)
	if _, err := siteRepo.AddOrigin(context.Background(), siteID, "https://embed.example.com"); err != nil {
		t.Fatalf("add origin: %v", err)
	}
	svc := &Service{
		sites:    siteRepo,
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{Mode: domain.CommentModeAuthenticated}},
	}

	view, err := svc.AuthorizationContext(context.Background(), siteID, domain.RoleAdmin, "https://embed.example.com")
	if err != nil {
		t.Fatalf("authorization context: %v", err)
	}
	if view.SiteID != siteID || view.SiteName != "Site" || view.Origin != "https://embed.example.com" {
		t.Fatalf("view = %+v, want site id/name and exact origin", view)
	}

	t.Run("anonymous mode ordinary user rejects", func(t *testing.T) {
		anonymous := &Service{
			sites:    siteRepo,
			settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{Mode: domain.CommentModeAnonymous}},
		}
		if _, err := anonymous.AuthorizationContext(context.Background(), siteID, domain.RoleUser, "https://embed.example.com"); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("err = %v, want ErrForbidden", err)
		}
	})

	t.Run("unlisted origin rejects", func(t *testing.T) {
		if _, err := svc.AuthorizationContext(context.Background(), siteID, domain.RoleAdmin, "https://other.example.com"); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("err = %v, want ErrForbidden", err)
		}
	})

	t.Run("missing site rejects", func(t *testing.T) {
		if _, err := svc.AuthorizationContext(context.Background(), 999999, domain.RoleAdmin, "https://embed.example.com"); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("err = %v, want ErrForbidden", err)
		}
	})

	t.Run("inactive site rejects", func(t *testing.T) {
		inactive := &domain.Site{Name: "Inactive", CanonicalURL: "https://inactive.example.com", Status: domain.SiteStatusDisabled}
		if err := siteRepo.Create(context.Background(), inactive); err != nil {
			t.Fatalf("create inactive site: %v", err)
		}
		if _, err := svc.AuthorizationContext(context.Background(), inactive.ID, domain.RoleAdmin, "https://embed.example.com"); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("err = %v, want ErrForbidden", err)
		}
	})
}

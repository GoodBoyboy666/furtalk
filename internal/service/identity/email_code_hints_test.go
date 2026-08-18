package identity

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"

	"gorm.io/gorm"
)

// emailCodeLoginHintsFixture 装配使用真实仓储与内存缓存的登录服务。
func emailCodeLoginHintsFixture(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()
	db := newCaptchaLoginDB(t)
	svc := captchaLoginService(t, db, map[string]bool{}, &recordingCaptchaVerifier{})
	return svc, db
}

// TestEmailCodeLoginNewUserUsesDefaultProfile 证明验证码登录新建用户不再接受
// nickname/website_url 提示，一律使用邮箱派生的默认昵称且不带网站。
func TestEmailCodeLoginNewUserUsesDefaultProfile(t *testing.T) {
	svc, _ := emailCodeLoginHintsFixture(t)
	seedEmailCode(t, svc, "new@example.com", "123456")

	session, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{
		Email: "new@example.com",
		Code:  "123456",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if session == nil {
		t.Fatal("session = nil")
	}
	user, err := svc.users.FindByEmailNormalized(context.Background(), "new@example.com")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if user.Nickname != "new" {
		t.Fatalf("nickname = %q, want email-derived default", user.Nickname)
	}
	if user.WebsiteURL != nil {
		t.Fatalf("website = %v, want nil for new code-login user", user.WebsiteURL)
	}
}

// TestEmailCodeLoginHintsKeepRegistrationRules 证明注册门禁不受影响：
// 域名被拒时即使携带提示也不创建用户。
func TestEmailCodeLoginHintsKeepRegistrationRules(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := NewService(Dependencies{
		TxRunner:      gormtx.NewRunner(db),
		Users:         repository.NewUserRepo(db),
		Cache:         cache.NewMemory(10000),
		Policy:        configurableEmailPolicy{blacklist: []string{"blocked.com"}},
		CaptchaPolicy: staticCaptchaPolicy{map[string]bool{}},
		Signer:        loginTestSigner{lifetime: 7 * 24 * 60 * 60},
	})
	seedEmailCode(t, svc, "new@blocked.com", "123456")

	_, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{
		Email: "new@blocked.com",
		Code:  "123456",
	})
	if !errors.Is(err, domain.ErrEmailDomainNotAllowed) {
		t.Fatalf("err = %v, want ErrEmailDomainNotAllowed", err)
	}
	if _, ferr := svc.users.FindByEmailNormalized(context.Background(), "new@blocked.com"); !errors.Is(ferr, domain.ErrNotFound) {
		t.Fatalf("user must not be created: %v", ferr)
	}
}

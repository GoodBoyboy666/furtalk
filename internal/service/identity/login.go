package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/onetime"
	"furtalk/internal/platform/value"
)

// Session 成功的第一方登录结果。
type Session struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

// EmailCodeStore 带用途前缀的临时邮箱验证码存取边界。
type EmailCodeStore interface {
	SetEmailCode(ctx context.Context, purpose, normalizedEmail, digest string, ttl time.Duration) error
	DeleteEmailCode(ctx context.Context, purpose, normalizedEmail string) error
	// AtomicVerifyEmailCode 原子验证并消费验证码：摘要匹配返回 true；不匹配、
	// 缺失、过期或达到失败上限返回 false。错误提交的失败次数由后端原子递增。
	AtomicVerifyEmailCode(ctx context.Context, purpose, normalizedEmail, submittedHash string, maxAttempts int) (bool, error)
}

// cacheEmailCodeStore 基于缓存存储实现带用途前缀的邮箱验证码存取。
type cacheEmailCodeStore struct {
	store   cache.Store
	onetime *onetime.Store
}

func emailCodeKey(purpose, normalizedEmail string) string {
	return "email-code:" + purpose + ":" + normalizedEmail
}

// SetEmailCode issues or replaces an expiring one-time digest.
func (a cacheEmailCodeStore) SetEmailCode(ctx context.Context, purpose, normalizedEmail, digest string, ttl time.Duration) error {
	key := emailCodeKey(purpose, normalizedEmail)
	if a.onetime != nil {
		return a.onetime.Issue(ctx, key, digest, ttl)
	}
	// Narrow test doubles may intentionally provide only the generic cache
	// contract. They can exercise gates and mail rendering, but cannot verify.
	return a.store.Set(ctx, key, digest, ttl)
}

// DeleteEmailCode 从缓存删除邮箱验证码记录。
func (a cacheEmailCodeStore) DeleteEmailCode(ctx context.Context, purpose, normalizedEmail string) error {
	if a.onetime != nil {
		return a.onetime.Delete(ctx, emailCodeKey(purpose, normalizedEmail))
	}
	return a.store.Delete(ctx, emailCodeKey(purpose, normalizedEmail))
}

// AtomicVerifyEmailCode 原子验证并消费邮箱验证码记录。
func (a cacheEmailCodeStore) AtomicVerifyEmailCode(ctx context.Context, purpose, normalizedEmail, submittedHash string, maxAttempts int) (bool, error) {
	if a.onetime == nil {
		// A narrow business fake may support issuance/gates but not verification.
		// Production composition rejects such a backend when constructing onetime.
		return false, nil
	}
	result, err := a.onetime.VerifyAndConsume(ctx, emailCodeKey(purpose, normalizedEmail), submittedHash, maxAttempts)
	if err != nil {
		return false, err
	}
	return result == onetime.Consumed, nil
}

// SendEmailCode 校验邮箱、执行 CAPTCHA 策略、保存验证码哈希并投递验证码邮件。
// 未知邮箱的域名必须通过名单策略，否则在写验证码缓存或发送邮件前拒绝。
func (s *Service) SendEmailCode(ctx context.Context, rawEmail, captchaToken string) error {
	_, normalized, err := value.NormalizeEmail(rawEmail)
	if err != nil {
		return domain.ErrValidation
	}
	if err := s.checkCaptcha(ctx, EmailCodeAction, captchaToken); err != nil {
		return err
	}
	if s.mailer == nil {
		return domain.ErrMailUnavailable
	}
	// 未知邮箱才需要域名校验；已存在用户的发送行为保持不变。
	_, err = s.users.FindByEmailNormalized(ctx, normalized)
	if errors.Is(err, domain.ErrNotFound) {
		if err := s.checkEmailDomainAllowed(ctx, normalized); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	code, err := generateCode(emailCodeLength)
	if err != nil {
		return err
	}
	if err := s.emailCodes.SetEmailCode(ctx, emailCodePurpose, normalized, cryptox.SHA256Hex([]byte(code)), s.codeTTL); err != nil {
		return err
	}
	msg, err := renderEmailCodeMessage(s.templates, normalized, code, s.codeTTL)
	if err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "email code render failed", logging.Error(err))
		return domain.ErrMailUnavailable
	}
	if err := s.mailer.Send(ctx, msg); err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "email code delivery failed", logging.Error(err))
		return domain.ErrMailUnavailable
	}
	return nil
}

// EmailCodeLoginInput 邮箱验证码登录的输入。
type EmailCodeLoginInput struct {
	Email        string
	Code         string
	CaptchaToken string
}

// LoginWithEmailCode 校验 CAPTCHA 后原子消费一次性验证码并登录。
// 未知邮箱在允许公开注册时自动注册普通用户。
func (s *Service) LoginWithEmailCode(ctx context.Context, input EmailCodeLoginInput) (*Session, error) {
	_, normalized, err := value.NormalizeEmail(input.Email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if err := s.checkCaptcha(ctx, EmailCodeLoginAction, input.CaptchaToken); err != nil {
		return nil, err
	}
	// 原子消费：错误验证码的失败次数由后端在单个原子操作内递增，
	// 正确验证码在并发下只能成功消费一次。缺失/过期/达到上限映射为通用凭据错误。
	consumed, err := s.emailCodes.AtomicVerifyEmailCode(ctx, emailCodePurpose, normalized, cryptox.SHA256Hex([]byte(input.Code)), s.maxAttempts)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, domain.ErrInvalidCredentials
	}

	user, err := s.users.FindByEmailNormalized(ctx, normalized)
	if errors.Is(err, domain.ErrNotFound) {
		return s.registerOnCodeLogin(ctx, normalized)
	}
	if err != nil {
		return nil, err
	}
	// 先完成登录门禁（账户状态、评论模式、签发与 CSRF），只有门禁成功后
	// 才把既存未验证邮箱标记为已验证，避免仅凭验证码消费就写入验证状态。
	session, err := s.completeLogin(ctx, user)
	if err != nil {
		return nil, err
	}
	if user.EmailVerifiedAt == nil {
		now := s.now().UTC().Truncate(time.Microsecond)
		if _, err := s.users.MarkEmailVerified(ctx, user.ID, now); err != nil {
			return nil, err
		}
	}
	return session, nil
}

// registerOnCodeLogin 在验证码登录命中未知邮箱且允许公开注册时创建用户。
// 自动注册前再次校验域名，域名名单在注册阶段同样生效。
func (s *Service) registerOnCodeLogin(ctx context.Context, normalized string) (*Session, error) {
	public, _, err := s.policy.Policy(ctx)
	if err != nil {
		return nil, err
	}
	if !public {
		return nil, domain.ErrInvalidCredentials
	}
	if err := s.checkEmailDomainAllowed(ctx, normalized); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	user := &domain.User{
		Email:           normalized,
		EmailNormalized: normalized,
		Nickname:        defaultNickname(normalized),
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	return s.completeLogin(ctx, user)
}

func (s *Service) completeLogin(ctx context.Context, user *domain.User) (*Session, error) {
	if user.Status != domain.UserStatusActive {
		return nil, domain.ErrDisabled
	}
	_, mode, err := s.policy.Policy(ctx)
	if err != nil {
		return nil, err
	}
	if !firstPartyAllowed(mode, user.Role) {
		return nil, domain.ErrInvalidCredentials
	}
	token, err := s.signer.SignFirstParty(user.ID, user.SessionVersion)
	if err != nil {
		return nil, err
	}
	csrfToken, err := cryptox.RandomToken(32)
	if err != nil {
		return nil, err
	}
	return &Session{
		Token:     token,
		CSRFToken: csrfToken,
		ExpiresAt: s.now().UTC().Add(s.signer.Lifetime()),
	}, nil
}

// Logout 清除 FP Cookie。服务端不保存会话，也无黑名单。
func (s *Service) Logout(ctx context.Context) error {
	return nil
}

// generateCode 生成 length 位纯数字验证码。
func generateCode(length int) (string, error) {
	const digits = "0123456789"
	buf := make([]byte, length)
	for i := 0; i < length; {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("generate email code: %w", err)
		}
		if b[0] < 250 {
			buf[i] = digits[int(b[0]%10)]
			i++
		}
	}
	return string(buf), nil
}

// renderEmailCodeMessage 渲染验证码邮件的主题、纯文本正文与模板化 HTML 正文。
// HTML 正文由模板渲染器生成，失败时返回错误，由调用方按邮件服务不可用处理。
func renderEmailCodeMessage(templates mailer.TemplateRenderer, to, code string, ttl time.Duration) (mailer.Message, error) {
	minutes := int(ttl / time.Minute)
	html, err := templates.LoginCode(mailer.LoginCodeData{
		Code:             code,
		ExpiresInMinutes: minutes,
	})
	if err != nil {
		return mailer.Message{}, err
	}
	return mailer.Message{
		To:       to,
		Subject:  "您的 Furtalk 登录验证码",
		TextBody: fmt.Sprintf("您的 Furtalk 登录验证码是：%s。\n\n验证码 %d 分钟内有效。如非本人操作，可忽略此邮件。", code, minutes),
		HTMLBody: html,
	}, nil
}

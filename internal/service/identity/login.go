package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/value"
)

// Session 成功的第一方登录结果。
type Session struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

// EmailCodeRecord 临时的邮箱验证码记录，JSON 形态与缓存层的记录一致。
type EmailCodeRecord = cache.EmailCodeRecord

// EmailCodeStore 带用途前缀的临时邮箱验证码存取边界。
type EmailCodeStore interface {
	SetEmailCode(ctx context.Context, purpose, normalizedEmail string, record EmailCodeRecord, ttl time.Duration) error
	GetEmailCode(ctx context.Context, purpose, normalizedEmail string) (*EmailCodeRecord, error)
	DeleteEmailCode(ctx context.Context, purpose, normalizedEmail string) error
	// AtomicVerifyEmailCode 原子验证并消费验证码记录：摘要匹配返回 true 且记录
	// 已删除；不匹配、缺失、过期或达到失败上限返回 false。错误提交的失败次数
	// 由后端在单个原子操作内递增，不依赖调用方的读-改-写。
	AtomicVerifyEmailCode(ctx context.Context, purpose, normalizedEmail, submittedHash string, maxAttempts int) (bool, error)
}

// EphemeralStore is retained as the legacy narrow contract for callers that
// provide one-off challenge stores. Production identity flows use the bounded
// cache.Namespace adapters instead.
type EphemeralStore interface {
	Set(ctx context.Context, key string, value any, ttl time.Duration) error
	AtomicConsume(ctx context.Context, key string) (string, error)
}

// cacheEmailCodeStore 基于缓存存储实现带用途前缀的邮箱验证码存取。
type cacheEmailCodeStore struct {
	store cache.Store
}

func emailCodeKey(purpose, normalizedEmail string) string {
	return "email-code:" + purpose + ":" + normalizedEmail
}

// SetEmailCode 在缓存中写入邮箱验证码记录。
func (a cacheEmailCodeStore) SetEmailCode(ctx context.Context, purpose, normalizedEmail string, record EmailCodeRecord, ttl time.Duration) error {
	return a.store.Set(ctx, emailCodeKey(purpose, normalizedEmail), record, ttl)
}

// GetEmailCode 从缓存读取邮箱验证码记录。
func (a cacheEmailCodeStore) GetEmailCode(ctx context.Context, purpose, normalizedEmail string) (*EmailCodeRecord, error) {
	var record EmailCodeRecord
	err := a.store.Get(ctx, emailCodeKey(purpose, normalizedEmail), &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// DeleteEmailCode 从缓存删除邮箱验证码记录。
func (a cacheEmailCodeStore) DeleteEmailCode(ctx context.Context, purpose, normalizedEmail string) error {
	return a.store.Delete(ctx, emailCodeKey(purpose, normalizedEmail))
}

// AtomicVerifyEmailCode 原子验证并消费邮箱验证码记录。
// 后端实现 AtomicEmailCodeVerifier 时使用其原子边界；否则回退到
// 读-改-写路径（仅供不具备原子性的测试替身使用）。
func (a cacheEmailCodeStore) AtomicVerifyEmailCode(ctx context.Context, purpose, normalizedEmail, submittedHash string, maxAttempts int) (bool, error) {
	key := emailCodeKey(purpose, normalizedEmail)
	if verifier, ok := a.store.(cache.AtomicEmailCodeVerifier); ok {
		result, err := verifier.AtomicEmailCodeVerify(ctx, key, submittedHash, maxAttempts)
		if err != nil {
			return false, err
		}
		return result == cache.EmailCodeConsumed, nil
	}
	return a.verifyEmailCodeRMW(ctx, key, submittedHash, maxAttempts)
}

// verifyEmailCodeRMW 以非原子的读-改-写实现验证码校验，保持与原子路径一致的语义。
// 仅被不支持原子边界的测试替身走到；生产后端（内存/Redis）都实现原子边界。
func (a cacheEmailCodeStore) verifyEmailCodeRMW(ctx context.Context, key, submittedHash string, maxAttempts int) (bool, error) {
	var record EmailCodeRecord
	if err := a.store.Get(ctx, key, &record); err != nil {
		return false, nil
	}
	now := time.Now()
	if now.After(record.ExpiresAt) || record.Attempts >= maxAttempts {
		_ = a.store.Delete(ctx, key)
		return false, nil
	}
	if subtle.ConstantTimeCompare([]byte(record.Hash), []byte(submittedHash)) == 1 {
		_ = a.store.Delete(ctx, key)
		return true, nil
	}
	record.Attempts++
	if record.Attempts >= maxAttempts {
		_ = a.store.Delete(ctx, key)
		return false, nil
	}
	remaining := time.Until(record.ExpiresAt)
	if remaining <= 0 {
		_ = a.store.Delete(ctx, key)
		return false, nil
	}
	_ = a.store.Set(ctx, key, record, remaining)
	return false, nil
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
	record := EmailCodeRecord{
		Hash:      cryptox.SHA256Hex([]byte(code)),
		Attempts:  0,
		ExpiresAt: s.now().UTC().Add(s.codeTTL),
	}
	if err := s.emailCodes.SetEmailCode(ctx, emailCodePurpose, normalized, record, s.codeTTL); err != nil {
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
		Nickname:        value.DefaultNickname(normalized),
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

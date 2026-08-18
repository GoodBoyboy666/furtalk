package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/value"
)

// RequestPasswordReset 为已存在的邮箱生成一次性密码重置验证码并投递邮件。
// 未知邮箱返回相同的公开成功，且零邮件、零用户、零有效验证码记录；
// 邮件/配置失败在用户 lookup 之后只记录日志，不返回区分存在性的响应。
func (s *Service) RequestPasswordReset(ctx context.Context, rawEmail, captchaToken string) error {
	_, normalized, err := value.NormalizeEmail(rawEmail)
	if err != nil {
		return domain.ErrValidation
	}
	if err := s.checkCaptcha(ctx, PasswordResetAction, captchaToken); err != nil {
		return err
	}
	_, err = s.users.FindByEmailNormalized(ctx, normalized)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.mailer == nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "password reset skipped: mailer not configured", "cause", "mailer_nil")
		return nil
	}
	code, err := generateCode(emailCodeLength)
	if err != nil {
		return err
	}
	record := EmailCodeRecord{
		Hash:      cryptox.SHA256Hex([]byte(code)),
		Attempts:  0,
		ExpiresAt: s.now().UTC().Add(passwordResetCodeTTL),
	}
	if err := s.emailCodes.SetEmailCode(ctx, passwordResetPurpose, normalized, record, passwordResetCodeTTL); err != nil {
		return err
	}
	msg, err := renderPasswordResetMessage(s.templates, normalized, code, passwordResetCodeTTL)
	if err != nil {
		// 渲染失败与投递失败同语义：删除验证码并保持公开响应，不能据此区分存在性。
		_ = s.emailCodes.DeleteEmailCode(ctx, passwordResetPurpose, normalized)
		logging.FromContext(ctx, s.log).WarnContext(ctx, "password reset mail render failed", logging.Error(err))
		return nil
	}
	if err := s.mailer.Send(ctx, msg); err != nil {
		// 投递失败不影响公开响应：未知邮箱不会到达此分支，响应不能据此区分邮箱存在性。
		_ = s.emailCodes.DeleteEmailCode(ctx, passwordResetPurpose, normalized)
		logging.FromContext(ctx, s.log).WarnContext(ctx, "password reset mail delivery failed", logging.Error(err))
	}
	return nil
}

// ResetPasswordWithCode 原子消费一次性密码重置验证码并更新密码。
// 密码哈希、首次 email verification 与会话代次递增在同一数据库事务写入：
// 已验证邮箱保留原验证时间，未验证邮箱写入当前时间。
// 成功不签发会话 Cookie；目标用户全部既有 JWT 因代次递增而失效。
func (s *Service) ResetPasswordWithCode(ctx context.Context, rawEmail, code, newPassword string) error {
	_, normalized, err := value.NormalizeEmail(rawEmail)
	if err != nil {
		return domain.ErrInvalidCredentials
	}
	if len(newPassword) < minPasswordLength {
		return domain.ErrValidation
	}
	consumed, err := s.emailCodes.AtomicVerifyEmailCode(ctx, passwordResetPurpose, normalized, cryptox.SHA256Hex([]byte(code)), passwordResetMaxAttempts)
	if err != nil {
		return err
	}
	if !consumed {
		return domain.ErrInvalidCredentials
	}
	passwordHash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var userID int64
	err = s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		id, _, err := s.users.ResetPasswordByEmail(ctx, normalized, passwordHash, now, now)
		if err != nil {
			return err
		}
		userID = id
		return nil
	})
	if err != nil {
		return err
	}
	return s.invalidateAuthz(ctx, userID)
}

// renderPasswordResetMessage 渲染密码重置验证码邮件的主题、纯文本正文与模板化 HTML 正文。
// HTML 正文由模板渲染器生成，失败时返回错误，由调用方按投递失败处理。
func renderPasswordResetMessage(templates mailer.TemplateRenderer, to, code string, ttl time.Duration) (mailer.Message, error) {
	minutes := int(ttl / time.Minute)
	html, err := templates.PasswordResetCode(mailer.PasswordResetCodeData{
		Code:             code,
		ExpiresInMinutes: minutes,
	})
	if err != nil {
		return mailer.Message{}, err
	}
	return mailer.Message{
		To:       to,
		Subject:  "您的 Furtalk 密码重置验证码",
		TextBody: fmt.Sprintf("您的 Furtalk 密码重置验证码是：%s。\n\n验证码 %d 分钟内有效。如非本人操作，可忽略此邮件。", code, minutes),
		HTMLBody: html,
	}, nil
}

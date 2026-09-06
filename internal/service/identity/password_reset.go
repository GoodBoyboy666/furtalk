package identity

import (
	"context"
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

// RequestPasswordReset 请求发送密码重置邮件。
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
	if err := s.emailCodes.SetEmailCode(ctx, passwordResetPurpose, normalized, cryptox.SHA256Hex([]byte(code)), passwordResetCodeTTL); err != nil {
		if errors.Is(err, cache.ErrCapacity) {
			s.logEphemeralCapacity(ctx, passwordResetNamespace)
			return nil
		}
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

// ResetPasswordWithCode 使用密码重置验证码更新密码。
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

// renderPasswordResetMessage 渲染密码重置邮件。
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

package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/passkey"
)

// WebAuthn 挑战会话存储常量。
const (
	passkeyChallengeTTL = 5 * time.Minute
	passkeyKeyPrefix    = "webauthn:"
)

// RegistrationOptions 保存 WebAuthn 注册流程返回给客户端的选项。
type RegistrationOptions struct {
	Challenge string
	Options   json.RawMessage
}

// LoginOptions 保存 WebAuthn 认证流程返回给客户端的选项。
type LoginOptions struct {
	Challenge string
	Options   json.RawMessage
}

// PasskeyAdapter 定义由 internal/platform/passkey 实现的 WebAuthn 适配边界。
type PasskeyAdapter interface {
	BeginRegistration(user passkey.User) (json.RawMessage, []byte, error)
	FinishRegistration(user passkey.User, session, response []byte) (*passkey.Credential, error)
	BeginLogin() (json.RawMessage, []byte, error)
	FinishLogin(session, response []byte, lookup func(rawID, userHandle []byte) (*passkey.User, error)) (*passkey.Credential, uint32, error)
}

// BeginPasskeyRegistration 启动 WebAuthn 注册流程。
func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID int64) (*RegistrationOptions, error) {
	if s.passkeyAdapter == nil {
		return nil, domain.ErrInvalidCredentials
	}
	user, err := s.passkeyUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	options, session, err := s.passkeyAdapter.BeginRegistration(*user)
	if err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "passkey registration begin failed", logging.Error(err))
		return nil, domain.ErrInvalidCredentials
	}
	sessionKey, err := s.storePasskeySession(ctx, session)
	if err != nil {
		return nil, err
	}
	return &RegistrationOptions{Challenge: sessionKey, Options: options}, nil
}

// FinishPasskeyRegistration 完成 WebAuthn 注册并保存凭证。
func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID int64, challenge string, response json.RawMessage) error {
	if s.passkeyAdapter == nil {
		return domain.ErrInvalidCredentials
	}
	session, err := s.consumePasskeySession(ctx, challenge)
	if err != nil {
		return domain.ErrInvalidCredentials
	}
	user, err := s.passkeyUser(ctx, userID)
	if err != nil {
		return domain.ErrInvalidCredentials
	}
	credential, err := s.passkeyAdapter.FinishRegistration(*user, session, response)
	if err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "passkey registration finish failed", logging.Error(err))
		return domain.ErrInvalidCredentials
	}
	transports, err := json.Marshal(credential.Transports)
	if err != nil {
		return domain.ErrInvalidCredentials
	}
	row := &domain.PasskeyCredential{
		UserID:          userID,
		CredentialID:    encodeCredentialID(credential.ID),
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transports:      string(transports),
		SignCount:       credential.SignCount,
		BackupEligible:  credential.BackupEligible,
		BackupState:     credential.BackupState,
		Name:            "Passkey",
	}
	err = s.passkeys.Create(ctx, row)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return domain.ErrInvalidCredentials
		}
		return err
	}
	return nil
}

// BeginPasskeyLogin 启动 WebAuthn 认证流程。
func (s *Service) BeginPasskeyLogin(ctx context.Context) (*LoginOptions, error) {
	if s.passkeyAdapter == nil {
		return nil, domain.ErrInvalidCredentials
	}
	options, session, err := s.passkeyAdapter.BeginLogin()
	if err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "passkey login begin failed", logging.Error(err))
		return nil, domain.ErrInvalidCredentials
	}
	sessionKey, err := s.storePasskeySession(ctx, session)
	if err != nil {
		return nil, err
	}
	return &LoginOptions{Challenge: sessionKey, Options: options}, nil
}

// VerifyPasskeyLogin 完成 WebAuthn 认证并生成会话。
func (s *Service) VerifyPasskeyLogin(ctx context.Context, challenge string, response json.RawMessage) (*Session, error) {
	if s.passkeyAdapter == nil {
		return nil, domain.ErrInvalidCredentials
	}
	session, err := s.consumePasskeySession(ctx, challenge)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	credential, counter, err := s.passkeyAdapter.FinishLogin(session, response, func(rawID, userHandle []byte) (*passkey.User, error) {
		return s.lookupPasskeyUser(ctx, rawID, userHandle)
	})
	if err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "passkey login finish failed", logging.Error(err))
		return nil, domain.ErrInvalidCredentials
	}
	stored, err := s.passkeys.GetByCredentialID(ctx, encodeCredentialID(credential.ID))
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if stored.SignCount > 0 && counter < stored.SignCount {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "passkey sign count rollback rejected", logging.ID("user_id", stored.UserID))
		return nil, domain.ErrInvalidCredentials
	}
	now := s.now().UTC()
	if err := s.passkeys.UpdateLoginState(ctx, stored.ID, counter, credential.BackupState, now); err != nil {
		return nil, err
	}
	user, err := s.users.FindByID(ctx, stored.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	return s.completeLogin(ctx, user)
}

// passkeyUser 用已存储的凭证构建提供给 passkey 适配器的用户。
func (s *Service) passkeyUser(ctx context.Context, userID int64) (*passkey.User, error) {
	user, err := s.users.FindByID(ctx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.passkeys.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.toPasskeyUser(ctx, user, rows), nil
}

// lookupPasskeyUser 在登录期间按凭证与用户句柄解析用户。
func (s *Service) lookupPasskeyUser(ctx context.Context, rawID, userHandle []byte) (*passkey.User, error) {
	credentialID := encodeCredentialID(rawID)
	row, err := s.passkeys.GetByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	user, err := s.users.FindByID(ctx, row.UserID)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	rows, err := s.passkeys.ListByUserID(ctx, row.UserID)
	if err != nil {
		return nil, err
	}
	return s.toPasskeyUser(ctx, user, rows), nil
}

// toPasskeyUser 将领域用户转换为 Passkey 适配器用户。
func (s *Service) toPasskeyUser(ctx context.Context, user *domain.User, rows []domain.PasskeyCredential) *passkey.User {
	credentials := make([]passkey.Credential, 0, len(rows))
	for _, row := range rows {
		credentialID, err := decodeCredentialID(row.CredentialID)
		if err != nil {
			continue
		}
		var transports []string
		if err := json.Unmarshal([]byte(row.Transports), &transports); err != nil {
			logging.FromContext(ctx, s.log).WarnContext(ctx, "passkey credential transports corrupted", "credential_id", row.CredentialID, logging.Error(err))
		}
		credentials = append(credentials, passkey.Credential{
			ID:              credentialID,
			PublicKey:       row.PublicKey,
			AttestationType: row.AttestationType,
			Transports:      transports,
			SignCount:       row.SignCount,
			BackupEligible:  row.BackupEligible,
			BackupState:     row.BackupState,
		})
	}
	return &passkey.User{
		ID:          userHandle(user.ID),
		Name:        user.Nickname,
		DisplayName: user.Nickname,
		Credentials: credentials,
	}
}

// storePasskeySession 以挑战为键持久化仪式会话。
func (s *Service) storePasskeySession(ctx context.Context, session []byte) (string, error) {
	var parsed struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(session, &parsed); err != nil || parsed.Challenge == "" {
		return "", domain.ErrInvalidCredentials
	}
	if err := s.passkeyStore.Set(ctx, parsed.Challenge, session, passkeyChallengeTTL); err != nil {
		return "", s.mapEphemeralError(ctx, "passkey", err)
	}
	return parsed.Challenge, nil
}

// consumePasskeySession 消费 Passkey 挑战会话。
func (s *Service) consumePasskeySession(ctx context.Context, challenge string) ([]byte, error) {
	if challenge == "" {
		return nil, domain.ErrInvalidCredentials
	}
	raw, err := s.passkeyStore.AtomicConsume(ctx, challenge)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	session, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	return session, nil
}

// userHandle 把十进制用户 id 编码为 WebAuthn 用户句柄字节。
func userHandle(userID int64) []byte {
	return []byte(strconv.FormatInt(userID, 10))
}

// encodeCredentialID 编码 Passkey 凭证标识。
func encodeCredentialID(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeCredentialID 解码 Passkey 凭证标识。
func decodeCredentialID(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

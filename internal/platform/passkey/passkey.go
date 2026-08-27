// Package passkey 封装 go-webauthn SDK。
// RP ID、RP origins 与 display name 为静态配置，challenge 由使用方存储并只消费一次。
package passkey

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config 是 WebAuthn 依赖方（RP）的静态配置。
// RPID 与 RPOrigins 必填；LoginTimeout 与 RegistrationTimeout 是登录与注册的强制超时。
type Config struct {
	RPID                string
	RPOrigins           []string
	RPDisplayName       string
	LoginTimeout        time.Duration
	RegistrationTimeout time.Duration
}

// Credential 是面向服务层暴露的已存储 WebAuthn credential。
// Transports 是可 JSON 序列化的 transport 提示列表。
type Credential struct {
	ID              []byte   `json:"id"`
	PublicKey       []byte   `json:"public_key"`
	AttestationType string   `json:"attestation_type"`
	Transports      []string `json:"transports"`
	SignCount       uint32   `json:"sign_count"`
	BackupEligible  bool     `json:"backup_eligible"`
	BackupState     bool     `json:"backup_state"`
}

// User 是面向服务层的 WebAuthn user。
// ID 是稳定的 user handle，不得包含可识别身份的邮箱。
type User struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []Credential
}

// Adapter 负责运行注册与登录流程。
type Adapter struct {
	wa *webauthn.WebAuthn
}

// New 校验静态 RP 配置并构建适配器。
func New(cfg Config) (*Adapter, error) {
	if cfg.RPID == "" || len(cfg.RPOrigins) == 0 {
		return nil, fmt.Errorf("passkey: rp id and origins are required")
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		RPDisplayName: cfg.RPDisplayName,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.LoginTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.RegistrationTimeout},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Adapter{wa: wa}, nil
}

// BeginRegistration 返回 credential 创建选项的 JSON 与不透明 session 载荷。
// session 载荷由使用方存储，例如以内嵌的 challenge 作为 key。
func (a *Adapter) BeginRegistration(user User) (json.RawMessage, []byte, error) {
	session, err := a.beginRegistration(user)
	if err != nil {
		return nil, nil, err
	}
	options, err := json.Marshal(session.options)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: marshal registration options: %w", err)
	}
	return options, session.raw, nil
}

// FinishRegistration 验证 attestation 响应并返回持久化的 credential 记录。
// 任何验证失败都返回通用错误。
func (a *Adapter) FinishRegistration(user User, sessionJSON, responseJSON []byte) (*Credential, error) {
	session, err := decodeSession(sessionJSON)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	credential, err := a.wa.CreateCredential(user.toSDK(), session, parsed)
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return fromSDK(credential), nil
}

// BeginLogin 返回 discoverable 断言选项 JSON 与不透明 session 载荷。
// 登录始终使用客户端可发现的 passkey，不接受用户标识或 credential allow-list。
func (a *Adapter) BeginLogin() (json.RawMessage, []byte, error) {
	options, session, err := a.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: %w", err)
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: marshal login options: %w", err)
	}
	encoded, err := encodeSession(session)
	if err != nil {
		return nil, nil, err
	}
	return raw, encoded, nil
}

// FinishLogin 根据 discoverable session 验证断言。
// lookup 根据 credential ID 与 authenticator 返回的 user handle 解析用户；
// 返回的断言计数器供使用方校验 sign_count，防止回滚攻击。
func (a *Adapter) FinishLogin(sessionJSON, responseJSON []byte, lookup func(rawID, userHandle []byte) (*User, error)) (*Credential, uint32, error) {
	session, err := decodeSession(sessionJSON)
	if err != nil {
		return nil, 0, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(responseJSON)
	if err != nil {
		return nil, 0, fmt.Errorf("passkey: %w", err)
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		user, err := lookup(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		return user.toSDK(), nil
	}
	_, credential, err := a.wa.ValidatePasskeyLogin(handler, session, parsed)
	if err != nil {
		return nil, 0, fmt.Errorf("passkey: %w", err)
	}
	counter := parsed.Response.AuthenticatorData.Counter
	return fromSDK(credential), counter, nil
}

type ceremonySession struct {
	options *protocol.CredentialCreation
	raw     []byte
}

func (a *Adapter) beginRegistration(user User) (*ceremonySession, error) {
	options, session, err := a.wa.BeginRegistration(
		user.toSDK(),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	encoded, err := encodeSession(session)
	if err != nil {
		return nil, err
	}
	return &ceremonySession{options: options, raw: encoded}, nil
}

func encodeSession(session *webauthn.SessionData) ([]byte, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("passkey: marshal session: %w", err)
	}
	return raw, nil
}

func decodeSession(raw []byte) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return session, fmt.Errorf("passkey: decode session: %w", err)
	}
	return session, nil
}

// toSDK 把面向服务层的 user 转成 go-webauthn 的 User 接口。
func (u User) toSDK() webauthn.User {
	return sdkUser{user: u}
}

type sdkUser struct {
	user User
}

// WebAuthnID 返回 user handle。
func (u sdkUser) WebAuthnID() []byte {
	return u.user.ID
}

// WebAuthnName 返回用户登录名。
func (u sdkUser) WebAuthnName() string {
	return u.user.Name
}

// WebAuthnDisplayName 返回展示名。
func (u sdkUser) WebAuthnDisplayName() string {
	return u.user.DisplayName
}

// WebAuthnCredentials 返回该用户已登记的凭证。
func (u sdkUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.user.Credentials))
	for _, c := range u.user.Credentials {
		out = append(out, c.toSDK())
	}
	return out
}

func (c Credential) toSDK() webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:              c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Authenticator: webauthn.Authenticator{
			SignCount: c.SignCount,
		},
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
	}
}

func fromSDK(c *webauthn.Credential) *Credential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return &Credential{
		ID:              c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transports:      transports,
		SignCount:       c.Authenticator.SignCount,
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
	}
}

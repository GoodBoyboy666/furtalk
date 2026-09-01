package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/oauth"
	"furtalk/internal/platform/value"
)

// OAuth 一次性 state/verifier 与流程用途常量。
const (
	oauthStateTTL    = 10 * time.Minute
	oauthStatePrefix = "oauth-state:"
	stateBytes       = 16
	verifierBytes    = 32
	nonceBytes       = 16

	oauthHandoffTTL    = 2 * time.Minute
	oauthHandoffPrefix = "oauth-handoff:"
	handoffBytes       = 32

	oauthPurposeLogin    = "login"
	oauthPurposeRegister = "register"
	oauthPurposeBind     = "bind"
)

// OAuthState 存储在 oauth-state:<state> 下的一次性临时记录。
// Verifier/Nonce 按 provider 能力可空：非 PKCE provider 无 Verifier，
// 非 ID-token provider 无 Nonce。RedirectURI 是授权 URL 中登记的回调地址，
// 令牌交换复用该精确值，不跨部署重算。
type OAuthState struct {
	Provider    string `json:"provider"`
	Purpose     string `json:"purpose"`
	Verifier    string `json:"verifier"`
	Nonce       string `json:"nonce,omitempty"`
	UserID      int64  `json:"user_id,omitempty"`
	Redirect    string `json:"redirect,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// OAuthHandoff  Apple form_post 桥接在 oauth-handoff:<token> 下保存的
// 短时一次性回调载荷。它只做传输适配，不交换授权码、不创建/绑定用户、
// 不签发 Cookie。
type OAuthHandoff struct {
	Provider string `json:"provider"`
	State    string `json:"state"`
	Code     string `json:"code"`
	Error    string `json:"error,omitempty"`
}

// ProviderMeta  GET /auth/providers 返回的公共元数据。
type ProviderMeta struct {
	Key  string
	Kind string
	Name string
}

// OAuthStart  BeginOAuth 的结果。
type OAuthStart struct {
	AuthURL string
}

// OAuthFactoryConfig  OAuth/OIDC provider 工厂所需的最小静态配置。
type OAuthFactoryConfig struct {
	ClientTimeout time.Duration
}

// OAuthProviderConfig  OAuthProviderFactory 的完整配置输入，
// 对应 setting.AuthProvider 的全部解密字段（含 Apple 私钥与自托管实例地址）。
type OAuthProviderConfig struct {
	ProviderKey     string
	Kind            string
	ClientID        string
	ClientSecret    string
	AuthURL         string
	TokenURL        string
	IssuerURL       string
	InstanceURL     string
	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey string
}

// OAuthProvider  OAuth/OIDC 适配器边界，由 internal/platform/oauth 实现。
type OAuthProvider interface {
	Name() string
	BuildAuthURL(ctx context.Context, req oauth.AuthorizationRequest) (string, error)
	Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.Identity, error)
}

// OAuthProviderFactory 按解密后的提供商配置构建 OAuthProvider。
type OAuthProviderFactory func(cfg OAuthProviderConfig) (OAuthProvider, error)

// NewOAuthProviderFactory 从模块自有静态配置构建 OAuth/OIDC provider 工厂。
func NewOAuthProviderFactory(cfg OAuthFactoryConfig) OAuthProviderFactory {
	timeout := cfg.ClientTimeout
	return func(providerCfg OAuthProviderConfig) (OAuthProvider, error) {
		provider, err := oauth.New(oauth.Config{
			ProviderKey:     providerCfg.ProviderKey,
			Kind:            providerCfg.Kind,
			ClientID:        providerCfg.ClientID,
			ClientSecret:    providerCfg.ClientSecret,
			AuthURL:         providerCfg.AuthURL,
			TokenURL:        providerCfg.TokenURL,
			IssuerURL:       providerCfg.IssuerURL,
			InstanceURL:     providerCfg.InstanceURL,
			AppleTeamID:     providerCfg.AppleTeamID,
			AppleKeyID:      providerCfg.AppleKeyID,
			ApplePrivateKey: providerCfg.ApplePrivateKey,
			Timeout:         timeout,
		})
		if err != nil {
			return nil, err
		}
		return provider, nil
	}
}

// OAuthProviders 列出已启用且已配置的 OAuth/OIDC 提供商，只含公共元数据。
func (s *Service) OAuthProviders(ctx context.Context) ([]ProviderMeta, error) {
	providers, err := s.providers.OAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ProviderMeta, 0, len(providers))
	for _, provider := range providers {
		out = append(out, ProviderMeta{
			Key:  provider.ProviderKey,
			Kind: string(provider.Kind),
			Name: s.providerDisplayName(provider),
		})
	}
	return out, nil
}

// registrationMode 返回固定 provider 的注册模式；
// 未知 key（自定义 OIDC）默认按已验证邮箱注册处理。
func registrationMode(providerKey string) oauth.RegistrationMode {
	if spec, ok := oauth.LookupProvider(providerKey); ok {
		return spec.Registration
	}
	return oauth.RegistrationVerifiedEmail
}

// BeginOAuth 启动 Authorization Code + PKCE 流程。
// 启动失败按类别区分：provider 缺失返回 ErrProviderNotFound（404）、密钥损坏
// 返回 ErrSecretCorrupt（500）、provider 构造或 OIDC discovery/授权 URL 失败
// 返回 ErrUnavailable（503）；只有 bind 未登录返回 401。
// bind-only provider 的 register 用途在构建任何内容前直接以通用失败拒绝。
func (s *Service) BeginOAuth(ctx context.Context, providerKey, purpose string, userID int64, redirect string) (*OAuthStart, error) {
	if purpose != oauthPurposeLogin && purpose != oauthPurposeRegister && purpose != oauthPurposeBind {
		return nil, domain.ErrValidation
	}
	if purpose == oauthPurposeRegister && registrationMode(providerKey) == oauth.RegistrationBindOnly {
		return nil, domain.ErrInvalidCredentials
	}
	if purpose == oauthPurposeBind && userID <= 0 {
		return nil, domain.ErrInvalidCredentials
	}
	providerConfig, err := s.providers.OAuthProvider(ctx, providerKey)
	if err != nil {
		return nil, err
	}
	provider, err := s.buildProvider(providerConfig)
	if err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "oauth provider construction failed", "provider", providerKey, logging.Error(err))
		return nil, domain.ErrUnavailable
	}
	state, err := cryptox.RandomToken(stateBytes)
	if err != nil {
		return nil, err
	}
	redirectURI := s.oauthRedirectURI(providerConfig.ProviderKey)
	record := OAuthState{
		Provider:    providerConfig.ProviderKey,
		Purpose:     purpose,
		UserID:      userID,
		Redirect:    sanitizeRedirect(redirect),
		RedirectURI: redirectURI,
	}
	// 按 catalog 能力生成 verifier 与 nonce：未知 key 保持自定义 OIDC 语义
	// （始终使用 S256 PKCE 与 nonce），适配器不得自行启用或关闭任一能力。
	pkce, nonce := true, true
	if spec, ok := oauth.LookupProvider(providerConfig.ProviderKey); ok {
		pkce, nonce = spec.PKCE, spec.Nonce
	}
	if pkce {
		verifier, err := cryptox.RandomToken(verifierBytes)
		if err != nil {
			return nil, err
		}
		record.Verifier = verifier
	}
	if nonce {
		nonceValue, err := cryptox.RandomToken(nonceBytes)
		if err != nil {
			return nil, err
		}
		record.Nonce = nonceValue
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if err := s.oauthState.Set(ctx, state, string(recordJSON), oauthStateTTL); err != nil {
		return nil, s.mapEphemeralError(ctx, "oauth_state", err)
	}
	authURL, err := provider.BuildAuthURL(ctx, oauth.AuthorizationRequest{
		State:       state,
		Verifier:    record.Verifier,
		Nonce:       record.Nonce,
		RedirectURI: redirectURI,
	})
	if err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "oauth build auth url failed", "provider", providerKey, logging.Error(err))
		return nil, domain.ErrUnavailable
	}
	return &OAuthStart{AuthURL: authURL}, nil
}

// FinishOAuth 消费 state，用 PKCE 交换 code，并按登录/注册/绑定规则签发会话。
// 返回的 redirect 在 state 有效时始终是已净化的站内回跳地址；state 无效时为空。
// 错误分类不泄露账号存在性：state 缺失/过期/重放/不匹配返回
// ErrOAuthCallbackInvalid，授权码交换或令牌校验失败返回
// ErrOAuthVerificationFailed，其余身份解析错误原样透传。
func (s *Service) FinishOAuth(ctx context.Context, providerKey, state, code string) (*Session, string, error) {
	if s.oauth == nil {
		return nil, "", domain.ErrOAuthVerificationFailed
	}
	raw, err := s.oauthState.AtomicConsume(ctx, state)
	if err != nil {
		return nil, "", domain.ErrOAuthCallbackInvalid
	}
	var record OAuthState
	if err := json.Unmarshal([]byte(raw), &record); err != nil || record.Provider != providerKey {
		return nil, "", domain.ErrOAuthCallbackInvalid
	}
	providerConfig, err := s.providers.OAuthProvider(ctx, providerKey)
	if err != nil {
		return nil, record.Redirect, domain.ErrOAuthVerificationFailed
	}
	provider, err := s.buildProvider(providerConfig)
	if err != nil {
		return nil, record.Redirect, domain.ErrOAuthVerificationFailed
	}
	oauthIdentity, err := provider.Exchange(ctx, oauth.ExchangeRequest{
		Code:        code,
		Verifier:    record.Verifier,
		Nonce:       record.Nonce,
		RedirectURI: record.RedirectURI,
	})
	if err != nil {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "oauth exchange/verify failed", "provider", providerKey, logging.Error(err))
		if oauth.IsResponseTooLarge(err) {
			return nil, record.Redirect, domain.ErrUnavailable
		}
		return nil, record.Redirect, domain.ErrOAuthVerificationFailed
	}
	session, err := s.resolveOAuthIdentity(ctx, providerConfig, oauthIdentity, record)
	if err != nil {
		return nil, record.Redirect, err
	}
	return session, record.Redirect, nil
}

// OAuthAccessDenied 原子消费一次性 state，恢复净化后的回跳地址，
// 并返回 ErrOAuthAccessDenied 表示用户取消了授权。
// 不创建绑定、不签发会话、不创建用户。未知或 provider 不匹配的 state
// 返回 ErrOAuthCallbackInvalid，不泄露回调细节。
func (s *Service) OAuthAccessDenied(ctx context.Context, providerKey, state string) (string, error) {
	raw, err := s.oauthState.AtomicConsume(ctx, state)
	if err != nil {
		return "", domain.ErrOAuthCallbackInvalid
	}
	var record OAuthState
	if err := json.Unmarshal([]byte(raw), &record); err != nil || record.Provider != providerKey {
		return "", domain.ErrOAuthCallbackInvalid
	}
	return record.Redirect, domain.ErrOAuthAccessDenied
}

// CreateOAuthHandoff 为 Apple form_post 回调创建短时一次性 handoff 记录，
// 返回不透明 token。state 必填；code/error 按实际载荷可有可无。
// 授权码绝不进入任何 URL。
func (s *Service) CreateOAuthHandoff(ctx context.Context, providerKey, state, code, errMsg string) (string, error) {
	if state == "" {
		return "", domain.ErrValidation
	}
	if providerKey != "apple" {
		return "", domain.ErrOAuthCallbackInvalid
	}
	var encodedState json.RawMessage
	if err := s.oauthState.Get(ctx, state, &encodedState); err != nil {
		return "", domain.ErrOAuthCallbackInvalid
	}
	var stateRecord OAuthState
	// BeginOAuth stores the serialized record as a string for compatibility with
	// AtomicConsume. Accept the raw object form as well for backend/test doubles.
	var rawState string
	if len(encodedState) > 0 && encodedState[0] == '"' {
		if err := json.Unmarshal(encodedState, &rawState); err != nil {
			return "", domain.ErrOAuthCallbackInvalid
		}
		encodedState = json.RawMessage(rawState)
	}
	if err := json.Unmarshal(encodedState, &stateRecord); err != nil || stateRecord.Provider != "apple" {
		return "", domain.ErrOAuthCallbackInvalid
	}
	token, err := cryptox.RandomToken(handoffBytes)
	if err != nil {
		return "", err
	}
	record := OAuthHandoff{Provider: providerKey, State: state, Code: code, Error: errMsg}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	if err := s.oauthHandoff.Set(ctx, token, string(recordJSON), oauthHandoffTTL); err != nil {
		return "", s.mapEphemeralError(ctx, "oauth_handoff", err)
	}
	return token, nil
}

// ConsumeOAuthHandoff 原子消费一次性 handoff 记录。
// 缺失、过期、重放或损坏的 token 返回 ErrOAuthCallbackInvalid。
func (s *Service) ConsumeOAuthHandoff(ctx context.Context, handoff string) (OAuthHandoff, error) {
	raw, err := s.oauthHandoff.AtomicConsume(ctx, handoff)
	if err != nil {
		return OAuthHandoff{}, domain.ErrOAuthCallbackInvalid
	}
	var record OAuthHandoff
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return OAuthHandoff{}, domain.ErrOAuthCallbackInvalid
	}
	return record, nil
}

// resolveOAuthIdentity 按注册模式与绑定状态解析身份。
// 固定顺序：先要求非空 subject → 按 (provider_key, subject) 查绑定 →
// bind-only 拒绝 / bind 直接绑定当前用户 → 已验证邮箱注册/邮箱匹配。
func (s *Service) resolveOAuthIdentity(ctx context.Context, providerConfig *AuthProvider, oauthIdentity *oauth.Identity, record OAuthState) (*Session, error) {
	// 1. 要求适配器输出非空 subject；空 subject 一律通用失败。
	if oauthIdentity == nil || oauthIdentity.Subject == "" {
		return nil, domain.ErrInvalidCredentials
	}
	// 2. 先按 (provider_key, subject) 查绑定，不触碰邮箱。
	bound, err := s.identities.GetByProviderSubject(ctx, providerConfig.ProviderKey, oauthIdentity.Subject)
	if err == nil {
		// 3. 已绑定：bind 只允许绑定当前用户，绝不把调用方切到其他账号；
		// login/register（旧语义）直接登录绑定用户。
		if record.Purpose == oauthPurposeBind && record.UserID != bound.UserID {
			return nil, domain.ErrInvalidCredentials
		}
		return s.completeOAuthLogin(ctx, bound)
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}

	// 4. 无绑定且 purpose=bind：直接为当前登录用户创建绑定；
	// VerifiedEmail 非空时原样存储，否则存空串（bind-only 无可信邮箱）。
	if record.Purpose == oauthPurposeBind {
		user, err := s.users.FindByID(ctx, record.UserID)
		if err != nil {
			return nil, err
		}
		return s.bindOAuthIdentity(ctx, providerConfig, oauthIdentity, user)
	}

	// 5. 无绑定且 provider 为 bind-only：拒绝。不做邮箱查找、不注册、
	// 不做域名校验、不写库，也不泄露身份是否存在。
	if registrationMode(providerConfig.ProviderKey) == oauth.RegistrationBindOnly {
		return nil, domain.ErrInvalidCredentials
	}

	// 6. 其余 provider（可注册）要求并规范化可信已验证邮箱，
	// 再复用既有公开注册 / 域名名单 / 邮箱匹配 / 事务写入规则。
	_, normalized, err := value.NormalizeEmail(oauthIdentity.VerifiedEmail)
	if err != nil || normalized == "" {
		return nil, domain.ErrInvalidCredentials
	}
	user, err := s.users.FindByEmailNormalized(ctx, normalized)
	if errors.Is(err, domain.ErrNotFound) {
		return s.registerOAuthUser(ctx, providerConfig, oauthIdentity, normalized, record)
	}
	if err != nil {
		return nil, err
	}
	// bind 无绑定分支已在前面处理；原邮箱匹配绑定的校验被保留以防回归。
	if record.Purpose != oauthPurposeBind || record.UserID != user.ID {
		return nil, domain.ErrInvalidCredentials
	}
	return s.bindOAuthIdentity(ctx, providerConfig, oauthIdentity, user)
}

// registerOAuthUser 在一个事务内静默创建普通已验证用户、绑定外部身份。
// 未知邮箱自动注册前校验域名名单；已存在的绑定或绑定已有用户不受影响。
func (s *Service) registerOAuthUser(ctx context.Context, providerConfig *AuthProvider, oauthIdentity *oauth.Identity, normalized string, record OAuthState) (*Session, error) {
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
	var userID int64
	err = s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		user := &domain.User{
			Email:           normalized,
			EmailNormalized: normalized,
			Nickname:        value.DefaultNickname(normalized),
			Role:            domain.RoleUser,
			Status:          domain.UserStatusActive,
			EmailVerifiedAt: &now,
		}
		if err := s.users.Create(ctx, user); err != nil {
			return err
		}
		if err := s.identities.Create(ctx, &domain.ExternalIdentity{
			UserID:          user.ID,
			ProviderKey:     providerConfig.ProviderKey,
			ProviderSubject: oauthIdentity.Subject,
			VerifiedEmail:   oauthIdentity.VerifiedEmail,
		}); err != nil {
			return err
		}
		userID = user.ID
		return nil
	})
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.completeLogin(ctx, user)
}

// bindOAuthIdentity 把外部身份绑定到已有用户并签发会话。
func (s *Service) bindOAuthIdentity(ctx context.Context, providerConfig *AuthProvider, oauthIdentity *oauth.Identity, user *domain.User) (*Session, error) {
	err := s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		return s.identities.Create(ctx, &domain.ExternalIdentity{
			UserID:          user.ID,
			ProviderKey:     providerConfig.ProviderKey,
			ProviderSubject: oauthIdentity.Subject,
			VerifiedEmail:   oauthIdentity.VerifiedEmail,
		})
	})
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	return s.completeLogin(ctx, user)
}

// completeOAuthLogin 登录已绑定到 (provider, subject) 对的用户。
func (s *Service) completeOAuthLogin(ctx context.Context, bound *domain.ExternalIdentity) (*Session, error) {
	user, err := s.users.FindByID(ctx, bound.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if err := s.identities.TouchLastLogin(ctx, bound.ID, now); err != nil {
		return nil, err
	}
	return s.completeLogin(ctx, user)
}

func (s *Service) buildProvider(providerConfig *AuthProvider) (OAuthProvider, error) {
	if providerConfig == nil || s.oauth == nil {
		return nil, domain.ErrUnavailable
	}
	provider, err := s.oauth(OAuthProviderConfig{
		ProviderKey:     providerConfig.ProviderKey,
		Kind:            string(providerConfig.Kind),
		ClientID:        providerConfig.ClientID,
		ClientSecret:    providerConfig.ClientSecret,
		AuthURL:         providerConfig.AuthURL,
		TokenURL:        providerConfig.TokenURL,
		IssuerURL:       providerConfig.IssuerURL,
		InstanceURL:     providerConfig.InstanceURL,
		AppleTeamID:     providerConfig.AppleTeamID,
		AppleKeyID:      providerConfig.AppleKeyID,
		ApplePrivateKey: providerConfig.ApplePrivateKey,
	})
	if err != nil {
		return nil, fmt.Errorf("identity: build oauth provider: %w", err)
	}
	return provider, nil
}

func (s *Service) oauthRedirectURI(providerKey string) string {
	return strings.TrimRight(s.baseURL, "/") + "/oauth/callback/" + url.PathEscape(providerKey)
}

// providerDisplayName 从固定 provider catalog 投影展示名；
// 未知 key（自定义 OIDC）回落到 key 本身。
func (s *Service) providerDisplayName(provider AuthProvider) string {
	if spec, ok := oauth.LookupProvider(provider.ProviderKey); ok {
		return spec.Name
	}
	return provider.ProviderKey
}

// sanitizeRedirect 只保留同源重定向目标。
// 浏览器会把反斜杠归一化为斜杠，因此 `\`、控制字符与空白混淆必须在解析前拒绝；
// 解析后拒绝绝对 URL 与携带 host 的网络路径引用，只放行站内相对路径与锚点。
func sanitizeRedirect(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	for _, r := range raw {
		if r == '\\' || r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	if u.IsAbs() || u.Host != "" {
		return "/"
	}
	return raw
}

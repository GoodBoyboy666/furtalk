package setting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/captcha"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/netprobe"
	"furtalk/internal/platform/oauth"
	"furtalk/internal/repository"
)

// masterKeyVersion 是当前 AES-GCM envelope 密钥版本。
const masterKeyVersion byte = 1

// CaptchaConfig 是 CAPTCHA 提供商的类型化配置，含机密。
// Endpoint 仅 CAP 使用，是管理员配置的外部 Standalone 实例基址，属于公开字段。
type CaptchaConfig struct {
	Provider  string `json:"provider"`
	SiteKey   string `json:"site_key"`
	SecretKey string `json:"secret_key"`
	Endpoint  string `json:"endpoint"`
}

// AuthConfig 是 OAuth/OIDC provider 的通用类型化配置，客户端密钥在持久化前加密。
// 包含全部固定内置 provider 与自定义 OIDC 可能出现的字段；严格解码拒绝未知字段，
// 每个 catalog 预设决定哪些字段公开、哪些字段加密（见 splitAuthConfig）。
type AuthConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	IssuerURL    string `json:"issuer_url"`
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
	InstanceURL  string `json:"instance_url"`
	TeamID       string `json:"team_id"`
	KeyID        string `json:"key_id"`
	PrivateKey   string `json:"private_key"`
}

// ProviderMeta 是提供商配置的只读管理表示（异类列表投影），不含 nonce、密文或明文机密。
// Enabled 仅 OAuth/OIDC 有意义；CAPTCHA 提供商没有启用语义。
type ProviderMeta struct {
	ProviderKey  string
	Kind         domain.ProviderKind
	Enabled      bool
	Configured   bool
	PublicConfig json.RawMessage
}

// ProviderService 校验并存储提供商配置，机密装入 AES-256-GCM envelope。
// CAPTCHA 与 OAuth/OIDC 使用各自的类型化语义：CAPTCHA 无 enabled，由 captcha_provider
// 选择设置决定当前使用者；OAuth/OIDC 通过 enabled 独立启用并允许多个同时启用。
type ProviderService struct {
	txRunner           TxRunner
	settings           *repository.SettingsRepo
	key                []byte
	prober             Prober
	invalidateSettings func()
}

// Prober 执行有界外部连通性检查，供管理员提供商测试端点使用。
type Prober interface {
	ProbeCaptcha(ctx context.Context, cfg CaptchaConfig) error
	ProbeURL(ctx context.Context, rawURL string) error
}

// networkProber 是生产环境的 prober。
type networkProber struct{}

// ProbeCaptcha 对验证码提供商执行有界连通性检查。
func (networkProber) ProbeCaptcha(ctx context.Context, cfg CaptchaConfig) error {
	return captcha.Probe(ctx, captcha.Config{
		Provider:  cfg.Provider,
		SecretKey: cfg.SecretKey,
		Endpoint:  cfg.Endpoint,
		Timeout:   testProbeTimeout,
	}, nil)
}

// ProbeURL 对给定 URL 执行有界连通性检查。
func (networkProber) ProbeURL(ctx context.Context, rawURL string) error {
	return netprobe.ProbeURL(ctx, rawURL, testProbeTimeout)
}

// NewProviderService 构建提供商服务。
func NewProviderService(txRunner TxRunner, settings *repository.SettingsRepo, secretKey []byte) *ProviderService {
	return &ProviderService{txRunner: txRunner, settings: settings, key: secretKey, prober: networkProber{}}
}

// SetProber 安装自定义连通性 prober。
func (s *ProviderService) SetProber(p Prober) {
	if p != nil {
		s.prober = p
	}
}

// SetSettingsInvalidator 安装设置快照失效回调，供删除 CAPTCHA provider 清空选择后同步失效。
func (s *ProviderService) SetSettingsInvalidator(fn func()) {
	if fn != nil {
		s.invalidateSettings = fn
	}
}

// List 返回全部提供商的只读管理表示（异类投影），按 provider key 升序。
// CAPTCHA 项无启用语义；OAuth/OIDC 项携带 enabled。
func (s *ProviderService) List(ctx context.Context) ([]ProviderMeta, error) {
	captchas, err := s.settings.ListCaptchaProviders(ctx)
	if err != nil {
		return nil, err
	}
	auths, err := s.settings.ListAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	metas := make([]ProviderMeta, 0, len(captchas)+len(auths))
	for _, row := range captchas {
		metas = append(metas, ProviderMeta{
			ProviderKey:  row.ProviderKey,
			Kind:         domain.ProviderKindCaptcha,
			Configured:   len(row.SecretCiphertext) > 0,
			PublicConfig: publicRaw(row.PublicConfig),
		})
	}
	for _, row := range auths {
		metas = append(metas, ProviderMeta{
			ProviderKey:  row.ProviderKey,
			Kind:         row.Kind,
			Enabled:      row.Enabled,
			Configured:   len(row.SecretCiphertext) > 0,
			PublicConfig: publicRaw(row.PublicConfig),
		})
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].ProviderKey < metas[j].ProviderKey })
	return metas, nil
}

// publicRaw 返回公开配置原始 JSON；空值归一化为空对象。
func publicRaw(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage{}
	}
	return json.RawMessage(raw)
}

// validateProviderKey 校验 provider key 非空且不与公开选择设置行 key 冲突。
func validateProviderKey(providerKey string) error {
	if strings.TrimSpace(providerKey) == "" {
		return fmt.Errorf("%w: provider key must not be empty", domain.ErrValidation)
	}
	if repository.ProviderSettingKey(providerKey) == repository.CaptchaProviderSettingKey {
		return fmt.Errorf("%w: provider key %q conflicts with the captcha selector setting", domain.ErrValidation, providerKey)
	}
	return nil
}

// UpsertCaptcha 校验并写入 CAPTCHA provider 配置；CAPTCHA 没有 enabled 语义。
// provider key 必须与 config.provider 类型一致（每种验证码类型只允许一个配置）。
func (s *ProviderService) UpsertCaptcha(ctx context.Context, providerKey string, config json.RawMessage) error {
	if err := validateProviderKey(providerKey); err != nil {
		return err
	}
	var parsed CaptchaConfig
	if err := decode(config, &parsed); err != nil {
		return err
	}
	if strings.TrimSpace(parsed.Provider) != providerKey {
		return fmt.Errorf("%w: captcha provider key %q must match provider type %q", domain.ErrValidation, providerKey, parsed.Provider)
	}
	public, secret, err := splitConfig(domain.ProviderKindCaptcha, config)
	if err != nil {
		return err
	}
	secretEnvelope, err := cryptox.Encrypt(s.key, masterKeyVersion, secret)
	if err != nil {
		return fmt.Errorf("setting: encrypt provider secret: %w", err)
	}
	nonce := secretEnvelope[1 : 1+12]
	ciphertext := secretEnvelope[1+12:]
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		return s.settings.UpsertCaptchaProvider(ctx, &repository.CaptchaProviderRow{
			ProviderKey:      providerKey,
			PublicConfig:     public,
			SecretKeyVersion: int(masterKeyVersion),
			SecretNonce:      nonce,
			SecretCiphertext: ciphertext,
		})
	})
}

// UpsertAuth 校验并写入 OAuth/OIDC provider 配置；enabled 独立启用并允许多个同时启用。
// key/kind 矩阵在持久化前强制：固定 catalog 预设要求其目录 kind，未知 key 只允许自定义 OIDC。
// Secret 更新契约：新建必须提供该 provider 的机密字段（client_secret 或 Apple private_key）；
// 编辑缺省/空机密原样复用现有 envelope，非空机密才加密替换；无现有 envelope 且无新机密返回 validation。
func (s *ProviderService) UpsertAuth(ctx context.Context, providerKey string, kind domain.ProviderKind, enabled bool, config json.RawMessage) error {
	if err := validateProviderKey(providerKey); err != nil {
		return err
	}
	if err := validateAuthKeyKind(providerKey, kind); err != nil {
		return err
	}
	public, newSecret, err := splitAuthConfig(providerKey, kind, config)
	if err != nil {
		return err
	}
	existing, getErr := s.settings.GetAuthProvider(ctx, providerKey)
	if getErr != nil && !errors.Is(getErr, domain.ErrNotFound) {
		return getErr
	}
	row := &repository.AuthProviderRow{
		ProviderKey:  providerKey,
		Kind:         kind,
		Enabled:      enabled,
		PublicConfig: public,
	}
	if len(newSecret) > 0 {
		secretEnvelope, err := cryptox.Encrypt(s.key, masterKeyVersion, newSecret)
		if err != nil {
			return fmt.Errorf("setting: encrypt provider secret: %w", err)
		}
		row.SecretKeyVersion = int(masterKeyVersion)
		row.SecretNonce = secretEnvelope[1 : 1+12]
		row.SecretCiphertext = secretEnvelope[1+12:]
	} else if existing != nil && len(existing.SecretCiphertext) > 0 {
		row.SecretKeyVersion = existing.SecretKeyVersion
		row.SecretNonce = existing.SecretNonce
		row.SecretCiphertext = existing.SecretCiphertext
	} else {
		return fmt.Errorf("%w: provider secret is required when creating or re-encrypting a provider", domain.ErrValidation)
	}
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		return s.settings.UpsertAuthProvider(ctx, row)
	})
}

// validateAuthKeyKind 强制 OAuth/OIDC 的 key/kind 支持矩阵：
// 固定 catalog 预设必须使用其目录 kind，未知 key 保持自定义 OIDC；其余组合一律拒绝。
func validateAuthKeyKind(providerKey string, kind domain.ProviderKind) error {
	if spec, ok := oauth.LookupProvider(providerKey); ok {
		if spec.Kind != string(kind) {
			return fmt.Errorf("%w: %s provider must use %s kind", domain.ErrValidation, providerKey, spec.Kind)
		}
		return nil
	}
	if kind != domain.ProviderKindOIDC {
		return fmt.Errorf("%w: custom providers only support oidc kind", domain.ErrValidation)
	}
	return nil
}

// Delete 删除提供商配置；删除当前选中的 CAPTCHA provider 时在同一事务清空选择设置，
// 删除未选中的 provider 不影响当前选择。
func (s *ProviderService) Delete(ctx context.Context, providerKey string) error {
	err := s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.clearSelectionIfSelected(ctx, providerKey); err != nil {
			return err
		}
		return s.deleteProviderRow(ctx, providerKey)
	})
	if err != nil {
		return err
	}
	if s.invalidateSettings != nil {
		s.invalidateSettings()
	}
	return nil
}

// clearSelectionIfSelected 当删除的 provider 是当前选中的 CAPTCHA provider 时清空选择设置。
func (s *ProviderService) clearSelectionIfSelected(ctx context.Context, providerKey string) error {
	if _, err := s.settings.GetCaptchaProvider(ctx, providerKey); errors.Is(err, domain.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	selected, err := s.selectedCaptchaProvider(ctx)
	if err != nil {
		return err
	}
	if selected != providerKey {
		return nil
	}
	return s.settings.Upsert(ctx, []repository.DynamicSettingRow{{
		Key: SettingKeyCaptchaProvider, Type: string(SettingTypeString), Value: []byte(`""`), UpdatedBy: 0,
	}})
}

// deleteProviderRow 按实际类型删除 provider 配置行。
func (s *ProviderService) deleteProviderRow(ctx context.Context, providerKey string) error {
	if err := s.settings.DeleteCaptchaProvider(ctx, providerKey); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if err := s.settings.DeleteAuthProvider(ctx, providerKey); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	return domain.ErrNotFound
}

// Test 对已配置且启用的提供商执行有界外部连通性检查。
func (s *ProviderService) Test(ctx context.Context, providerKey string) error {
	if cfg, err := s.CaptchaProvider(ctx, providerKey); err == nil {
		if err := s.prober.ProbeCaptcha(ctx, *cfg); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrUnavailable, err)
		}
		return nil
	} else if !errors.Is(err, domain.ErrProviderNotFound) && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	provider, err := s.AuthProvider(ctx, providerKey)
	if err != nil {
		return err
	}
	// Apple 的连通性测试在探测网络前先解析 ES256 私钥：私钥损坏属于配置错误，
	// 会在任何远程请求发起之前以 validation 失败，无效配置不产生可达性结果。
	if provider.ProviderKey == "apple" {
		if err := oauth.ValidateApplePrivateKey(provider.ApplePrivateKey); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrValidation, err)
		}
	}
	target, err := authProbeTarget(provider)
	if err != nil {
		return err
	}
	if err := s.prober.ProbeURL(ctx, target); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrUnavailable, err)
	}
	return nil
}

// 固定 provider 的连通性探测目标（仅公开数据，不含机密）。
const (
	twitterAuthURL     = "https://x.com/i/oauth2/authorize"
	discordAuthURL     = "https://discord.com/oauth2/authorize"
	microsoftDiscovery = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
	lineDiscovery      = "https://access.line.me/.well-known/openid-configuration"
	appleJWKSProbeURL  = "https://appleid.apple.com/auth/keys"
)

// authProbeTarget 返回 OAuth/OIDC provider 的连通性探测目标：
// discovery 类探测其 issuer/discovery 端点，固定 OAuth 探测授权端点；
// Apple 探测其固定 JWKS 端点（私钥解析由 ProviderService.Test 提前完成）。
func authProbeTarget(provider *AuthProvider) (string, error) {
	spec, ok := oauth.LookupProvider(provider.ProviderKey)
	if !ok {
		if provider.IssuerURL == "" {
			return "", fmt.Errorf("%w: oidc issuer url is required", domain.ErrValidation)
		}
		return provider.IssuerURL, nil
	}
	if spec.Kind == "oauth" {
		switch provider.ProviderKey {
		case "github":
			return provider.AuthURL, nil
		case "twitter":
			return twitterAuthURL, nil
		case "discord":
			return discordAuthURL, nil
		}
	}
	switch provider.ProviderKey {
	case "google":
		return provider.IssuerURL, nil
	case "gitlab", "gitea":
		if provider.InstanceURL == "" {
			return "", fmt.Errorf("%w: instance url is required", domain.ErrValidation)
		}
		return provider.InstanceURL + "/.well-known/openid-configuration", nil
	case "mastodon":
		if provider.InstanceURL == "" {
			return "", fmt.Errorf("%w: instance url is required", domain.ErrValidation)
		}
		return provider.InstanceURL + "/.well-known/oauth-authorization-server", nil
	case "microsoft":
		return microsoftDiscovery, nil
	case "line":
		return lineDiscovery, nil
	case "apple":
		return appleJWKSProbeURL, nil
	}
	return "", fmt.Errorf("%w: no probe target for provider %q", domain.ErrValidation, provider.ProviderKey)
}

// testProbeTimeout 限制每次外部连通性探测。
const testProbeTimeout = 5 * time.Second

// CaptchaProvider 返回指定 CAPTCHA provider 的解密配置（含机密）。
// provider 缺失、类型不符或未配置时返回 domain.ErrProviderNotFound；密钥损坏时返回 domain.ErrSecretCorrupt。
func (s *ProviderService) CaptchaProvider(ctx context.Context, providerKey string) (*CaptchaConfig, error) {
	row, err := s.settings.GetCaptchaProvider(ctx, providerKey)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrProviderNotFound
		}
		return nil, err
	}
	if len(row.SecretCiphertext) == 0 {
		return nil, domain.ErrProviderNotFound
	}
	return s.captchaConfig(row)
}

// SelectedCaptcha 返回当前选择的 CAPTCHA provider 的解密配置。
// 未选择时返回 domain.ErrProviderNotFound；选择指向缺失、类型不符、未配置或密钥损坏的
// provider 时返回相应错误（默认拒绝，绝不回退到其他 provider）。
func (s *ProviderService) SelectedCaptcha(ctx context.Context) (*CaptchaConfig, error) {
	selected, err := s.selectedCaptchaProvider(ctx)
	if err != nil {
		return nil, err
	}
	if selected == "" {
		return nil, domain.ErrProviderNotFound
	}
	return s.CaptchaProvider(ctx, selected)
}

// ValidateSelection 校验 captcha_provider 选择指向可用的 CAPTCHA provider。
// 空选择（清空）直接通过；选择缺失、类型不符、未配置或密钥损坏时返回 domain.ErrCaptchaUnavailable。
func (s *ProviderService) ValidateSelection(ctx context.Context, providerKey string) error {
	if providerKey == "" {
		return nil
	}
	if _, err := s.CaptchaProvider(ctx, providerKey); err != nil {
		return domain.ErrCaptchaUnavailable
	}
	return nil
}

// selectedCaptchaProvider 读取当前 captcha_provider 选择 key；行缺失视为未选择。
func (s *ProviderService) selectedCaptchaProvider(ctx context.Context) (string, error) {
	row, err := s.settings.Get(ctx, SettingKeyCaptchaProvider)
	if errors.Is(err, domain.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var selected string
	if err := json.Unmarshal(row.Value, &selected); err != nil {
		return "", fmt.Errorf("%w: captcha provider selection is corrupt", domain.ErrSecretCorrupt)
	}
	return selected, nil
}

// captchaConfig 将公共和解密后的机密数据块合并为类型化的 CaptchaConfig。
func (s *ProviderService) captchaConfig(row *repository.CaptchaProviderRow) (*CaptchaConfig, error) {
	cfg := CaptchaConfig{}
	if err := decodeConfigFields(row.PublicConfig, &cfg); err != nil {
		return nil, err
	}
	secret, err := s.decryptSecretEnvelope(row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext, row.ProviderKey)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(secret, &cfg); err != nil {
		return nil, fmt.Errorf("%w: captcha secret for %q is corrupt", domain.ErrSecretCorrupt, row.ProviderKey)
	}
	return &cfg, nil
}

// AuthProvider 是返回给消费者的类型化、解密后的 OAuth/OIDC 配置。
type AuthProvider struct {
	ProviderKey  string
	Kind         domain.ProviderKind
	Enabled      bool
	Configured   bool
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	IssuerURL    string
	// InstanceURL 是自托管实例的规范化 HTTPS 基址（GitLab/Gitea/Mastodon）。
	InstanceURL string
	// AppleTeamID 是 Apple client-secret JWT 的 iss。
	AppleTeamID string
	// AppleKeyID 是 Apple client-secret JWT 的 kid。
	AppleKeyID string
	// ApplePrivateKey 是 Apple 的 P-256 .p8 私钥。
	ApplePrivateKey string
}

// AuthProviders 列出已启用的 OAuth/OIDC 提供商及其解密后的凭证。
func (s *ProviderService) AuthProviders(ctx context.Context) ([]AuthProvider, error) {
	rows, err := s.settings.ListAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AuthProvider, 0, len(rows))
	for _, row := range rows {
		if !row.Enabled || len(row.SecretCiphertext) == 0 {
			continue
		}
		provider, err := s.AuthProvider(ctx, row.ProviderKey)
		if err != nil {
			return nil, err
		}
		out = append(out, *provider)
	}
	return out, nil
}

// AuthProvider 返回一个 OAuth/OIDC 提供商的解密配置。
// provider 缺失、类型不符、未启用或未配置时返回 domain.ErrProviderNotFound；密钥损坏时返回 domain.ErrSecretCorrupt。
func (s *ProviderService) AuthProvider(ctx context.Context, providerKey string) (*AuthProvider, error) {
	row, err := s.settings.GetAuthProvider(ctx, providerKey)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrProviderNotFound
		}
		return nil, err
	}
	if !row.Enabled || len(row.SecretCiphertext) == 0 {
		return nil, fmt.Errorf("%w: provider %q is not configured or enabled", domain.ErrProviderNotFound, providerKey)
	}
	secret, err := s.decryptSecretEnvelope(row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext, row.ProviderKey)
	if err != nil {
		return nil, err
	}
	var cfg AuthConfig
	if err := decodeConfigFields(json.RawMessage(row.PublicConfig), &cfg); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(secret, &cfg); err != nil {
		return nil, fmt.Errorf("%w: provider secret for %q is corrupt", domain.ErrSecretCorrupt, providerKey)
	}
	return &AuthProvider{
		ProviderKey:     row.ProviderKey,
		Kind:            row.Kind,
		Enabled:         row.Enabled,
		Configured:      true,
		ClientID:        cfg.ClientID,
		ClientSecret:    cfg.ClientSecret,
		AuthURL:         cfg.AuthURL,
		TokenURL:        cfg.TokenURL,
		IssuerURL:       cfg.IssuerURL,
		InstanceURL:     cfg.InstanceURL,
		AppleTeamID:     cfg.TeamID,
		AppleKeyID:      cfg.KeyID,
		ApplePrivateKey: cfg.PrivateKey,
	}, nil
}

// decodeConfigFields 将 public_config 数据块解码为类型化配置。
func decodeConfigFields(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%w: provider public config is corrupt", domain.ErrSecretCorrupt)
	}
	return nil
}

// decryptSecretEnvelope 重建 envelope（version || nonce || ciphertext），并用当前主密钥解密。
func (s *ProviderService) decryptSecretEnvelope(version int, nonce, ciphertext []byte, providerKey string) ([]byte, error) {
	if version != int(masterKeyVersion) {
		return nil, domain.ErrSecretCorrupt
	}
	envelope := make([]byte, 0, 1+len(nonce)+len(ciphertext))
	envelope = append(envelope, masterKeyVersion)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)
	return cryptox.Decrypt(s.key, masterKeyVersion, envelope)
}

// splitConfig 解析并校验 CAPTCHA provider 配置，返回公共 JSON 与待加密的机密 JSON。
func splitConfig(kind domain.ProviderKind, raw json.RawMessage) ([]byte, []byte, error) {
	if kind != domain.ProviderKindCaptcha {
		return nil, nil, fmt.Errorf("%w: unknown provider kind %q", domain.ErrValidation, kind)
	}
	var cfg CaptchaConfig
	if err := decode(raw, &cfg); err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(cfg.Endpoint) != "" {
		normalized, err := normalizeHTTPSURL(cfg.Endpoint)
		if err != nil {
			return nil, nil, err
		}
		cfg.Endpoint = normalized
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	public := map[string]any{"provider": cfg.Provider, "site_key": cfg.SiteKey}
	if cfg.Endpoint != "" {
		public["endpoint"] = cfg.Endpoint
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		return nil, nil, err
	}
	secret, err := json.Marshal(map[string]any{"secret_key": cfg.SecretKey})
	if err != nil {
		return nil, nil, err
	}
	return publicJSON, secret, nil
}

// splitAuthConfig 解析并校验 OAuth/OIDC provider 配置。
// 固定 catalog 预设按目录 schema 拆分公开字段与机密字段；未知 key 按自定义 OIDC 处理
// （必须提供 HTTPS Issuer）。GitHub 固定 auth/token 端点，Google 固定 Issuer，由目录预设锁定。
// 返回公共 JSON 与可选的新 Secret JSON（缺省/空机密返回 nil，表示保留现有 envelope）。
func splitAuthConfig(providerKey string, kind domain.ProviderKind, raw json.RawMessage) ([]byte, []byte, error) {
	if err := validateAuthKeyKind(providerKey, kind); err != nil {
		return nil, nil, err
	}
	spec := authConfigSpec(providerKey)
	var cfg AuthConfig
	if err := decodeAuth(raw, &cfg); err != nil {
		return nil, nil, err
	}
	applyAuthConfigDefaults(&cfg, spec)
	if err := validateAuthConfig(providerKey, &cfg, spec); err != nil {
		return nil, nil, err
	}
	public, err := publicAuthConfig(cfg, spec)
	if err != nil {
		return nil, nil, err
	}
	secret, err := secretAuthConfig(cfg, spec)
	if err != nil {
		return nil, nil, err
	}
	return public, secret, nil
}

// customOIDCSpec 是未知 key 的默认配置模式：任意 key + oidc，注册模式为可信邮箱。
var customOIDCSpec = oauth.ProviderSpec{
	Key:          "custom-oidc",
	Name:         "Custom OIDC",
	Kind:         "oidc",
	Registration: oauth.RegistrationVerifiedEmail,
	PKCE:         true,
	Nonce:        true,
	Callback:     oauth.CallbackQuery,
	Config: oauth.ConfigSpec{
		PublicFields: []string{"client_id", "issuer_url"},
		SecretField:  "client_secret",
	},
}

// authConfigSpec 返回 provider 的配置 schema：目录预设优先，未知 key 按自定义 OIDC。
func authConfigSpec(providerKey string) oauth.ProviderSpec {
	if spec, ok := oauth.LookupProvider(providerKey); ok {
		return *spec
	}
	return customOIDCSpec
}

// applyAuthConfigDefaults 应用预设锁定的公开字段值，覆盖管理端提交的同名字段。
func applyAuthConfigDefaults(cfg *AuthConfig, spec oauth.ProviderSpec) {
	for field, value := range spec.Config.FixedPublic {
		switch field {
		case "auth_url":
			cfg.AuthURL = value
		case "token_url":
			cfg.TokenURL = value
		case "issuer_url":
			cfg.IssuerURL = value
		}
	}
}

// validateAuthConfig 按 provider 的配置 schema 校验必填字段与规范化规则。
// client_id 对所有 provider 必填；instance_url 按预设要求默认/必填并做 HTTPS 规范化；
// Apple 的 key_id 与 private_key 必须作为原子对出现；自定义 OIDC 必须提供 HTTPS Issuer。
func validateAuthConfig(providerKey string, cfg *AuthConfig, spec oauth.ProviderSpec) error {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return fmt.Errorf("%w: %s client id is required", domain.ErrValidation, providerKey)
	}
	if spec.Config.InstanceURLRequired || spec.Config.InstanceURLDefault != "" || strings.TrimSpace(cfg.InstanceURL) != "" {
		raw := strings.TrimSpace(cfg.InstanceURL)
		if raw == "" {
			if spec.Config.InstanceURLRequired {
				return fmt.Errorf("%w: %s instance url is required", domain.ErrValidation, providerKey)
			}
			raw = spec.Config.InstanceURLDefault
		}
		normalized, err := normalizeInstanceURL(raw, providerKey == "mastodon")
		if err != nil {
			return err
		}
		cfg.InstanceURL = normalized
	}
	if providerKey == "apple" {
		if strings.TrimSpace(cfg.TeamID) == "" {
			return fmt.Errorf("%w: apple team id is required", domain.ErrValidation)
		}
		// key_id 与 private_key 必须作为原子对轮换：提供新私钥时必须同时提供 key_id；
		// 编辑缺省/空私钥时 key_id 可照常随公开字段往返，机密保留现有 envelope。
		if strings.TrimSpace(cfg.PrivateKey) != "" && strings.TrimSpace(cfg.KeyID) == "" {
			return fmt.Errorf("%w: apple key id is required when the private key is supplied", domain.ErrValidation)
		}
	}
	if _, inCatalog := oauth.LookupProvider(providerKey); !inCatalog {
		if !validHTTPSURL(cfg.IssuerURL) || !strings.HasPrefix(cfg.IssuerURL, "https://") {
			return fmt.Errorf("%w: oidc issuer url must be an absolute https url", domain.ErrValidation)
		}
	}
	return nil
}

// publicAuthConfig 构建存储到 public_config 的 JSON，只包含预设公开字段的非空值，绝不包含机密。
func publicAuthConfig(cfg AuthConfig, spec oauth.ProviderSpec) ([]byte, error) {
	values := map[string]any{}
	for _, field := range spec.Config.PublicFields {
		switch field {
		case "client_id":
			if cfg.ClientID != "" {
				values[field] = cfg.ClientID
			}
		case "issuer_url":
			if cfg.IssuerURL != "" {
				values[field] = cfg.IssuerURL
			}
		case "auth_url":
			if cfg.AuthURL != "" {
				values[field] = cfg.AuthURL
			}
		case "token_url":
			if cfg.TokenURL != "" {
				values[field] = cfg.TokenURL
			}
		case "instance_url":
			if cfg.InstanceURL != "" {
				values[field] = cfg.InstanceURL
			}
		case "team_id":
			if cfg.TeamID != "" {
				values[field] = cfg.TeamID
			}
		case "key_id":
			if cfg.KeyID != "" {
				values[field] = cfg.KeyID
			}
		default:
			return nil, fmt.Errorf("setting: unsupported public field %q", field)
		}
	}
	return json.Marshal(values)
}

// secretAuthConfig 构建待加密的 secret JSON；空值返回 nil（保留现有 envelope）。
func secretAuthConfig(cfg AuthConfig, spec oauth.ProviderSpec) ([]byte, error) {
	switch spec.Config.SecretField {
	case "client_secret":
		return optionalSecret("client_secret", cfg.ClientSecret)
	case "private_key":
		return optionalSecret("private_key", cfg.PrivateKey)
	default:
		return nil, nil
	}
}

// optionalSecret 仅当 secret 非空时返回待加密的 secret JSON，空值返回 nil（保留现有 envelope）。
func optionalSecret(field, secret string) ([]byte, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, nil
	}
	return json.Marshal(map[string]any{field: secret})
}

// decodeAuth 严格解析 OAuth/OIDC provider 配置：拒绝未知字段与尾随数据。
func decodeAuth(raw json.RawMessage, into *AuthConfig) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: provider config is required", domain.ErrValidation)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%w: malformed provider config", domain.ErrValidation)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("%w: malformed provider config", domain.ErrValidation)
	}
	return nil
}

// decode 解析必填的提供商配置，空值或格式错误时返回 domain.ErrValidation。
func decode(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: provider config is required", domain.ErrValidation)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%w: malformed provider config", domain.ErrValidation)
	}
	return nil
}

// Validate 校验验证码提供商的类型、site key/secret key 必填，以及 CAP 的绝对端点。
// endpoint 对任意类型都允许（覆盖 siteverify 端点）；非空必须为 http(s) 绝对 URL，
// CAP 类型必填。
func (c CaptchaConfig) Validate() error {
	switch c.Provider {
	case "turnstile", "recaptcha", "hcaptcha", "cap":
	default:
		return fmt.Errorf("%w: captcha provider must be turnstile, recaptcha, hcaptcha or cap", domain.ErrValidation)
	}
	if strings.TrimSpace(c.SiteKey) == "" || strings.TrimSpace(c.SecretKey) == "" {
		return fmt.Errorf("%w: captcha site key and secret key are required", domain.ErrValidation)
	}
	if c.Provider == "cap" {
		if !validHTTPSURL(c.Endpoint) {
			return fmt.Errorf("%w: cap endpoint must be an absolute http(s) url", domain.ErrValidation)
		}
		return nil
	}
	if strings.TrimSpace(c.Endpoint) != "" && !validHTTPSURL(c.Endpoint) {
		return fmt.Errorf("%w: captcha endpoint must be an absolute http(s) url", domain.ErrValidation)
	}
	return nil
}

// validHTTPSURL 判断字符串是否为带主机名的 http/https 绝对 URL。
func validHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

// normalizeHTTPSURL 校验并规范化绝对 http(s) URL：
// 去除尾部斜杠与查询/片段，不改动主机与协议。
func normalizeHTTPSURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("%w: captcha endpoint must be an absolute http(s) url", domain.ErrValidation)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String(), nil
}

// normalizeInstanceURL 校验并规范化自托管实例地址：
// 仅接受 https，拒绝 userinfo/query/fragment，主机名小写并去掉默认端口与尾部斜杠；
// rootOnly 时禁止部署子路径（Mastodon 的规范部署根是 origin）。
func normalizeInstanceURL(raw string, rootOnly bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: instance url must be an absolute https url without userinfo, query or fragment", domain.ErrValidation)
	}
	if rootOnly && u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("%w: mastodon instance url must be a root origin without a path", domain.ErrValidation)
	}
	u.Scheme = "https"
	u.Host = normalizeURLHost(u)
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String(), nil
}

// normalizeURLHost 小写化主机名、保留非默认端口并去掉默认 https 端口（443）。
func normalizeURLHost(u *url.URL) string {
	name := strings.ToLower(u.Hostname())
	if strings.Contains(name, ":") {
		name = "[" + name + "]"
	}
	if port := u.Port(); port != "" && port != "443" {
		name += ":" + port
	}
	return name
}

// SMTPProbe 对静态 SMTP 配置执行有界连通性检查。
type SMTPProbe struct {
	cfg    mailer.SMTPConfig
	prober SMTPProber
}

// SMTPProber 运行静态 SMTP 配置的有界连通性检查。
type SMTPProber interface {
	ProbeSMTP(ctx context.Context, cfg mailer.SMTPConfig) error
}

// smtpProber 是生产环境的 prober。
type smtpProber struct{}

// ProbeSMTP 对给定 SMTP 配置执行有界连通性检查。
func (smtpProber) ProbeSMTP(ctx context.Context, cfg mailer.SMTPConfig) error {
	return mailer.Probe(ctx, cfg)
}

// NewSMTPProbe 构建 SMTP 连通性检查用例。
func NewSMTPProbe(cfg mailer.SMTPConfig) *SMTPProbe {
	return &SMTPProbe{cfg: cfg, prober: smtpProber{}}
}

// SetProber 安装自定义连通性 prober。
func (s *SMTPProbe) SetProber(p SMTPProber) {
	if p != nil {
		s.prober = p
	}
}

// Test 对静态 SMTP 配置执行有界连通性检查。
func (s *SMTPProbe) Test(ctx context.Context) error {
	if s.cfg.Host == "" {
		return fmt.Errorf("%w: smtp is not configured", domain.ErrValidation)
	}
	if err := s.prober.ProbeSMTP(ctx, s.cfg); err != nil {
		switch {
		case errors.Is(err, mailer.ErrConfig):
			return fmt.Errorf("%w: %v", domain.ErrValidation, err)
		case errors.Is(err, mailer.ErrUnavailable):
			return fmt.Errorf("%w: %v", domain.ErrUnavailable, err)
		default:
			return err
		}
	}
	return nil
}

package setting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/captcha"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/netprobe"
	"furtalk/internal/platform/notifier"
	"furtalk/internal/platform/oauth"
	"furtalk/internal/platform/spam"
	"furtalk/internal/platform/urlx"
	"furtalk/internal/repository"
)

// masterKeyVersion 是当前 AES-GCM envelope 密钥版本。
const masterKeyVersion byte = cryptox.ProviderEnvelopeVersion

// CaptchaConfig  CAPTCHA 提供商的类型化配置，含机密。
// Endpoint 仅 CAP 使用，管理员配置的外部 Standalone 实例基址，属于公开字段。
type CaptchaConfig struct {
	Provider  string `json:"provider"`
	SiteKey   string `json:"site_key"`
	SecretKey string `json:"secret_key"`
	Endpoint  string `json:"endpoint"`
}

// AuthConfig  OAuth/OIDC provider 的通用类型化配置，客户端密钥在持久化前加密。
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

// SpamConfig 垃圾检测 provider 的通用类型化配置，含机密。
// 固定 provider key 决定哪些字段公开、哪些字段加密（见 spamProviderSpec）。
type SpamConfig struct {
	// CheckNickname 本地词库渠道字段；CheckNickname 开启时昵称也参与匹配。
	CheckNickname bool `json:"check_nickname"`
	// Action 本地/Akismet 二元检测器的命中动作，仅允许 pending 或 spam。
	Action string `json:"action"`
	// APIKey  Akismet 的 API key，加密保存。
	APIKey string `json:"api_key"`
	// Region 与 BizType 阿里云/腾讯云渠道字段；BizType 可选。
	Region  string `json:"region"`
	BizType string `json:"biz_type"`
	// AccessKeyID 与 AccessKeySecret 阿里云凭据，加密保存。
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	// SecretID 与 SecretKey 腾讯云凭据，加密保存。
	SecretID  string `json:"secret_id"`
	SecretKey string `json:"secret_key"`
}

// NotificationConfig 是通知通道 provider 的类型化配置，机密字段在持久化前加密。
// 平台字段做并集；每个固定 key 只使用自己声明的字段（见 notificationProviderSpec）。
type NotificationConfig struct {
	BotToken           string `json:"bot_token"`
	ChatID             string `json:"chat_id"`
	WebhookURL         string `json:"webhook_url"`
	ServerURL          string `json:"server_url"`
	DeviceKey          string `json:"device_key"`
	ChannelAccessToken string `json:"channel_access_token"`
	TargetID           string `json:"target_id"`
	// SigningSecret 可选签名密钥（feishu/dingtalk/webhook），三态处理：
	// 缺省保留现值、显式 null 清除、非空替换。
	SigningSecret *string `json:"signing_secret"`
}

// notificationConfigInput 通知通道配置的严格解析输入。
// SigningSecret 用 RawMessage 区分三种状态：缺失（nil）=保留、null=清除、非空=替换。
type notificationConfigInput struct {
	BotToken           string          `json:"bot_token"`
	ChatID             string          `json:"chat_id"`
	WebhookURL         string          `json:"webhook_url"`
	ServerURL          string          `json:"server_url"`
	DeviceKey          string          `json:"device_key"`
	ChannelAccessToken string          `json:"channel_access_token"`
	TargetID           string          `json:"target_id"`
	SigningSecret      json.RawMessage `json:"signing_secret"`
}

// notificationProviderSpec 描述一个固定通知通道 key 的配置模式。
// secretFields 必填机密字段；optionalSecretFields 是可选的机密字段（三态处理）。
type notificationProviderSpec struct {
	key                  string
	publicFields         []string
	secretFields         []string
	optionalSecretFields []string
}

// notificationProviderKeys 固定的通知通道 provider key 顺序（投递顺序）。
// 独立命名空间，避免与 OAuth 的 line/discord 等 key 冲突。
var notificationProviderKeys = []string{
	"notification.telegram",
	"notification.feishu",
	"notification.dingtalk",
	"notification.bark",
	"notification.slack",
	"notification.line",
	"notification.webhook",
	"notification.discord",
}

// notificationProviderSpecs 固定通知通道 provider 的配置矩阵。
// 除 Bark 的 server_url 外，所有目的地字段均按机密加密保存。
var notificationProviderSpecs = map[string]notificationProviderSpec{
	"notification.telegram": {
		key:          "notification.telegram",
		secretFields: []string{"bot_token", "chat_id"},
	},
	"notification.feishu": {
		key:                  "notification.feishu",
		secretFields:         []string{"webhook_url"},
		optionalSecretFields: []string{"signing_secret"},
	},
	"notification.dingtalk": {
		key:                  "notification.dingtalk",
		secretFields:         []string{"webhook_url"},
		optionalSecretFields: []string{"signing_secret"},
	},
	"notification.bark": {
		key:          "notification.bark",
		publicFields: []string{"server_url"},
		secretFields: []string{"device_key"},
	},
	"notification.slack": {
		key:          "notification.slack",
		secretFields: []string{"webhook_url"},
	},
	"notification.line": {
		key:          "notification.line",
		secretFields: []string{"channel_access_token", "target_id"},
	},
	"notification.webhook": {
		key:                  "notification.webhook",
		secretFields:         []string{"webhook_url"},
		optionalSecretFields: []string{"signing_secret"},
	},
	"notification.discord": {
		key:          "notification.discord",
		secretFields: []string{"webhook_url"},
	},
}

// ValidNotificationProviderKey 报告 key 是否为固定通知通道 provider key。
func ValidNotificationProviderKey(providerKey string) bool {
	_, ok := notificationProviderSpecs[providerKey]
	return ok
}

// isNotificationProviderKey 报告 key 是否属于保留的 notification.* 命名空间。
func isNotificationProviderKey(providerKey string) bool {
	return strings.HasPrefix(providerKey, "notification.")
}

// spamProviderSpec 描述一个固定垃圾检测 provider key 的配置模式。
// binary 表示二元检测器（本地/Akismet），携带 action；云检测器为三元且无 action。
type spamProviderSpec struct {
	key          string
	publicFields []string
	secretFields []string
	binary       bool
}

// spamProviderKeys 固定的垃圾检测 provider key 顺序（执行顺序）。
var spamProviderKeys = []string{"spam.local", "spam.akismet", "spam.aliyun", "spam.tencent"}

// spamProviderSpecs 固定垃圾检测 provider 的配置矩阵。
var spamProviderSpecs = map[string]spamProviderSpec{
	"spam.local": {
		key:          "spam.local",
		publicFields: []string{"check_nickname", "action"},
		binary:       true,
	},
	"spam.akismet": {
		key:          "spam.akismet",
		publicFields: []string{"action"},
		secretFields: []string{"api_key"},
		binary:       true,
	},
	"spam.aliyun": {
		key:          "spam.aliyun",
		publicFields: []string{"region", "biz_type"},
		secretFields: []string{"access_key_id", "access_key_secret"},
	},
	"spam.tencent": {
		key:          "spam.tencent",
		publicFields: []string{"region", "biz_type"},
		secretFields: []string{"secret_id", "secret_key"},
	},
}

// ValidSpamProviderKey 报告 key 否为固定垃圾检测 provider key。
func ValidSpamProviderKey(providerKey string) bool {
	_, ok := spamProviderSpecs[providerKey]
	return ok
}

// isSpamProviderKey 报告 key 是否属于保留的 spam.* 命名空间。
func isSpamProviderKey(providerKey string) bool {
	return strings.HasPrefix(providerKey, "spam.")
}

// validateSpamAction 校验二元检测器的命中动作只能是 pending 或 spam。
func validateSpamAction(action string) error {
	if action != "pending" && action != "spam" {
		return fmt.Errorf("%w: spam hit action must be pending or spam", domain.ErrValidation)
	}
	return nil
}

// ProviderMeta 提供商配置的只读管理表示（异类列表投影），不含 nonce、密文或明文机密。
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
	notificationTester NotificationTester
	log                *slog.Logger
}

// Prober 执行有界外部连通性检查，供管理员提供商测试端点使用。
type Prober interface {
	ProbeCaptcha(ctx context.Context, cfg CaptchaConfig) error
	ProbeURL(ctx context.Context, rawURL string) error
}

// NotificationTester 向通知通道发送显式标记的测试消息。
// 由组合根在通知服务装配完成后接线，设置层不感知通知业务消息内容；
// 测试允许在通道停用时执行，但要求配置完整。
type NotificationTester interface {
	TestNotification(ctx context.Context, providerKey string, cfg NotificationConfig) error
}

// networkProber 生产环境的 prober。
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

// NewProviderService 构建提供商服务，并只保留 provider envelope v2 的派生密钥。
func NewProviderService(txRunner TxRunner, settings *repository.SettingsRepo, secretKey []byte, logger *slog.Logger) (*ProviderService, error) {
	key, err := cryptox.DeriveProviderKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("setting: derive provider secret key: %w", err)
	}
	return &ProviderService{
		txRunner: txRunner,
		settings: settings,
		key:      append([]byte(nil), key...),
		prober:   networkProber{},
		log:      logging.Normalize(logger),
	}, nil
}

// AuditSecrets 在启动阶段只读检查所有已知 provider 的密文。
// 持久化数据问题只产生聚合 warning，不影响应用启动；具体 provider 在实际使用时仍 fail closed。
func (s *ProviderService) AuditSecrets(ctx context.Context) {
	type row struct {
		version    int
		nonce      []byte
		ciphertext []byte
	}
	var rows []row
	queryFailures := 0
	appendRows := func(values []row) {
		rows = append(rows, values...)
	}
	if values, err := s.settings.ListCaptchaProviders(ctx); err != nil {
		queryFailures++
	} else {
		converted := make([]row, 0, len(values))
		for _, value := range values {
			converted = append(converted, row{value.SecretKeyVersion, value.SecretNonce, value.SecretCiphertext})
		}
		appendRows(converted)
	}
	if values, err := s.settings.ListAuthProviders(ctx); err != nil {
		queryFailures++
	} else {
		converted := make([]row, 0, len(values))
		for _, value := range values {
			converted = append(converted, row{value.SecretKeyVersion, value.SecretNonce, value.SecretCiphertext})
		}
		appendRows(converted)
	}
	if values, err := s.settings.ListSpamProviders(ctx); err != nil {
		queryFailures++
	} else {
		converted := make([]row, 0, len(values))
		for _, value := range values {
			converted = append(converted, row{value.SecretKeyVersion, value.SecretNonce, value.SecretCiphertext})
		}
		appendRows(converted)
	}
	if values, err := s.settings.ListNotificationProviders(ctx); err != nil {
		queryFailures++
	} else {
		converted := make([]row, 0, len(values))
		for _, value := range values {
			converted = append(converted, row{value.SecretKeyVersion, value.SecretNonce, value.SecretCiphertext})
		}
		appendRows(converted)
	}

	scanned, unsupported, unreadable := 0, 0, 0
	for _, value := range rows {
		if len(value.ciphertext) == 0 {
			continue
		}
		scanned++
		if value.version != int(masterKeyVersion) {
			unsupported++
			continue
		}
		envelope := make([]byte, 0, 1+len(value.nonce)+len(value.ciphertext))
		envelope = append(envelope, masterKeyVersion)
		envelope = append(envelope, value.nonce...)
		envelope = append(envelope, value.ciphertext...)
		if _, err := cryptox.Decrypt(s.key, masterKeyVersion, envelope); err != nil {
			unreadable++
		}
	}
	if queryFailures > 0 || unsupported > 0 || unreadable > 0 {
		s.log.Warn("providers: startup secret audit found unusable envelopes",
			slog.Int("scanned", scanned),
			slog.Int("unsupported_versions", unsupported),
			slog.Int("unreadable", unreadable),
			slog.Int("query_failures", queryFailures),
			slog.Int("expected_version", int(masterKeyVersion)))
	}
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

// SetNotificationTester 安装通知通道测试器，供管理员测试端点实际发送测试消息。
func (s *ProviderService) SetNotificationTester(t NotificationTester) {
	if t != nil {
		s.notificationTester = t
	}
}

// List 返回全部提供商的只读管理表示（异类投影），按 provider key 升序。
// CAPTCHA 项无启用语义；OAuth/OIDC、垃圾检测与通知通道项携带 enabled。
func (s *ProviderService) List(ctx context.Context) ([]ProviderMeta, error) {
	captchas, err := s.settings.ListCaptchaProviders(ctx)
	if err != nil {
		return nil, err
	}
	auths, err := s.settings.ListAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	spams, err := s.settings.ListSpamProviders(ctx)
	if err != nil {
		return nil, err
	}
	notifications, err := s.settings.ListNotificationProviders(ctx)
	if err != nil {
		return nil, err
	}
	metas := make([]ProviderMeta, 0, len(captchas)+len(auths)+len(spams)+len(notifications))
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
	for _, row := range spams {
		metas = append(metas, ProviderMeta{
			ProviderKey:  row.ProviderKey,
			Kind:         domain.ProviderKindSpam,
			Enabled:      row.Enabled,
			Configured:   spamConfigured(row),
			PublicConfig: publicSpamRaw(row.ProviderKey, row.PublicConfig),
		})
	}
	for _, row := range notifications {
		metas = append(metas, ProviderMeta{
			ProviderKey:  row.ProviderKey,
			Kind:         domain.ProviderKindNotification,
			Enabled:      row.Enabled,
			Configured:   len(row.SecretCiphertext) > 0,
			PublicConfig: publicRaw(row.PublicConfig),
		})
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].ProviderKey < metas[j].ProviderKey })
	return metas, nil
}

// spamConfigured 判定垃圾检测 provider 的已配置状态。
// 本地词库渠道由合法公开字段决定（其信封允许无 Secret）；
// 外部渠道必须有非空密文。旧行中的 file_path 仅作为历史数据忽略。
func spamConfigured(row repository.SpamProviderRow) bool {
	if row.ProviderKey == "spam.local" {
		var public struct {
			Action string `json:"action"`
		}
		if len(row.PublicConfig) == 0 || json.Unmarshal(row.PublicConfig, &public) != nil {
			return false
		}
		return validateSpamAction(public.Action) == nil
	}
	return len(row.SecretCiphertext) > 0
}

// publicSpamRaw 返回垃圾检测公开配置；固定本地词库渠道过滤旧行中的
// file_path 字段，防止历史路径继续出现在管理 API 响应中。
func publicSpamRaw(providerKey string, raw []byte) json.RawMessage {
	if providerKey != "spam.local" || len(raw) == 0 {
		return publicRaw(raw)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return publicRaw(raw)
	}
	delete(fields, "file_path")
	filtered, err := json.Marshal(fields)
	if err != nil {
		return publicRaw(raw)
	}
	return filtered
}

// publicRaw 返回公开配置原始 JSON；空值归一化为空对象。
func publicRaw(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage{}
	}
	return json.RawMessage(raw)
}

// validateProviderKey 校验 provider key 非空、不与公开选择设置行 key 冲突，
// 且不占用保留的 spam.* / notification.* 命名空间（这两类 key 只允许对应类型的 upsert）。
func validateProviderKey(providerKey string) error {
	if strings.TrimSpace(providerKey) == "" {
		return fmt.Errorf("%w: provider key must not be empty", domain.ErrValidation)
	}
	if repository.ProviderSettingKey(providerKey) == repository.CaptchaProviderSettingKey {
		return fmt.Errorf("%w: provider key %q conflicts with the captcha selector setting", domain.ErrValidation, providerKey)
	}
	if isSpamProviderKey(providerKey) {
		return fmt.Errorf("%w: provider key %q is reserved for spam providers", domain.ErrValidation, providerKey)
	}
	if isNotificationProviderKey(providerKey) {
		return fmt.Errorf("%w: provider key %q is reserved for notification providers", domain.ErrValidation, providerKey)
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

// UpsertSpam 校验并写入垃圾检测 provider 配置；enabled 独立启用并允许多个渠道同时启用。
// 只接受固定 key：spam.local、spam.akismet、spam.aliyun、spam.tencent。
// Secret 更新契约：本地渠道无机密；外部渠道新建必须提供完整 Secret 组，编辑时整组
// 为空表示原样保留，部分提交拒绝，完整非空组才替换信封。
// enabled=true 必须同时满足公开配置与 Secret 完整，不能保存看似启用但不可运行的渠道。
func (s *ProviderService) UpsertSpam(ctx context.Context, providerKey string, enabled bool, config json.RawMessage) error {
	if !ValidSpamProviderKey(providerKey) {
		return fmt.Errorf("%w: unknown spam provider key %q", domain.ErrValidation, providerKey)
	}
	public, newSecret, err := s.splitSpamConfig(providerKey, config)
	if err != nil {
		return err
	}
	existing, getErr := s.settings.GetSpamProvider(ctx, providerKey)
	if getErr != nil && !errors.Is(getErr, domain.ErrNotFound) {
		return getErr
	}
	row := &repository.SpamProviderRow{
		ProviderKey:  providerKey,
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
	}
	if enabled {
		if err := validateSpamRunnable(providerKey, row); err != nil {
			return err
		}
	}
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		return s.settings.UpsertSpamProvider(ctx, row)
	})
}

// validateSpamRunnable 校验 enabled=true 的渠道确实具备运行条件：
// 本地渠道必须有合法公开字段；外部渠道必须有可用 Secret 信封。
func validateSpamRunnable(providerKey string, row *repository.SpamProviderRow) error {
	if providerKey == "spam.local" {
		var public struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(row.PublicConfig, &public); err != nil {
			return fmt.Errorf("%w: local keyword configuration is corrupt", domain.ErrValidation)
		}
		return validateSpamAction(public.Action)
	}
	if len(row.SecretCiphertext) == 0 {
		return fmt.Errorf("%w: provider secret is required when enabling %q", domain.ErrValidation, providerKey)
	}
	return nil
}

// SpamProvider 返回给消费者的类型化、解密后的垃圾检测配置。
type SpamProvider struct {
	ProviderKey string
	Enabled     bool
	Configured  bool
	Config      SpamConfig
}

// SpamProvider 返回一个垃圾检测 provider 的解密配置。
// provider 缺失、类型不符或未配置时返回 domain.ErrProviderNotFound；密钥损坏时返回 domain.ErrSecretCorrupt。
func (s *ProviderService) SpamProvider(ctx context.Context, providerKey string) (*SpamProvider, error) {
	row, err := s.settings.GetSpamProvider(ctx, providerKey)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrProviderNotFound
		}
		return nil, err
	}
	return s.spamProvider(row)
}

// EnabledSpamProviders 返回全部已启用且已配置的垃圾检测 provider 解密配置，按固定执行顺序。
func (s *ProviderService) EnabledSpamProviders(ctx context.Context) ([]SpamProvider, error) {
	rows, err := s.settings.ListSpamProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SpamProvider, 0, len(rows))
	for _, key := range spamProviderKeys {
		for _, row := range rows {
			if row.ProviderKey != key || !row.Enabled {
				continue
			}
			provider, err := s.spamProvider(&row)
			if err != nil {
				return nil, err
			}
			out = append(out, *provider)
			break
		}
	}
	return out, nil
}

// spamProvider 合并公开字段与解密后的机密字段为类型化配置。
// 只合并该渠道声明的机密字段，防止字段串位；本地渠道无信封直接返回公开配置。
func (s *ProviderService) spamProvider(row *repository.SpamProviderRow) (*SpamProvider, error) {
	provider := &SpamProvider{ProviderKey: row.ProviderKey, Enabled: row.Enabled, Configured: spamConfigured(*row)}
	if err := decodeConfigFields(row.PublicConfig, &provider.Config); err != nil {
		return nil, err
	}
	if len(row.SecretCiphertext) == 0 {
		return provider, nil
	}
	secret, err := s.decryptSecretEnvelope(row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext, row.ProviderKey)
	if err != nil {
		return nil, err
	}
	var secretCfg SpamConfig
	if err := json.Unmarshal(secret, &secretCfg); err != nil {
		return nil, fmt.Errorf("%w: provider secret for %q is corrupt", domain.ErrSecretCorrupt, row.ProviderKey)
	}
	switch row.ProviderKey {
	case "spam.akismet":
		provider.Config.APIKey = secretCfg.APIKey
	case "spam.aliyun":
		provider.Config.AccessKeyID = secretCfg.AccessKeyID
		provider.Config.AccessKeySecret = secretCfg.AccessKeySecret
	case "spam.tencent":
		provider.Config.SecretID = secretCfg.SecretID
		provider.Config.SecretKey = secretCfg.SecretKey
	}
	return provider, nil
}

// splitSpamConfig 解析并校验垃圾检测 provider 配置，返回公共 JSON 与待加密的机密 JSON。
func (s *ProviderService) splitSpamConfig(providerKey string, raw json.RawMessage) ([]byte, []byte, error) {
	spec, ok := spamProviderSpecs[providerKey]
	if !ok {
		return nil, nil, fmt.Errorf("%w: unknown spam provider key %q", domain.ErrValidation, providerKey)
	}
	var cfg SpamConfig
	if err := decodeSpam(raw, &cfg); err != nil {
		return nil, nil, err
	}
	if err := validateSpamConfig(providerKey, spec, &cfg); err != nil {
		return nil, nil, err
	}
	public, err := publicSpamConfig(cfg, spec)
	if err != nil {
		return nil, nil, err
	}
	secret, err := secretSpamConfig(cfg, spec)
	if err != nil {
		return nil, nil, err
	}
	return public, secret, nil
}

// validateSpamConfig 校验垃圾检测 provider 的字段：二元渠道的 action、本地固定词库
// 与云渠道的 region 必填。
func validateSpamConfig(providerKey string, spec spamProviderSpec, cfg *SpamConfig) error {
	if spec.binary {
		if err := validateSpamAction(cfg.Action); err != nil {
			return err
		}
	}
	if providerKey == "spam.local" {
		if err := spam.ValidateKeywordFile(); err != nil {
			if errors.Is(err, spam.ErrInvalidFile) {
				return fmt.Errorf("%w: %v", domain.ErrValidation, err)
			}
			return err
		}
	}
	if providerKey == "spam.aliyun" || providerKey == "spam.tencent" {
		if strings.TrimSpace(cfg.Region) == "" {
			return fmt.Errorf("%w: %s region is required", domain.ErrValidation, providerKey)
		}
	}
	return nil
}

// publicSpamConfig 构建存储到 public_config 的 JSON，只包含该渠道声明的公开字段。
func publicSpamConfig(cfg SpamConfig, spec spamProviderSpec) ([]byte, error) {
	values := map[string]any{}
	for _, field := range spec.publicFields {
		switch field {
		case "check_nickname":
			values[field] = cfg.CheckNickname
		case "action":
			if cfg.Action != "" {
				values[field] = cfg.Action
			}
		case "region":
			if cfg.Region != "" {
				values[field] = cfg.Region
			}
		case "biz_type":
			if cfg.BizType != "" {
				values[field] = cfg.BizType
			}
		default:
			return nil, fmt.Errorf("setting: unsupported spam public field %q", field)
		}
	}
	return json.Marshal(values)
}

// secretSpamConfig 构建待加密的 Secret JSON。
// 外部渠道 Secret 组必须全部为空或全部非空：部分提交拒绝，整组为空返回 nil（保留现有 envelope）。
func secretSpamConfig(cfg SpamConfig, spec spamProviderSpec) ([]byte, error) {
	if len(spec.secretFields) == 0 {
		return nil, nil
	}
	values := map[string]string{}
	for _, field := range spec.secretFields {
		switch field {
		case "api_key":
			values[field] = cfg.APIKey
		case "access_key_id":
			values[field] = cfg.AccessKeyID
		case "access_key_secret":
			values[field] = cfg.AccessKeySecret
		case "secret_id":
			values[field] = cfg.SecretID
		case "secret_key":
			values[field] = cfg.SecretKey
		default:
			return nil, fmt.Errorf("setting: unsupported spam secret field %q", field)
		}
	}
	hasAny := false
	hasBlank := false
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			hasAny = true
		} else {
			hasBlank = true
		}
	}
	if hasAny && hasBlank {
		return nil, fmt.Errorf("%w: %s secret group must be provided completely or left blank", domain.ErrValidation, spec.key)
	}
	if !hasAny {
		return nil, nil
	}
	return json.Marshal(values)
}

// decodeSpam 严格解析垃圾检测 provider 配置：拒绝未知字段与尾随数据。
func decodeSpam(raw json.RawMessage, into *SpamConfig) error {
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

// UpsertNotification 校验并写入通知通道 provider 配置；enabled 独立启用。
// 只接受固定 key。Secret 更新契约：新建必须提供该平台全部必填机密字段；
// 编辑时必填机密字段为空保留现值，非空才替换；可选签名密钥三态处理
// （缺失=保留、null=清除、非空=替换）。启用前必须校验合并后的完整配置。
func (s *ProviderService) UpsertNotification(ctx context.Context, providerKey string, enabled bool, config json.RawMessage) error {
	if !ValidNotificationProviderKey(providerKey) {
		return fmt.Errorf("%w: unknown notification provider key %q", domain.ErrValidation, providerKey)
	}
	spec := notificationProviderSpecs[providerKey]
	input, err := decodeNotificationInput(config)
	if err != nil {
		return err
	}
	// 读取既有配置用于合并；密钥损坏时返回 ErrSecretCorrupt，管理员需删除后重建。
	var existing *NotificationConfig
	row, getErr := s.settings.GetNotificationProvider(ctx, providerKey)
	if getErr == nil {
		provider, err := s.notificationProvider(row)
		if err != nil {
			return err
		}
		existing = &provider.Config
	} else if !errors.Is(getErr, domain.ErrNotFound) {
		return getErr
	}

	merged, err := effectiveNotificationConfig(providerKey, *input, existing)
	if err != nil {
		return err
	}
	if err := validateNotificationConfig(providerKey, merged); err != nil {
		return err
	}
	if enabled {
		if err := validateNotificationRunnable(providerKey, merged); err != nil {
			return err
		}
	}
	public, err := publicNotificationConfig(*merged, spec)
	if err != nil {
		return err
	}
	secret, err := secretNotificationConfig(*merged, spec)
	if err != nil {
		return err
	}
	newRow := &repository.NotificationProviderRow{
		ProviderKey:  providerKey,
		Enabled:      enabled,
		PublicConfig: public,
	}
	if len(secret) > 0 {
		secretEnvelope, err := cryptox.Encrypt(s.key, masterKeyVersion, secret)
		if err != nil {
			return fmt.Errorf("setting: encrypt provider secret: %w", err)
		}
		newRow.SecretKeyVersion = int(masterKeyVersion)
		newRow.SecretNonce = secretEnvelope[1 : 1+12]
		newRow.SecretCiphertext = secretEnvelope[1+12:]
	}
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		return s.settings.UpsertNotificationProvider(ctx, newRow)
	})
}

// NotificationProvider 返回给消费者的类型化、解密后的通知通道配置。
type NotificationProvider struct {
	ProviderKey string
	Enabled     bool
	Configured  bool
	Config      NotificationConfig
}

// NotificationProvider 返回单个通知通道的解密配置。
// provider 缺失时返回 domain.ErrProviderNotFound；密钥损坏时返回 domain.ErrSecretCorrupt。
func (s *ProviderService) NotificationProvider(ctx context.Context, providerKey string) (*NotificationProvider, error) {
	row, err := s.settings.GetNotificationProvider(ctx, providerKey)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrProviderNotFound
		}
		return nil, err
	}
	return s.notificationProvider(row)
}

// EnabledNotificationProviders 返回全部已启用通知通道的解密配置，按固定 key 顺序。
// 配置损坏会整体失败（fail closed），绝不静默跳过某个通道。
func (s *ProviderService) EnabledNotificationProviders(ctx context.Context) ([]NotificationProvider, error) {
	rows, err := s.settings.ListNotificationProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]NotificationProvider, 0, len(rows))
	for _, key := range notificationProviderKeys {
		for _, row := range rows {
			if row.ProviderKey != key || !row.Enabled {
				continue
			}
			provider, err := s.notificationProvider(&row)
			if err != nil {
				return nil, err
			}
			out = append(out, *provider)
			break
		}
	}
	return out, nil
}

// notificationProvider 合并公开字段与解密后的机密字段为类型化配置。
// 只合并该平台声明的机密字段，防止字段串位；无信封时只返回公开配置。
func (s *ProviderService) notificationProvider(row *repository.NotificationProviderRow) (*NotificationProvider, error) {
	provider := &NotificationProvider{
		ProviderKey: row.ProviderKey,
		Enabled:     row.Enabled,
		Configured:  len(row.SecretCiphertext) > 0,
	}
	if err := decodeConfigFields(row.PublicConfig, &provider.Config); err != nil {
		return nil, err
	}
	if len(row.SecretCiphertext) == 0 {
		return provider, nil
	}
	secret, err := s.decryptSecretEnvelope(row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext, row.ProviderKey)
	if err != nil {
		return nil, fmt.Errorf("%w: provider secret for %q is corrupt", domain.ErrSecretCorrupt, row.ProviderKey)
	}
	var secretCfg NotificationConfig
	if err := json.Unmarshal(secret, &secretCfg); err != nil {
		return nil, fmt.Errorf("%w: provider secret for %q is corrupt", domain.ErrSecretCorrupt, row.ProviderKey)
	}
	spec := notificationProviderSpecs[row.ProviderKey]
	for _, field := range append(append([]string{}, spec.secretFields...), spec.optionalSecretFields...) {
		switch field {
		case "bot_token":
			provider.Config.BotToken = secretCfg.BotToken
		case "chat_id":
			provider.Config.ChatID = secretCfg.ChatID
		case "webhook_url":
			provider.Config.WebhookURL = secretCfg.WebhookURL
		case "device_key":
			provider.Config.DeviceKey = secretCfg.DeviceKey
		case "channel_access_token":
			provider.Config.ChannelAccessToken = secretCfg.ChannelAccessToken
		case "target_id":
			provider.Config.TargetID = secretCfg.TargetID
		case "signing_secret":
			provider.Config.SigningSecret = secretCfg.SigningSecret
		default:
			return nil, fmt.Errorf("setting: unsupported notification secret field %q", field)
		}
	}
	return provider, nil
}

// effectiveNotificationConfig 把输入合并到既有配置：必填字段为空保留现值，
// signing_secret 三态处理（缺失=保留、null=清除、显式空串=清除、非空=替换）。
func effectiveNotificationConfig(providerKey string, input notificationConfigInput, existing *NotificationConfig) (*NotificationConfig, error) {
	if !ValidNotificationProviderKey(providerKey) {
		return nil, fmt.Errorf("%w: unknown notification provider key %q", domain.ErrValidation, providerKey)
	}
	out := &NotificationConfig{}
	if existing != nil {
		*out = *existing
	}
	if input.BotToken != "" {
		out.BotToken = input.BotToken
	}
	if input.ChatID != "" {
		out.ChatID = input.ChatID
	}
	if input.WebhookURL != "" {
		out.WebhookURL = input.WebhookURL
	}
	if input.ServerURL != "" {
		out.ServerURL = input.ServerURL
	}
	if input.DeviceKey != "" {
		out.DeviceKey = input.DeviceKey
	}
	if input.ChannelAccessToken != "" {
		out.ChannelAccessToken = input.ChannelAccessToken
	}
	if input.TargetID != "" {
		out.TargetID = input.TargetID
	}
	switch {
	case input.SigningSecret == nil:
		// 缺失 → 保留现值。
	case string(input.SigningSecret) == "null":
		out.SigningSecret = nil
	default:
		var v string
		if err := json.Unmarshal(input.SigningSecret, &v); err != nil {
			return nil, fmt.Errorf("%w: signing_secret must be a string or null", domain.ErrValidation)
		}
		v = strings.TrimSpace(v)
		if v == "" {
			out.SigningSecret = nil
		} else {
			out.SigningSecret = &v
		}
	}
	return out, nil
}

// validateNotificationConfig 校验平台必填字段与 URL 形态。
// 完整合并后的配置每次 upsert 都校验，保证保存的通道始终可运行。
func validateNotificationConfig(providerKey string, cfg *NotificationConfig) error {
	switch providerKey {
	case "notification.telegram":
		if strings.TrimSpace(cfg.BotToken) == "" {
			return missingNotificationField(providerKey, "bot_token")
		}
		if strings.TrimSpace(cfg.ChatID) == "" {
			return missingNotificationField(providerKey, "chat_id")
		}
	case "notification.feishu", "notification.dingtalk", "notification.slack", "notification.discord":
		if strings.TrimSpace(cfg.WebhookURL) == "" {
			return missingNotificationField(providerKey, "webhook_url")
		}
		platform, err := notifier.ParsePlatform(providerKey)
		if err != nil {
			return fmt.Errorf("%w: %v", domain.ErrValidation, err)
		}
		if err := notifier.ValidateWebhookURL(platform, cfg.WebhookURL); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrValidation, err)
		}
	case "notification.webhook":
		if strings.TrimSpace(cfg.WebhookURL) == "" {
			return missingNotificationField(providerKey, "webhook_url")
		}
		if err := notifier.ValidateTrustedURL(cfg.WebhookURL); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrValidation, err)
		}
	case "notification.bark":
		if strings.TrimSpace(cfg.ServerURL) == "" {
			return missingNotificationField(providerKey, "server_url")
		}
		if strings.TrimSpace(cfg.DeviceKey) == "" {
			return missingNotificationField(providerKey, "device_key")
		}
		if err := notifier.ValidateTrustedURL(cfg.ServerURL); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrValidation, err)
		}
	case "notification.line":
		if strings.TrimSpace(cfg.ChannelAccessToken) == "" {
			return missingNotificationField(providerKey, "channel_access_token")
		}
		if strings.TrimSpace(cfg.TargetID) == "" {
			return missingNotificationField(providerKey, "target_id")
		}
	default:
		return fmt.Errorf("%w: unknown notification provider key %q", domain.ErrValidation, providerKey)
	}
	return nil
}

// validateNotificationRunnable 校验启用通道可运行：要求配置完整且可解密。
// 由于 upsert 已对合并结果做完整校验，这里与常规校验等价。
func validateNotificationRunnable(providerKey string, cfg *NotificationConfig) error {
	return validateNotificationConfig(providerKey, cfg)
}

// missingNotificationField 生成必填字段缺失的验证错误。
func missingNotificationField(providerKey, field string) error {
	return fmt.Errorf("%w: %s %s is required", domain.ErrValidation, providerKey, field)
}

// publicNotificationConfig 构建存储到 public_config 的 JSON，只包含该平台声明的公开字段。
func publicNotificationConfig(cfg NotificationConfig, spec notificationProviderSpec) ([]byte, error) {
	values := map[string]any{}
	for _, field := range spec.publicFields {
		switch field {
		case "server_url":
			if cfg.ServerURL != "" {
				values[field] = cfg.ServerURL
			}
		default:
			return nil, fmt.Errorf("setting: unsupported notification public field %q", field)
		}
	}
	return json.Marshal(values)
}

// secretNotificationConfig 构建待加密的 Secret JSON，只包含该平台声明的机密字段；
// 可选机密字段未设置时从 JSON 中省略。
func secretNotificationConfig(cfg NotificationConfig, spec notificationProviderSpec) ([]byte, error) {
	values := map[string]string{}
	for _, field := range spec.secretFields {
		switch field {
		case "bot_token":
			values[field] = cfg.BotToken
		case "chat_id":
			values[field] = cfg.ChatID
		case "webhook_url":
			values[field] = cfg.WebhookURL
		case "device_key":
			values[field] = cfg.DeviceKey
		case "channel_access_token":
			values[field] = cfg.ChannelAccessToken
		case "target_id":
			values[field] = cfg.TargetID
		default:
			return nil, fmt.Errorf("setting: unsupported notification secret field %q", field)
		}
	}
	for _, field := range spec.optionalSecretFields {
		if field != "signing_secret" {
			return nil, fmt.Errorf("setting: unsupported optional notification secret field %q", field)
		}
		if cfg.SigningSecret != nil {
			values[field] = *cfg.SigningSecret
		}
	}
	return json.Marshal(values)
}

// decodeNotificationInput 严格解析通知通道 provider 配置：拒绝未知字段与尾随数据。
func decodeNotificationInput(raw json.RawMessage) (*notificationConfigInput, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: provider config is required", domain.ErrValidation)
	}
	var input notificationConfigInput
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		return nil, fmt.Errorf("%w: malformed provider config", domain.ErrValidation)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%w: malformed provider config", domain.ErrValidation)
	}
	return &input, nil
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
	if err := s.settings.DeleteSpamProvider(ctx, providerKey); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if err := s.settings.DeleteNotificationProvider(ctx, providerKey); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	return domain.ErrNotFound
}

// Test 对已配置的提供商执行有界外部连通性检查。
// CAPTCHA/OAuth 沿用探测目标检查；通知通道通过 NotificationTester 发送显式测试消息，
// 测试允许在通道停用时执行，但要求配置完整（无效配置→validation，远程失败→unavailable）。
func (s *ProviderService) Test(ctx context.Context, providerKey string) error {
	if cfg, err := s.CaptchaProvider(ctx, providerKey); err == nil {
		if err := s.prober.ProbeCaptcha(ctx, *cfg); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrUnavailable, err)
		}
		return nil
	} else if !errors.Is(err, domain.ErrProviderNotFound) && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	// Apple 的连通性测试在探测网络前先解析 ES256 私钥：私钥损坏属于配置错误，
	// 会在任何远程请求发起之前以 validation 失败，无效配置不产生可达性结果。
	if provider, err := s.AuthProvider(ctx, providerKey); err == nil {
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
	} else if !errors.Is(err, domain.ErrProviderNotFound) && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if ValidNotificationProviderKey(providerKey) {
		provider, err := s.NotificationProvider(ctx, providerKey)
		if err != nil {
			return err
		}
		if s.notificationTester == nil {
			return fmt.Errorf("%w: notification tester is not configured", domain.ErrUnavailable)
		}
		return s.notificationTester.TestNotification(ctx, providerKey, provider.Config)
	}
	return domain.ErrProviderNotFound
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
		instance, err := urlx.ParseHTTPSBase(provider.InstanceURL)
		if err != nil {
			return "", fmt.Errorf("%w: instance url is invalid", domain.ErrValidation)
		}
		return urlx.JoinPathSegments(instance, ".well-known", "openid-configuration").String(), nil
	case "mastodon":
		if provider.InstanceURL == "" {
			return "", fmt.Errorf("%w: instance url is required", domain.ErrValidation)
		}
		instance, err := urlx.ParseHTTPSBase(provider.InstanceURL)
		if err != nil {
			return "", fmt.Errorf("%w: instance url is invalid", domain.ErrValidation)
		}
		return urlx.JoinPathSegments(instance, ".well-known", "oauth-authorization-server").String(), nil
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

// AuthProvider 返回给消费者的类型化、解密后的 OAuth/OIDC 配置。
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
	// InstanceURL 自托管实例的规范化 HTTPS 基址（GitLab/Gitea/Mastodon）。
	InstanceURL string
	// AppleTeamID  Apple client-secret JWT 的 iss。
	AppleTeamID string
	// AppleKeyID  Apple client-secret JWT 的 kid。
	AppleKeyID string
	// ApplePrivateKey  Apple 的 P-256 .p8 私钥。
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
		s.log.Warn("providers: secret envelope rejected",
			slog.String("provider_key", providerKey),
			slog.Int("stored_version", version),
			slog.Int("expected_version", int(masterKeyVersion)))
		return nil, domain.ErrSecretCorrupt
	}
	envelope := make([]byte, 0, 1+len(nonce)+len(ciphertext))
	envelope = append(envelope, masterKeyVersion)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)
	plaintext, err := cryptox.Decrypt(s.key, masterKeyVersion, envelope)
	if err != nil {
		s.log.Warn("providers: secret envelope rejected",
			slog.String("provider_key", providerKey),
			slog.Int("stored_version", version),
			slog.Int("expected_version", int(masterKeyVersion)))
		return nil, domain.ErrSecretCorrupt
	}
	return plaintext, nil
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

// customOIDCSpec 未知 key 的默认配置模式：任意 key + oidc。
var customOIDCSpec = oauth.ProviderSpec{
	Key:      "custom-oidc",
	Name:     "Custom OIDC",
	Kind:     "oidc",
	PKCE:     true,
	Nonce:    true,
	Callback: oauth.CallbackQuery,
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
		normalized, err := urlx.ParseHTTPSBase(cfg.IssuerURL)
		if err != nil {
			return fmt.Errorf("%w: oidc issuer url must be an absolute https url", domain.ErrValidation)
		}
		cfg.IssuerURL = normalized.String()
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
		if _, err := urlx.ParseHTTPBase(c.Endpoint); err != nil {
			return fmt.Errorf("%w: cap endpoint must be an absolute http(s) url", domain.ErrValidation)
		}
		return nil
	}
	if strings.TrimSpace(c.Endpoint) != "" {
		if _, err := urlx.ParseHTTPBase(c.Endpoint); err != nil {
			return fmt.Errorf("%w: captcha endpoint must be an absolute http(s) base url", domain.ErrValidation)
		}
	}
	return nil
}

// normalizeHTTPSURL 校验并规范化绝对 http(s) base URL。
func normalizeHTTPSURL(raw string) (string, error) {
	u, err := urlx.ParseHTTPBase(raw)
	if err != nil {
		return "", fmt.Errorf("%w: captcha endpoint must be an absolute http(s) url", domain.ErrValidation)
	}
	return u.String(), nil
}

// normalizeInstanceURL 校验并规范化自托管实例地址：
// 仅接受 https，拒绝 userinfo/query/fragment，主机名小写并去掉默认端口与尾部斜杠；
// rootOnly 时禁止部署子路径（Mastodon 的规范部署根是 origin）。
func normalizeInstanceURL(raw string, rootOnly bool) (string, error) {
	u, err := urlx.ParseHTTPSBase(raw)
	if err != nil {
		return "", fmt.Errorf("%w: instance url must be an absolute https url without userinfo, query or fragment", domain.ErrValidation)
	}
	if rootOnly && u.Path != "" {
		return "", fmt.Errorf("%w: mastodon instance url must be a root origin without a path", domain.ErrValidation)
	}
	return u.String(), nil
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

// smtpProber 生产环境的 prober。
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

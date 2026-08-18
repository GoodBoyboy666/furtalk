// Package oauth 实现第三方登录的 provider 适配器：
// GitHub OAuth2（授权码 + PKCE）、GitLab/Gitea 的单实例 OIDC discovery 适配器、
// Mastodon 的单实例 OAuth2 适配器、Microsoft/LINE/Apple 的专用 ID-token 适配器
// 与通用 OIDC。
// 只有显式验证邮箱的 provider（email_verified=true 且非空）才会产生可用的 VerifiedEmail；
// 缺失邮箱不否定 Subject，绑定模式 provider 永不返回邮箱。
package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	// ErrUnsupported 在 provider 的 key/kind 组合没有对应适配器时返回，
	// 例如没有 userinfo 端点的通用 OAuth provider。
	ErrUnsupported = errors.New("oauth: unsupported provider configuration")
	// ErrIdentity 在 provider 身份无法验证或邮箱未验证时返回的通用回调错误。
	ErrIdentity = errors.New("oauth: provider identity verification failed")
)

// Identity 是标准化后的 provider 输出。
// 只有 provider 断言邮箱已验证时 VerifiedEmail 才非空；
// 缺失邮箱不否定 Subject，此时 VerifiedEmail 为空字符串。
type Identity struct {
	Subject       string
	VerifiedEmail string
}

// AuthorizationRequest 是一次授权跳转所需的全部输入。
// Verifier 与 Nonce 按 provider 能力可空：非 PKCE provider 的 Verifier 为空，
// 非 ID-token provider 的 Nonce 为空；适配器不得自行启用或关闭任一能力。
type AuthorizationRequest struct {
	State       string
	Verifier    string
	Nonce       string
	RedirectURI string
}

// ExchangeRequest 是回调阶段换取身份所需的全部输入。
// Verifier 与 Nonce 同样按 provider 能力可空，与 AuthorizationRequest 保持一致。
type ExchangeRequest struct {
	Code        string
	Verifier    string
	Nonce       string
	RedirectURI string
}

// Provider 是消费者拥有的 OAuth/OIDC 适配器接口。
type Provider interface {
	// Name 返回 provider 元数据中使用的显示名称。
	Name() string
	// BuildAuthURL 为新的 state、可选 PKCE verifier 与可选 nonce 返回 provider 授权 URL。
	// ctx 用于 OIDC discovery 等网络请求；失败时返回错误而非空 URL。
	BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error)
	// Exchange 用 code 换取 token，
	// 验证身份（包括 OIDC 的 issuer/audience/signature/nonce）并返回标准化后的 identity。
	Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error)
}

// Config 携带解密后的 provider 配置与共享的 HTTP client。
// 该配置只用于一次 New 调用，不会在 provider 种类之间复用。
type Config struct {
	ProviderKey  string
	Kind         string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	IssuerURL    string
	// APIURL 覆盖 GitHub API 基础地址（测试使用 mock server）。
	APIURL string
	// InstanceURL 是自托管实例的规范化 HTTPS 基址（GitLab/Gitea/Mastodon）。
	InstanceURL string
	// AppleTeamID 是 Apple client-secret JWT 的 iss。
	AppleTeamID string
	// AppleKeyID 是 Apple client-secret JWT 的 kid。
	AppleKeyID string
	// ApplePrivateKey 是 Apple 的 P-256 .p8 私钥。
	ApplePrivateKey string

	HTTPClient *http.Client
	Timeout    time.Duration
}

// New 根据给定配置构建 provider 适配器。
// oauth kind 支持 github/mastodon/twitter/discord；oidc kind 支持 gitlab/gitea 的
// discovery 适配器与 microsoft/apple/line 的专用 ID-token 适配器，其余 key
// （google/自定义 OIDC）走通用 OIDC 适配器。
// 其他任何组合一律以 ErrUnsupported 拒绝。
func New(cfg Config) (Provider, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if cfg.Timeout > 0 {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	switch cfg.Kind {
	case "oauth":
		switch cfg.ProviderKey {
		case "github":
			return newGitHubProvider(cfg, client), nil
		case "mastodon":
			return newMastodonProvider(cfg, client)
		case "twitter":
			return newTwitterProvider(cfg, client), nil
		case "discord":
			return newDiscordProvider(cfg, client), nil
		default:
			return nil, fmt.Errorf("%w: unsupported oauth provider %q", ErrUnsupported, cfg.ProviderKey)
		}
	case "oidc":
		switch cfg.ProviderKey {
		case "gitlab", "gitea":
			return newDiscoveryProvider(cfg, client)
		case "microsoft":
			return newMicrosoftProvider(cfg, client), nil
		case "apple":
			return newAppleProvider(cfg, client)
		case "line":
			return newLINEProvider(cfg, client), nil
		default:
			return newOIDCProvider(cfg, client)
		}
	default:
		return nil, fmt.Errorf("%w: unknown provider kind %q", ErrUnsupported, cfg.Kind)
	}
}

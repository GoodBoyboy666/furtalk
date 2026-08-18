package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Mastodon 授权请求所需的固定 scopes：
// profile 覆盖 4.4+ userinfo；read:accounts 覆盖 4.3 verify_credentials 回退。
const (
	mastodonScopeProfile      = "profile"
	mastodonScopeReadAccounts = "read:accounts"
)

// mastodonDiscovery 是 RFC 8414 的 oauth-authorization-server 元数据文档。
// issuer 与 userinfo_endpoint 可选：issuer 缺省回退实例 origin，userinfo_endpoint
// 只在 4.4+ 出现；authorization_endpoint 与 token_endpoint 必须齐全。
type mastodonDiscovery struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

// mastodonProvider 是单实例、只绑定的 Mastodon OAuth2 适配器。
// 要求实例 >= 4.3（元数据端点必须可用）；使用 S256 PKCE 但不发送 nonce。
// 4.4+ 通过 userinfo 端点取得 ActivityPub actor URI 作为 subject，
// 4.3 回退使用 verify_credentials 的局部 Account ID 做实例作用域化编码。
// 该 provider 永远不返回邮箱。
type mastodonProvider struct {
	key          string
	clientID     string
	clientSecret string
	instanceURL  string
	httpClient   *http.Client

	mu    sync.Mutex
	disco *mastodonDiscovery
}

func newMastodonProvider(cfg Config, client *http.Client) (*mastodonProvider, error) {
	if strings.TrimSpace(cfg.InstanceURL) == "" {
		return nil, fmt.Errorf("%w: mastodon instance url is required", ErrUnsupported)
	}
	return &mastodonProvider{
		key:          cfg.ProviderKey,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		instanceURL:  strings.TrimRight(cfg.InstanceURL, "/"),
		httpClient:   client,
	}, nil
}

// Name 返回 provider 显示名称。
func (p *mastodonProvider) Name() string {
	return "Mastodon"
}

// clientContext 返回注入共享 HTTP client 的上下文，
// 使 metadata/token/userinfo 的全部网络请求走同一 client（含超时）。
func (p *mastodonProvider) clientContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, p.httpClient)
}

// discovery 在 {instance}/.well-known/oauth-authorization-server 请求 RFC 8414
// 元数据并缓存结果。实例低于 4.3 时元数据不可用，discovery 失败即硬失败（4.3 下限），
// 不回退到硬编码端点。
func (p *mastodonProvider) discovery(ctx context.Context) (*mastodonDiscovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disco != nil {
		return p.disco, nil
	}
	endpoint := p.instanceURL + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	client := p.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: mastodon metadata status %d", resp.StatusCode)
	}
	var doc mastodonDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.AuthURL == "" || doc.TokenURL == "" {
		return nil, fmt.Errorf("oauth: incomplete mastodon metadata")
	}
	if doc.Issuer == "" {
		doc.Issuer = p.instanceURL
	}
	p.disco = &doc
	return &doc, nil
}

func (p *mastodonProvider) oauthConfig(ctx context.Context, redirectURI string) (*oauth2.Config, error) {
	doc, err := p.discovery(ctx)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   doc.AuthURL,
			TokenURL:  doc.TokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: redirectURI,
		Scopes:      []string{mastodonScopeProfile, mastodonScopeReadAccounts},
	}, nil
}

// BuildAuthURL 在元数据成功后，为新的 state 与可选 PKCE verifier 生成授权 URL。
// 仅在 verifier 非空时附加 code_challenge（S256）；Mastodon 不发送 nonce，
// 即使请求中带 nonce 也忽略。
func (p *mastodonProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	config, err := p.oauthConfig(ctx, req.RedirectURI)
	if err != nil {
		return "", err
	}
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(req.Verifier))
	}
	return config.AuthCodeURL(req.State, opts...), nil
}

// Exchange 用 code 换取 token 并解析已认证 actor，返回只含 Subject 的 Identity。
// 4.4+ 用 userinfo 的 ActivityPub actor URI；4.3 回退用 verify_credentials 的
// Account ID 做 (issuer, id) 作用域化编码。任何失败映射为 ErrIdentity。
func (p *mastodonProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
	config, err := p.oauthConfig(ctx, req.RedirectURI)
	if err != nil {
		return nil, ErrIdentity
	}
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.Verifier))
	}
	token, err := config.Exchange(p.clientContext(ctx), req.Code, opts...)
	if err != nil {
		return nil, ErrIdentity
	}
	doc, err := p.discovery(ctx)
	if err != nil {
		return nil, ErrIdentity
	}
	subject, err := p.resolveActor(ctx, doc, token)
	if err != nil {
		return nil, ErrIdentity
	}
	if subject == "" {
		return nil, ErrIdentity
	}
	return &Identity{Subject: subject, VerifiedEmail: ""}, nil
}

// resolveActor 按元数据能力解析 actor subject：
// 有 userinfo_endpoint（4.4+）时用它；没有时走 verify_credentials 回退（4.3）。
func (p *mastodonProvider) resolveActor(ctx context.Context, doc *mastodonDiscovery, token *oauth2.Token) (string, error) {
	if doc.UserInfoURL != "" {
		return p.fetchUserInfoSubject(ctx, doc.UserInfoURL, token)
	}
	return p.fetchVerifyCredentialsSubject(ctx, doc.Issuer, token)
}

// fetchUserInfoSubject 用 Bearer token 请求 4.4+ userinfo 端点，
// 返回 ActivityPub actor URI 原样作为全局唯一的 subject。
func (p *mastodonProvider) fetchUserInfoSubject(ctx context.Context, userInfoURL string, token *oauth2.Token) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return "", err
	}
	token.SetAuthHeader(req)
	client := p.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oauth: mastodon userinfo status %d", resp.StatusCode)
	}
	var info struct {
		Subject string `json:"sub"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	if info.Subject == "" {
		return "", ErrIdentity
	}
	return info.Subject, nil
}

// fetchVerifyCredentialsSubject 用 Bearer token 请求 4.3 verify_credentials 端点，
// 返回 (issuer, Account ID) 的作用域化编码 subject。
func (p *mastodonProvider) fetchVerifyCredentialsSubject(ctx context.Context, issuer string, token *oauth2.Token) (string, error) {
	endpoint := p.instanceURL + "/api/v1/accounts/verify_credentials"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	token.SetAuthHeader(req)
	client := p.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oauth: mastodon verify_credentials status %d", resp.StatusCode)
	}
	var account struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return "", err
	}
	if account.ID == "" {
		return "", ErrIdentity
	}
	return ScopedSubject(issuer, account.ID), nil
}

var _ Provider = (*mastodonProvider)(nil)

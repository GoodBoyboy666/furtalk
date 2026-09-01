package oauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// discoveryProvider 是基于 OIDC discovery 的单实例适配器（GitLab/Gitea）。
// 与通用 oidcProvider 不同，它信任 discovery 文档返回的 issuer：Gitea 1.25+
// 的 trailing-slash 行为与可配置的 JWT_CLAIM_ISSUER 使 instance != issuer，
// 因此不能使用 oidc.NewProvider（它强制 issuer == 配置地址）或自行拼接 issuer。
// ID token 的签名、issuer、audience、有效期校验由 go-oidc 完成，nonce 由本包
// 发送并校验；邮箱仅在非空且 email_verified=true 时输出。
type discoveryProvider struct {
	key          string
	name         string
	clientID     string
	clientSecret string
	instanceURL  string
	httpClient   *http.Client

	mu       sync.Mutex
	disco    *oidc.ProviderConfig
	provider *oidc.Provider
}

func newDiscoveryProvider(cfg Config, client *http.Client) (*discoveryProvider, error) {
	if strings.TrimSpace(cfg.InstanceURL) == "" {
		return nil, fmt.Errorf("%w: %s instance url is required", ErrUnsupported, cfg.ProviderKey)
	}
	name := "GitLab"
	if cfg.ProviderKey == "gitea" {
		name = "Gitea"
	}
	return &discoveryProvider{
		key:          cfg.ProviderKey,
		name:         name,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		instanceURL:  strings.TrimRight(cfg.InstanceURL, "/"),
		httpClient:   client,
	}, nil
}

// Name 返回 provider 显示名称：gitlab 显示为 GitLab，gitea 显示为 Gitea。
func (p *discoveryProvider) Name() string {
	return p.name
}

// clientContext 返回注入共享 HTTP client 的上下文，
// 使 discovery/JWKS/token/userinfo 的全部网络请求走同一 client（含超时）。
func (p *discoveryProvider) clientContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, p.httpClient)
}

// discovery 在 {instance}/.well-known/openid-configuration 手动执行 discovery
// 并缓存结果。discovery 文档只用于解析端点与 issuer；id-token verifier 使用
// 发现到的 issuer 与 jwks_uri 构造，不要求 discovered issuer 与 instance 一致。
func (p *discoveryProvider) discovery(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return p.provider, nil
	}
	doc, err := p.fetchDiscoveryDocument(ctx)
	if err != nil {
		return nil, err
	}
	provider := doc.NewProvider(p.clientContext(ctx))
	p.disco = doc
	p.provider = provider
	return provider, nil
}

// fetchDiscoveryDocument 请求并解析 OIDC discovery 文档。
// issuer、authorization_endpoint、token_endpoint 与 jwks_uri 必须齐全；
// userinfo_endpoint 由 ID token 缺少已验证邮箱时才用到，允许缺失。
func (p *discoveryProvider) fetchDiscoveryDocument(ctx context.Context) (*oidc.ProviderConfig, error) {
	endpoint := p.instanceURL + "/.well-known/openid-configuration"
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
		return nil, fmt.Errorf("oauth: discovery status %d", resp.StatusCode)
	}
	var doc oidc.ProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.IssuerURL == "" || doc.AuthURL == "" || doc.TokenURL == "" || doc.JWKSURL == "" {
		return nil, fmt.Errorf("oauth: incomplete discovery document")
	}
	return &doc, nil
}

func (p *discoveryProvider) oauthConfig(ctx context.Context, redirectURI string) (*oauth2.Config, error) {
	provider, err := p.discovery(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := provider.Endpoint()
	// 机密客户端：client_secret 放入 token 请求体，与 code_verifier 一起提交。
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  redirectURI,
		Scopes:       []string{oidcScopeOpenID, oidcScopeEmail, oidcScopeProfile},
	}, nil
}

// BuildAuthURL 在 discovery 成功后，为新的 state、可选 PKCE verifier 与可选 nonce
// 生成授权 URL。仅在 verifier 非空时附加 code_challenge（S256），仅在 nonce 非空时
// 附加 nonce 参数。
func (p *discoveryProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	config, err := p.oauthConfig(ctx, req.RedirectURI)
	if err != nil {
		return "", err
	}
	opts := make([]oauth2.AuthCodeOption, 0, 2)
	if req.Verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(req.Verifier))
	}
	if req.Nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", req.Nonce))
	}
	return config.AuthCodeURL(req.State, opts...), nil
}

// Exchange 用 code 换取 token，校验 ID token 的签名、issuer、audience 与 nonce。
// ID token 含已验证邮箱时直接使用；否则用访问令牌请求 UserInfo 作为 subject 一致的
// 已验证邮箱回退。缺失邮箱不否定 subject，返回空的 VerifiedEmail。
// 输出的 Subject 是 (discovered issuer, ID token subject) 的作用域化编码。
func (p *discoveryProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
	config, err := p.oauthConfig(ctx, req.RedirectURI)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.Verifier))
	}
	token, err := config.Exchange(p.clientContext(ctx), req.Code, opts...)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, ErrIdentity
	}
	provider, err := p.discovery(ctx)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: p.clientID})
	idToken, err := tokenVerifier.Verify(p.clientContext(ctx), rawIDToken)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	// go-oidc 的 Verify 不校验 nonce：当流程发送了 nonce 时，必须与 ID token 的
	// nonce claim 恒定时间比较；缺失或不等一律拒绝。
	if req.Nonce != "" && subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(req.Nonce)) != 1 {
		return nil, ErrIdentity
	}
	if idToken.Subject == "" {
		return nil, ErrIdentity
	}
	issuer := ""
	if p.disco != nil {
		issuer = p.disco.IssuerURL
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, ErrIdentity
	}
	verifiedEmail := ""
	if claims.Email != "" && claims.EmailVerified != nil && *claims.EmailVerified {
		verifiedEmail = claims.Email
	} else {
		verifiedEmail, err = p.fetchUserInfoVerifiedEmail(ctx, provider, token, idToken.Subject)
		if err != nil {
			return nil, preserveProviderError(err)
		}
	}
	return &Identity{
		Subject:       ScopedSubject(issuer, idToken.Subject),
		VerifiedEmail: verifiedEmail,
	}, nil
}

// fetchUserInfoVerifiedEmail 在 ID token 缺少已验证邮箱时，用访问令牌请求 UserInfo
// 作为回退。仅当 UserInfo 的 sub 与 ID token subject 一致且 email 已验证时才返回邮箱；
// UserInfo 缺失邮箱或未验证时返回空字符串，不否定 subject。
func (p *discoveryProvider) fetchUserInfoVerifiedEmail(ctx context.Context, provider *oidc.Provider, token *oauth2.Token, subject string) (string, error) {
	info, err := provider.UserInfo(p.clientContext(ctx), oauth2.StaticTokenSource(token))
	if err != nil {
		return "", err
	}
	if info.Subject != subject {
		return "", ErrIdentity
	}
	if info.Email == "" || !info.EmailVerified {
		return "", nil
	}
	return info.Email, nil
}

var _ Provider = (*discoveryProvider)(nil)

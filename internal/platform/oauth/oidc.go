package oauth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC 授权请求所需的固定 scopes。
const (
	oidcScopeOpenID  = "openid"
	oidcScopeEmail   = "email"
	oidcScopeProfile = "profile"
)

// oidcProvider 封装基于 discovery 的 Google 与通用 OpenID Connect provider。
// discovery 文档、JWKS 以及 ID token 的签名、issuer、audience 校验
// 来自 coreos/go-oidc；nonce 由本包发送并校验，邮箱仅在被断言已验证时输出。
type oidcProvider struct {
	key          string
	name         string
	clientID     string
	clientSecret string
	issuerURL    string
	httpClient   *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
}

// newOIDCProvider 创建通用 OIDC 适配器。
func newOIDCProvider(cfg Config, client *http.Client) (*oidcProvider, error) {
	if strings.TrimSpace(cfg.IssuerURL) == "" {
		return nil, fmt.Errorf("%w: oidc issuer url is required", ErrUnsupported)
	}
	name := "OIDC"
	if cfg.ProviderKey == "google" {
		name = "Google"
	}
	return &oidcProvider{
		key:          cfg.ProviderKey,
		name:         name,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		issuerURL:    cfg.IssuerURL,
		httpClient:   client,
	}, nil
}

// Name 返回 provider 显示名称：google 显示为 Google，其余为 OIDC。
func (p *oidcProvider) Name() string {
	return p.name
}

// clientContext 返回注入共享 HTTP client 的上下文。
func (p *oidcProvider) clientContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, p.httpClient)
}

// discovery 在首次调用时执行 discovery 并缓存结果。
func (p *oidcProvider) discovery(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return p.provider, nil
	}
	provider, err := oidc.NewProvider(p.clientContext(ctx), p.issuerURL)
	if err != nil {
		return nil, err
	}
	p.provider = provider
	return provider, nil
}

// oauthConfig 根据 OIDC discovery 构建 OAuth 配置。
func (p *oidcProvider) oauthConfig(ctx context.Context, redirectURI string) (*oauth2.Config, error) {
	provider, err := p.discovery(ctx)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       []string{oidcScopeOpenID, oidcScopeEmail, oidcScopeProfile},
	}, nil
}

// BuildAuthURL 在 discovery 成功后，为新的 state、可选 PKCE verifier 与可选 nonce 生成授权 URL。
func (p *oidcProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
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
func (p *oidcProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
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
	idToken, err := tokenVerifier.Verify(ctx, rawIDToken)
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
		verifiedEmail, err = p.fetchUserInfoVerifiedEmail(ctx, token, idToken.Subject)
		if err != nil {
			return nil, preserveProviderError(err)
		}
	}
	return &Identity{Subject: idToken.Subject, VerifiedEmail: verifiedEmail}, nil
}

// fetchUserInfoVerifiedEmail 在 ID token 缺少已验证邮箱时，用访问令牌请求 UserInfo 作为回退。
func (p *oidcProvider) fetchUserInfoVerifiedEmail(ctx context.Context, token *oauth2.Token, subject string) (string, error) {
	provider, err := p.discovery(ctx)
	if err != nil {
		return "", err
	}
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

var _ Provider = (*oidcProvider)(nil)

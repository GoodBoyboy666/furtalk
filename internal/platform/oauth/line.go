package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// LINE Login 的固定端点与 issuer。
// 端点由适配器代码所有，不可配置；cfg 中的同名值仅在测试时覆盖。
const (
	lineAuthorizeURL = "https://access.line.me/oauth2/v2.1/authorize"
	lineTokenURL     = "https://api.line.me/oauth2/v2.1/token"
	lineVerifyURL    = "https://api.line.me/oauth2/v2.1/verify"
	// lineIssuer 是 LINE ID token 允许的唯一 issuer。
	lineIssuer = "https://access.line.me"
)

// lineProvider 是 LINE Login 的固定端点 OIDC 适配器。
// 使用 S256 PKCE 与必选 nonce（按 catalog）；token 请求把 channel ID/secret
// 放入 body（AuthStyleInParams）。ID token 的签名、audience、有效期与 nonce
// 全部交给 LINE 官方 verify 端点校验（LINE 的 ID token 可能是用 channel secret
// 签名的 HS256，不能由本包手工验证签名），本包只解析返回的已验证 claims。
// 该 provider 只绑定：subject 是 (https://access.line.me, sub) 的作用域化编码，
// email 一律忽略，VerifiedEmail 永远为空。
type lineProvider struct {
	key          string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	verifyURL    string
	httpClient   *http.Client
}

func newLINEProvider(cfg Config, client *http.Client) *lineProvider {
	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = lineAuthorizeURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = lineTokenURL
	}
	verifyURL := cfg.APIURL
	if verifyURL == "" {
		verifyURL = lineVerifyURL
	}
	return &lineProvider{
		key:          cfg.ProviderKey,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		authURL:      authURL,
		tokenURL:     tokenURL,
		verifyURL:    verifyURL,
		httpClient:   client,
	}
}

// Name 返回 provider 显示名称。
func (p *lineProvider) Name() string {
	return "LINE"
}

// clientContext 返回注入共享 HTTP client 的上下文，
// 使 token/verify 的全部网络请求走同一 client（含超时）。
func (p *lineProvider) clientContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
}

func (p *lineProvider) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.authURL,
			TokenURL:  p.tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: redirectURI,
		Scopes:      []string{oidcScopeOpenID, oidcScopeProfile},
	}
}

// BuildAuthURL 为新的 state、可选 PKCE verifier 与可选 nonce 生成 LINE 授权 URL。
// 仅在 verifier 非空时附加 code_challenge（S256），仅在 nonce 非空时附加 nonce 参数。
func (p *lineProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 2)
	if req.Verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(req.Verifier))
	}
	if req.Nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", req.Nonce))
	}
	return p.oauthConfig(req.RedirectURI).AuthCodeURL(req.State, opts...), nil
}

// Exchange 用 code 换取 token，并把 ID token 交给 LINE 官方 verify 端点校验。
// LINE 要求 nonce：请求 nonce 缺失时直接失败，不发起任何网络请求。
// 任何失败统一映射为 ErrIdentity；错误文本不包含 code/token/secret/nonce。
func (p *lineProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
	if req.Nonce == "" {
		return nil, ErrIdentity
	}
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.Verifier))
	}
	token, err := p.oauthConfig(req.RedirectURI).Exchange(p.clientContext(ctx), req.Code, opts...)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, ErrIdentity
	}
	claims, err := p.verifyIDToken(ctx, rawIDToken, req.Nonce)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	return &Identity{Subject: ScopedSubject(lineIssuer, claims.Subject), VerifiedEmail: ""}, nil
}

// lineClaims 是 LINE verify 端点返回的已验证 ID token claims。
// email 字段即使存在也按产品策略忽略。
type lineClaims struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss"`
	Email   string `json:"email"`
}

// verifyIDToken 调用 LINE 官方 verify 端点校验 ID token。
// LINE 在服务端校验签名、audience、有效期与 nonce；本包只解析返回的 claims，
// 要求 sub 非空且 iss（若出现）必须精确等于 https://access.line.me。
// email 即使返回也被忽略。
func (p *lineProvider) verifyIDToken(ctx context.Context, rawIDToken string, nonce string) (*lineClaims, error) {
	form := url.Values{}
	form.Set("id_token", rawIDToken)
	form.Set("client_id", p.clientID)
	form.Set("nonce", nonce)
	var claims lineClaims
	if err := postForm(ctx, p.httpClient, p.verifyURL, form, &claims); err != nil {
		return nil, err
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, ErrIdentity
	}
	if claims.Issuer != "" && claims.Issuer != lineIssuer {
		return nil, ErrIdentity
	}
	return &claims, nil
}

var _ Provider = (*lineProvider)(nil)

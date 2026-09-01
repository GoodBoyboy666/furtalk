package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// Discord OAuth2 授权请求所需的固定 scopes。
// identify 提供稳定 id，email 提供候选邮箱（是否可信由 verified 字段决定）。
const (
	discordScopeIdentify = "identify"
	discordScopeEmail    = "email"
)

// Discord 的固定端点。端点由适配器代码所有；cfg 中的同名值仅在测试时覆盖。
const (
	discordAuthorizeURL = "https://discord.com/oauth2/authorize"
	discordTokenURL     = "https://discord.com/api/oauth2/token"
	discordAPIURL       = "https://discord.com/api/v10"
)

// discordProvider Discord 的 OAuth2 API 适配器。
// 普通网页登录流程未文档化 PKCE，因此不会发送 code_challenge/code_verifier与nonce。
// confidential client 的 token 请求固定使用 HTTP Basic
// （AuthStyleInHeader；Discord 同时支持 body 方式，固定 Basic 不会触发探测重试）。
// subject 是 User snowflake id；VerifiedEmail 只在 email 非空且 verified=true 时填充。
type discordProvider struct {
	key          string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	userInfoURL  string
	httpClient   *http.Client
}

func newDiscordProvider(cfg Config, client *http.Client) *discordProvider {
	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = discordAuthorizeURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = discordTokenURL
	}
	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = discordAPIURL
	}
	return &discordProvider{
		key:          cfg.ProviderKey,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		authURL:      authURL,
		tokenURL:     tokenURL,
		userInfoURL:  strings.TrimRight(apiURL, "/") + "/users/@me",
		httpClient:   client,
	}
}

// Name 返回 provider 显示名称。
func (p *discordProvider) Name() string {
	return "Discord"
}

// clientContext 返回注入共享 HTTP client 的上下文，
// 使 token/userinfo 的全部网络请求走同一 client（含超时）。
func (p *discordProvider) clientContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
}

func (p *discordProvider) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.authURL,
			TokenURL:  p.tokenURL,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: redirectURI,
		Scopes:      []string{discordScopeIdentify, discordScopeEmail},
	}
}

// BuildAuthURL 为新的 state 生成 Discord 授权 URL。
// Discord 普通网页登录未定义 PKCE，即使请求中带 verifier 也不会附加 code_challenge；
// 同样不会发送 nonce。
func (p *discordProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	return p.oauthConfig(req.RedirectURI).AuthCodeURL(req.State), nil
}

// Exchange 用 code 换取 token，通过 Bearer 拉取 /users/@me 并返回标准化后的 Identity。
// subject 是 User 的 snowflake id；VerifiedEmail 只在 email 非空且 verified=true 时填充，
// 否则保留空字符串（缺失/未验证邮箱不会否定 subject）。
// 任何失败映射为 ErrIdentity。
func (p *discordProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
	token, err := p.oauthConfig(req.RedirectURI).Exchange(p.clientContext(ctx), req.Code)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	user, err := p.fetchUserInfo(ctx, token)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	if user.ID == "" {
		return nil, ErrIdentity
	}
	verifiedEmail := ""
	if user.Email != "" && user.Verified {
		verifiedEmail = user.Email
	}
	return &Identity{Subject: user.ID, VerifiedEmail: verifiedEmail}, nil
}

// discordUser 是 GET /users/@me 返回的用户对象。
type discordUser struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

// fetchUserInfo 用 Bearer token 请求 /users/@me。
// 非 200 或 JSON 解析失败返回错误（由 Exchange 统一映射为 ErrIdentity）。
func (p *discordProvider) fetchUserInfo(ctx context.Context, token *oauth2.Token) (*discordUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	token.SetAuthHeader(req)
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
		return nil, fmt.Errorf("oauth: discord userinfo status %d", resp.StatusCode)
	}
	var user discordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

var _ Provider = (*discordProvider)(nil)

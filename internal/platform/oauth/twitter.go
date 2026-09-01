package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// Twitter/X 授权请求所需的固定 scopes。
// users.email 使 /2/users/me 返回 confirmed_email（X 的“已确认邮箱”语义）。
const (
	twitterScopeTweetRead  = "tweet.read"
	twitterScopeUsersRead  = "users.read"
	twitterScopeUsersEmail = "users.email"
)

// Twitter/X 的固定端点与 userinfo 查询参数。
// 端点由适配器代码所有；cfg 中的同名值仅在测试时覆盖。
const (
	twitterAuthorizeURL = "https://x.com/i/oauth2/authorize"
	twitterTokenURL     = "https://api.x.com/2/oauth2/token"
	twitterAPIURL       = "https://api.x.com/2"
	// twitterUserFields 请求 confirmed_email 字段：它是 X 对“已确认邮箱”的等价语义。
	twitterUserFields = "confirmed_email"
)

// twitterProvider 是 Twitter/X 的固定端点 OAuth2 API 适配器。
// 使用 S256 PKCE（授权码流要求）但不发送 nonce；confidential client 的 token 请求
// 必须使用 HTTP Basic（AuthStyleInHeader），x/oauth2 的默认行为
// 先按 body 后按 header 顺序发送，不符合 Twitter 要求。
// 探测重试会烧掉约 30 秒过期的 code。subject 是 /2/users/me 的不可变 id，
// VerifiedEmail 只在 confirmed_email 非空时填充。
type twitterProvider struct {
	key          string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	userInfoURL  string
	httpClient   *http.Client
}

func newTwitterProvider(cfg Config, client *http.Client) *twitterProvider {
	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = twitterAuthorizeURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = twitterTokenURL
	}
	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = twitterAPIURL
	}
	return &twitterProvider{
		key:          cfg.ProviderKey,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		authURL:      authURL,
		tokenURL:     tokenURL,
		userInfoURL:  strings.TrimRight(apiURL, "/") + "/users/me?user.fields=" + twitterUserFields,
		httpClient:   client,
	}
}

// Name 返回 provider 显示名称。
func (p *twitterProvider) Name() string {
	return "Twitter"
}

// clientContext 返回注入共享 HTTP client 的上下文，
// 使 token/userinfo 的全部网络请求走同一 client（含超时）。
func (p *twitterProvider) clientContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
}

func (p *twitterProvider) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.authURL,
			TokenURL:  p.tokenURL,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: redirectURI,
		Scopes:      []string{twitterScopeTweetRead, twitterScopeUsersRead, twitterScopeUsersEmail},
	}
}

// BuildAuthURL 为新的 state 与可选 PKCE verifier 生成 Twitter/X 授权 URL。
// 仅在 verifier 非空时附加 code_challenge（S256）；X 不发送 nonce，
// 即使请求中带 nonce 也忽略。
func (p *twitterProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(req.Verifier))
	}
	return p.oauthConfig(req.RedirectURI).AuthCodeURL(req.State, opts...), nil
}

// Exchange 用 code 换取 token，通过 Bearer 拉取 /2/users/me 并返回标准化后的 Identity。
// subject 是响应中不可变的 id；VerifiedEmail 只取非空的 confirmed_email，
// 缺失邮箱不否定 subject。任何失败映射为 ErrIdentity，错误文本不包含
// code/token/secret。
func (p *twitterProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.Verifier))
	}
	token, err := p.oauthConfig(req.RedirectURI).Exchange(p.clientContext(ctx), req.Code, opts...)
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
	return &Identity{Subject: user.ID, VerifiedEmail: user.ConfirmedEmail}, nil
}

// twitterUser 是 /2/users/me 返回的 data 对象。
type twitterUser struct {
	ID             string `json:"id"`
	ConfirmedEmail string `json:"confirmed_email"`
}

// fetchUserInfo 用 Bearer token 请求 /2/users/me。
// 非 200 或 JSON 解析失败返回错误（由 Exchange 统一映射为 ErrIdentity）。
func (p *twitterProvider) fetchUserInfo(ctx context.Context, token *oauth2.Token) (*twitterUser, error) {
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
		return nil, fmt.Errorf("oauth: twitter userinfo status %d", resp.StatusCode)
	}
	var body struct {
		Data twitterUser `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return &body.Data, nil
}

var _ Provider = (*twitterProvider)(nil)

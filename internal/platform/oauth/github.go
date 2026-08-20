package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

// githubScopes 是 GitHub OAuth 授权申请的范围。
const (
	githubScopes = "read:user user:email"
)

type githubProvider struct {
	key          string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	apiURL       string
	httpClient   *http.Client
}

func newGitHubProvider(cfg Config, client *http.Client) *githubProvider {
	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	return &githubProvider{
		key:          cfg.ProviderKey,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		authURL:      cfg.AuthURL,
		tokenURL:     cfg.TokenURL,
		apiURL:       apiURL,
		httpClient:   client,
	}
}

// Name 返回 provider 显示名称。
func (p *githubProvider) Name() string {
	return "GitHub"
}

func (p *githubProvider) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.authURL,
			TokenURL: p.tokenURL,
		},
		RedirectURL: redirectURI,
		Scopes:      []string{"read:user", "user:email"},
	}
}

// BuildAuthURL 为新的 state 与可选 PKCE verifier 生成 GitHub 授权 URL。
// GitHub 不发送 nonce；即使请求中带 nonce 也会忽略。
func (p *githubProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(req.Verifier))
	}
	return p.oauthConfig(req.RedirectURI).AuthCodeURL(req.State, opts...), nil
}

// httpContext 返回注入共享 HTTP client 的上下文，使 oauth2 库在统一有界超时的
// 基础 transport 上叠加 Bearer 注入，而不覆盖其认证 transport。
func (p *githubProvider) httpContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
}

// Exchange 用授权码换取 token，拉取用户与已验证邮箱，返回标准化后的 Identity。
func (p *githubProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.Verifier))
	}
	token, err := p.oauthConfig(req.RedirectURI).Exchange(p.httpContext(ctx), req.Code, opts...)
	if err != nil {
		return nil, ErrIdentity
	}
	user, err := p.fetchUser(ctx, token)
	if err != nil {
		return nil, ErrIdentity
	}
	email, err := p.fetchVerifiedEmail(ctx, token)
	if err != nil {
		return nil, ErrIdentity
	}
	if user.subject() == "" || email == "" {
		return nil, ErrIdentity
	}
	return &Identity{Subject: user.subject(), VerifiedEmail: email}, nil
}

type githubUser struct {
	ID int64 `json:"id"`
}

func (u githubUser) subject() string {
	return strconv.FormatInt(u.ID, 10)
}

type githubEmail struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

func (p *githubProvider) fetchUser(ctx context.Context, token *oauth2.Token) (*githubUser, error) {
	client := p.oauthConfig("").Client(p.httpContext(ctx), token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiURL+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github userinfo status %d", resp.StatusCode)
	}
	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *githubProvider) fetchVerifiedEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := p.oauthConfig("").Client(p.httpContext(ctx), token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiURL+"/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github emails status %d", resp.StatusCode)
	}
	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}
	for _, email := range emails {
		if email.Verified && email.Primary && email.Email != "" {
			return email.Email, nil
		}
	}
	for _, email := range emails {
		if email.Verified && email.Email != "" {
			return email.Email, nil
		}
	}
	return "", nil
}

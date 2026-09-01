package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// Apple 的固定端点、issuer 与 scopes。
const (
	appleAuthorizeURL = "https://appleid.apple.com/auth/authorize"
	appleTokenURL     = "https://appleid.apple.com/auth/token"
	appleJWKSURL      = "https://appleid.apple.com/auth/keys"
	appleIssuer       = "https://appleid.apple.com"
	appleScopeName    = "name"
	appleScopeEmail   = "email"
	// appleResponseModeFormPost 是申请 name/email scope 时回调的强制 response_mode。
	appleResponseModeFormPost = "form_post"
)

// appleProvider 是 Sign in with Apple 的固定端点适配器。
// 网页流程未定义 PKCE（不发送 code_challenge/code_verifier），nonce 按 catalog
// 发送并校验；授权请求固定 response_mode=form_post。token 交换使用现场生成的
// 短期 ES256 client-secret JWT（见 apple_secret.go）；返回的 ID token 用 Apple
// 固定 JWKS 以 RS256 校验签名、issuer、audience、有效期，nonce 由本包恒定时间
// 比较。只有语义上明确为 true 的 email_verified 且 email 非空时才输出 VerifiedEmail。
type appleProvider struct {
	key        string
	clientID   string
	teamID     string
	keyID      string
	privateKey *ecdsa.PrivateKey
	authURL    string
	tokenURL   string
	jwksURL    string
	httpClient *http.Client
}

func newAppleProvider(cfg Config, client *http.Client) (*appleProvider, error) {
	if strings.TrimSpace(cfg.AppleTeamID) == "" || strings.TrimSpace(cfg.AppleKeyID) == "" {
		return nil, fmt.Errorf("%w: apple team id and key id are required", ErrUnsupported)
	}
	privateKey, err := parseApplePrivateKey(cfg.ApplePrivateKey)
	if err != nil {
		return nil, err
	}
	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = appleAuthorizeURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = appleTokenURL
	}
	jwksURL := cfg.APIURL
	if jwksURL == "" {
		jwksURL = appleJWKSURL
	}
	return &appleProvider{
		key:        cfg.ProviderKey,
		clientID:   cfg.ClientID,
		teamID:     cfg.AppleTeamID,
		keyID:      cfg.AppleKeyID,
		privateKey: privateKey,
		authURL:    authURL,
		tokenURL:   tokenURL,
		jwksURL:    jwksURL,
		httpClient: client,
	}, nil
}

// Name 返回 provider 显示名称。
func (p *appleProvider) Name() string {
	return "Apple"
}

// clientContext 返回注入共享 HTTP client 的上下文，
// 使 token/JWKS 的全部网络请求走同一 client（含超时）。
func (p *appleProvider) clientContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, p.httpClient)
}

func (p *appleProvider) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: p.clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.authURL,
			TokenURL: p.tokenURL,
		},
		RedirectURL: redirectURI,
		Scopes:      []string{appleScopeName, appleScopeEmail},
	}
}

// BuildAuthURL 为新的 state 与可选 nonce 生成 Apple 授权 URL。
// Apple 网页流程未定义 PKCE，即使请求中带 verifier 也不附加 code_challenge；
// response_mode=form_post 始终附加（申请 name/email scope 的强制要求）。
func (p *appleProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 2)
	if req.Nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", req.Nonce))
	}
	opts = append(opts, oauth2.SetAuthURLParam("response_mode", appleResponseModeFormPost))
	return p.oauthConfig(req.RedirectURI).AuthCodeURL(req.State, opts...), nil
}

// Exchange 用 code 换取 token 并完整验证 Apple ID token。
// client-secret JWT 每次交换现场生成，绝不持久化或记录。
// 任何失败统一映射为 ErrIdentity；错误文本不包含 code/token/secret。
func (p *appleProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
	clientSecret, err := p.clientSecret(time.Now().UTC())
	if err != nil {
		return nil, ErrIdentity
	}
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("grant_type", "authorization_code")
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := postForm(ctx, p.httpClient, p.tokenURL, form, &body); err != nil {
		return nil, preserveProviderError(err)
	}
	if body.IDToken == "" {
		return nil, ErrIdentity
	}
	return p.verifyIDToken(ctx, body.IDToken, req.Nonce)
}

// verifyIDToken 用 Apple 固定 JWKS 校验 ID token（Apple issuer 固定，go-oidc 的固定 issuer verifier 适用）。
// 校验前先解析 JWS 头并要求 alg 为 RS256；
// go-oidc 负责签名、issuer、audience 与有效期，nonce 由本包恒定时间比较。
// email_verified 只在语义明确为 true 且 email 非空时输出为 VerifiedEmail。
func (p *appleProvider) verifyIDToken(ctx context.Context, raw string, nonce string) (*Identity, error) {
	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, ErrIdentity
	}
	if len(parsed.Signatures) != 1 || parsed.Signatures[0].Header.Algorithm != string(jose.RS256) {
		return nil, ErrIdentity
	}
	keySet := oidc.NewRemoteKeySet(p.clientContext(ctx), p.jwksURL)
	verifier := oidc.NewVerifier(appleIssuer, keySet, &oidc.Config{ClientID: p.clientID})
	idToken, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, preserveProviderError(err)
	}
	// go-oidc 的 Verify 不校验 nonce：必须与 ID token 的 nonce claim 恒定时间
	// 比较；流程发送了 nonce 时，缺失或不等一律拒绝。
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return nil, ErrIdentity
	}
	if idToken.Subject == "" {
		return nil, ErrIdentity
	}
	verifiedEmail, _ := appleVerifiedEmail(idToken)
	return &Identity{
		Subject:       ScopedSubject(appleIssuer, idToken.Subject),
		VerifiedEmail: verifiedEmail,
	}, nil
}

// appleVerifiedEmail 严格解析 Apple 的 email/email_verified claims。
// Apple 的 email_verified 可能序列化为布尔或字符串；仅当 email 非空且
// email_verified 语义上为 true（bool true 或大小写不敏感的 "true"）时返回邮箱；
// 任何缺失、false 或其他值都返回空邮箱。
func appleVerifiedEmail(token *oidc.IDToken) (string, bool) {
	var claims struct {
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
	}
	if err := token.Claims(&claims); err != nil {
		return "", false
	}
	if claims.Email == "" {
		return "", false
	}
	var verified any
	if err := json.Unmarshal(claims.EmailVerified, &verified); err != nil {
		return "", false
	}
	switch v := verified.(type) {
	case bool:
		if v {
			return claims.Email, true
		}
	case string:
		if strings.EqualFold(v, "true") {
			return claims.Email, true
		}
	}
	return "", false
}

var _ Provider = (*appleProvider)(nil)

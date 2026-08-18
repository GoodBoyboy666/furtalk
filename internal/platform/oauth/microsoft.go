package oauth

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// Microsoft identity platform v2 的固定端点与 issuer 模板。
// 端点与 authority 由适配器代码所有，不可配置；cfg 中的同名值仅在测试时覆盖。
const (
	microsoftAuthorizeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	microsoftTokenURL     = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	microsoftJWKSURL      = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	// microsoftIssuerTemplate 是 common metadata 的 issuer 模板；
	// 具体 issuer 只有读取 token 的 tid 后才能确定。
	microsoftIssuerTemplate    = "https://login.microsoftonline.com/{tenantid}/v2.0"
	microsoftTenantPlaceholder = "{tenantid}"
	// microsoftClockSkew 是 exp/nbf 校验允许的时钟偏差。
	microsoftClockSkew = 2 * time.Minute
	// microsoftKeyCacheTTL 是 JWKS 快照的缓存时长（有界缓存，过期后刷新）。
	microsoftKeyCacheTTL = time.Hour
)

// microsoftGUIDPattern 匹配 Microsoft tid/oid 的 GUID 格式。
var microsoftGUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// microsoftProvider 是 Microsoft identity platform v2 的固定 common 适配器。
// 使用 S256 PKCE 与必选 nonce（按 catalog）。ID token 用 Microsoft JWKS 手工
// 验证签名：issuer 先按 tid 展开模板，再与命中签名 key 的 issuer 元数据交叉
// 校验，audience、有效期与 nonce 逐一检查。subject 是不可变的 tid+oid 组合；
// email/preferred_username 可变或缺失，不作为 VerifiedEmail。
type microsoftProvider struct {
	key          string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	jwksURL      string
	httpClient   *http.Client

	mu     sync.Mutex
	jwks   map[string]microsoftSigningKey
	jwksAt time.Time
}

// microsoftSigningKey 是解析后的 Microsoft 签名密钥及其可选的 issuer 元数据。
type microsoftSigningKey struct {
	key    *jose.JSONWebKey
	issuer []string
}

func newMicrosoftProvider(cfg Config, client *http.Client) *microsoftProvider {
	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = microsoftAuthorizeURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = microsoftTokenURL
	}
	jwksURL := cfg.APIURL
	if jwksURL == "" {
		jwksURL = microsoftJWKSURL
	}
	return &microsoftProvider{
		key:          cfg.ProviderKey,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		authURL:      authURL,
		tokenURL:     tokenURL,
		jwksURL:      jwksURL,
		httpClient:   client,
	}
}

// Name 返回 provider 显示名称。
func (p *microsoftProvider) Name() string {
	return "Microsoft"
}

// clientContext 返回注入共享 HTTP client 的上下文，
// 使 token/JWKS 的全部网络请求走同一 client（含超时）。
func (p *microsoftProvider) clientContext(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
}

func (p *microsoftProvider) oauthConfig(redirectURI string) *oauth2.Config {
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

// BuildAuthURL 为新的 state、可选 PKCE verifier 与可选 nonce 生成 Microsoft
// 授权 URL。仅在 verifier 非空时附加 code_challenge（S256），仅在 nonce 非空时
// 附加 nonce 参数。
func (p *microsoftProvider) BuildAuthURL(ctx context.Context, req AuthorizationRequest) (string, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 2)
	if req.Verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(req.Verifier))
	}
	if req.Nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", req.Nonce))
	}
	return p.oauthConfig(req.RedirectURI).AuthCodeURL(req.State, opts...), nil
}

// Exchange 用 code 换取 token 并完整验证 Microsoft ID token。
// 任何失败统一映射为 ErrIdentity；错误文本不包含 code/token/secret。
func (p *microsoftProvider) Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if req.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.Verifier))
	}
	token, err := p.oauthConfig(req.RedirectURI).Exchange(p.clientContext(ctx), req.Code, opts...)
	if err != nil {
		return nil, ErrIdentity
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, ErrIdentity
	}
	return p.verifyIDToken(ctx, rawIDToken, req.Nonce)
}

// verifyIDToken 手工验证 Microsoft ID token（不使用 go-oidc 的固定 issuer
// verifier，因为具体 issuer 由 token 的 tid 决定）：
// 解析 JWS 头并限制 RS256，取 kid 命中签名密钥并验证签名，然后依次检查
// issuer 模板展开、签名 key issuer 约束、audience、有效期、nonce、tid/oid。
func (p *microsoftProvider) verifyIDToken(ctx context.Context, raw string, nonce string) (*Identity, error) {
	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, ErrIdentity
	}
	if len(parsed.Signatures) != 1 {
		return nil, ErrIdentity
	}
	kid := parsed.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, ErrIdentity
	}
	keys, err := p.signingKeys(ctx)
	if err != nil {
		return nil, ErrIdentity
	}
	signingKey, ok := keys[kid]
	if !ok {
		return nil, ErrIdentity
	}
	payload, err := parsed.Verify(signingKey.key.Key)
	if err != nil {
		return nil, ErrIdentity
	}
	var claims struct {
		Iss   string `json:"iss"`
		Aud   string `json:"aud"`
		Exp   int64  `json:"exp"`
		Nbf   int64  `json:"nbf"`
		Nonce string `json:"nonce"`
		TID   string `json:"tid"`
		OID   string `json:"oid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrIdentity
	}
	if !microsoftGUIDPattern.MatchString(claims.TID) || claims.OID == "" {
		return nil, ErrIdentity
	}
	now := time.Now().UTC()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(microsoftClockSkew)) {
		return nil, ErrIdentity
	}
	if claims.Nbf != 0 && now.Add(microsoftClockSkew).Before(time.Unix(claims.Nbf, 0)) {
		return nil, ErrIdentity
	}
	expectedIssuer := strings.ReplaceAll(microsoftIssuerTemplate, microsoftTenantPlaceholder, claims.TID)
	if claims.Iss != expectedIssuer {
		return nil, ErrIdentity
	}
	if claims.Aud != p.clientID {
		return nil, ErrIdentity
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return nil, ErrIdentity
	}
	if len(signingKey.issuer) > 0 && !microsoftKeyAllowsIssuer(signingKey.issuer, claims.TID, claims.Iss) {
		return nil, ErrIdentity
	}
	return &Identity{
		Subject:       claims.TID + ":" + claims.OID,
		VerifiedEmail: "",
	}, nil
}

// microsoftKeyAllowsIssuer 判断命中签名 key 的 issuer 元数据是否允许该 token
// issuer：每条目按 token tid 展开 {tenantid} 模板后精确匹配。
func microsoftKeyAllowsIssuer(entries []string, tid, tokenIssuer string) bool {
	for _, entry := range entries {
		if expanded := strings.ReplaceAll(entry, microsoftTenantPlaceholder, tid); expanded == tokenIssuer {
			return true
		}
	}
	return false
}

// signingKeys 返回缓存的 Microsoft 签名密钥；缓存过期或缺失时重新抓取。
// 抓取失败返回错误（失败关闭），不返回过期快照。
func (p *microsoftProvider) signingKeys(ctx context.Context) (map[string]microsoftSigningKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.jwks != nil && time.Since(p.jwksAt) < microsoftKeyCacheTTL {
		return p.jwks, nil
	}
	keys, err := p.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	p.jwks = keys
	p.jwksAt = time.Now().UTC()
	return keys, nil
}

// fetchJWKS 抓取并解析 Microsoft JWKS，返回 kid 索引。
// 任一密钥缺少 kid、issuer 元数据畸形或不是 RSA 公钥时整体拒绝（失败关闭）。
func (p *microsoftProvider) fetchJWKS(ctx context.Context) (map[string]microsoftSigningKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL, nil)
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
		return nil, fmt.Errorf("oauth: microsoft jwks status %d", resp.StatusCode)
	}
	var body struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	keys := make(map[string]microsoftSigningKey, len(body.Keys))
	for _, raw := range body.Keys {
		key, err := parseMicrosoftSigningKey(raw)
		if err != nil {
			return nil, err
		}
		keys[key.key.KeyID] = key
	}
	return keys, nil
}

// microsoftJWKMeta 是 JWK 中与签名无关的元数据（kid 与 issuer）。
type microsoftJWKMeta struct {
	Kid    string          `json:"kid"`
	Issuer json.RawMessage `json:"issuer"`
}

// parseMicrosoftSigningKey 解析单个 Microsoft 签名密钥：
// kid 必须存在；issuer（若出现）必须是字符串数组且每个元素非空；
// 密钥本身必须是 RSA 公钥。
func parseMicrosoftSigningKey(raw json.RawMessage) (microsoftSigningKey, error) {
	var meta microsoftJWKMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return microsoftSigningKey{}, err
	}
	if meta.Kid == "" {
		return microsoftSigningKey{}, fmt.Errorf("oauth: microsoft signing key missing kid")
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return microsoftSigningKey{}, err
	}
	if _, ok := jwk.Key.(*rsa.PublicKey); !ok {
		return microsoftSigningKey{}, fmt.Errorf("oauth: microsoft signing key %q is not an rsa public key", meta.Kid)
	}
	out := microsoftSigningKey{key: &jwk}
	if len(meta.Issuer) > 0 {
		var issuers []string
		if err := json.Unmarshal(meta.Issuer, &issuers); err != nil {
			return microsoftSigningKey{}, fmt.Errorf("oauth: microsoft signing key %q has malformed issuer metadata", meta.Kid)
		}
		if len(issuers) == 0 {
			return microsoftSigningKey{}, fmt.Errorf("oauth: microsoft signing key %q has empty issuer metadata", meta.Kid)
		}
		for _, iss := range issuers {
			if iss == "" {
				return microsoftSigningKey{}, fmt.Errorf("oauth: microsoft signing key %q has empty issuer entry", meta.Kid)
			}
		}
		out.issuer = issuers
	}
	return out, nil
}

var _ Provider = (*microsoftProvider)(nil)

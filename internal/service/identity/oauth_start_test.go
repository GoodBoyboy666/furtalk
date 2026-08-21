package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/oauth"
)

// fakeOAuthProvider 是 BeginOAuth 测试使用的 provider 替身。
type fakeOAuthProvider struct {
	name     string
	authURL  string
	buildErr error
	gotAuth  oauth.AuthorizationRequest
}

func (p *fakeOAuthProvider) Name() string { return p.name }

func (p *fakeOAuthProvider) BuildAuthURL(ctx context.Context, req oauth.AuthorizationRequest) (string, error) {
	p.gotAuth = req
	if p.buildErr != nil {
		return "", p.buildErr
	}
	return p.authURL, nil
}

func (p *fakeOAuthProvider) Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.Identity, error) {
	return nil, oauth.ErrIdentity
}

// fakeOAuthFactory 按 provider key 返回可配置的 provider 或构造错误。
type fakeOAuthFactory struct {
	provider OAuthProvider
	failKeys map[string]error
}

func (f *fakeOAuthFactory) build(cfg OAuthProviderConfig) (OAuthProvider, error) {
	if f.failKeys != nil {
		if err := f.failKeys[cfg.ProviderKey]; err != nil {
			return nil, err
		}
	}
	return f.provider, nil
}

// oauthTestProviders 是 BeginOAuth 测试的 provider 读取器替身。
type oauthTestProviders struct {
	provider *AuthProvider
	err      error
}

func (p oauthTestProviders) OAuthProviders(ctx context.Context) ([]AuthProvider, error) {
	return nil, nil
}

func (p oauthTestProviders) OAuthProvider(ctx context.Context, providerKey string) (*AuthProvider, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.provider, nil
}

// newOAuthStartService 装配 BeginOAuth 所需的最小服务。
func newOAuthStartService(providers OAuthProviderReader, factory OAuthProviderFactory) *Service {
	store := cache.NewMemory(10000)
	return NewService(Dependencies{
		Cache:        store,
		Providers:    providers,
		OAuthFactory: factory,
		BaseURL:      "https://example.com",
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// TestBeginOAuthSuccessfulGitHubURL 验证 github provider 成功返回授权 URL。
func TestBeginOAuthSuccessfulGitHubURL(t *testing.T) {
	t.Parallel()
	factory := &fakeOAuthFactory{provider: &fakeOAuthProvider{name: "GitHub", authURL: "https://github.com/login/oauth/authorize?x=1"}}
	svc := newOAuthStartService(oauthTestProviders{
		provider: &AuthProvider{ProviderKey: "github", Kind: domain.ProviderKindOAuth, ClientID: "id", ClientSecret: "secret"},
	}, factory.build)

	start, err := svc.BeginOAuth(context.Background(), "github", oauthPurposeLogin, 0, "")
	if err != nil {
		t.Fatalf("BeginOAuth: %v", err)
	}
	if start == nil || start.AuthURL == "" {
		t.Fatal("start must include a non-empty auth URL")
	}
}

// TestBeginOAuthBindRequiresPrincipal 验证 bind 未带 userID 返回 ErrInvalidCredentials。
func TestBeginOAuthBindRequiresPrincipal(t *testing.T) {
	t.Parallel()
	svc := newOAuthStartService(oauthTestProviders{}, nil)
	if _, err := svc.BeginOAuth(context.Background(), "github", oauthPurposeBind, 0, ""); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("bind without user err = %v, want ErrInvalidCredentials", err)
	}
}

// TestBeginOAuthProviderNotFound 验证缺失/禁用 provider 返回 ErrProviderNotFound。
func TestBeginOAuthProviderNotFound(t *testing.T) {
	t.Parallel()
	svc := newOAuthStartService(oauthTestProviders{err: domain.ErrProviderNotFound}, nil)
	if _, err := svc.BeginOAuth(context.Background(), "missing", oauthPurposeLogin, 0, ""); !errors.Is(err, domain.ErrProviderNotFound) {
		t.Fatalf("missing provider err = %v, want ErrProviderNotFound", err)
	}
}

// TestBeginOAuthSecretCorrupt 验证密钥损坏返回 ErrSecretCorrupt。
func TestBeginOAuthSecretCorrupt(t *testing.T) {
	t.Parallel()
	svc := newOAuthStartService(oauthTestProviders{err: domain.ErrSecretCorrupt}, nil)
	if _, err := svc.BeginOAuth(context.Background(), "github", oauthPurposeLogin, 0, ""); !errors.Is(err, domain.ErrSecretCorrupt) {
		t.Fatalf("secret corrupt err = %v, want ErrSecretCorrupt", err)
	}
}

// TestBeginOAuthProviderConstructionFailure 验证 provider 构造失败返回 ErrUnavailable。
func TestBeginOAuthProviderConstructionFailure(t *testing.T) {
	t.Parallel()
	factory := &fakeOAuthFactory{failKeys: map[string]error{"github": oauth.ErrUnsupported}}
	svc := newOAuthStartService(oauthTestProviders{
		provider: &AuthProvider{ProviderKey: "github", Kind: domain.ProviderKindOAuth, ClientID: "id", ClientSecret: "secret"},
	}, factory.build)

	if _, err := svc.BeginOAuth(context.Background(), "github", oauthPurposeLogin, 0, ""); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("construction failure err = %v, want ErrUnavailable", err)
	}
}

// TestBeginOAuthDiscoveryFailure 验证 OIDC discovery/授权 URL 失败返回 ErrUnavailable。
func TestBeginOAuthDiscoveryFailure(t *testing.T) {
	t.Parallel()
	factory := &fakeOAuthFactory{provider: &fakeOAuthProvider{name: "OIDC", buildErr: oauth.ErrIdentity}}
	svc := newOAuthStartService(oauthTestProviders{
		provider: &AuthProvider{ProviderKey: "custom", Kind: domain.ProviderKindOIDC, ClientID: "id", ClientSecret: "secret", IssuerURL: "https://issuer.example.com"},
	}, factory.build)

	if _, err := svc.BeginOAuth(context.Background(), "custom", oauthPurposeLogin, 0, ""); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("discovery failure err = %v, want ErrUnavailable", err)
	}
}

// TestBeginOAuthValidationErrors 验证非法 purpose 返回 ErrValidation。
func TestBeginOAuthValidationErrors(t *testing.T) {
	t.Parallel()
	svc := newOAuthStartService(oauthTestProviders{}, nil)
	if _, err := svc.BeginOAuth(context.Background(), "github", "steal", 0, ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid purpose err = %v, want ErrValidation", err)
	}
}

// TestBeginOAuthCapabilitiesByCatalog 验证 BeginOAuth 按 catalog 能力生成
// PKCE verifier 与 nonce：PKCE provider 带 verifier、ID-token provider 带 nonce、
// 两者都不支持的 provider 均留空；未知 key 保持自定义 OIDC（两者都生成）。
func TestBeginOAuthCapabilitiesByCatalog(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		providerKey  string
		kind         domain.ProviderKind
		wantVerifier bool
		wantNonce    bool
	}{
		{name: "github pkce no nonce", providerKey: "github", kind: domain.ProviderKindOAuth, wantVerifier: true, wantNonce: false},
		{name: "google pkce and nonce", providerKey: "google", kind: domain.ProviderKindOIDC, wantVerifier: true, wantNonce: true},
		{name: "discord no pkce no nonce", providerKey: "discord", kind: domain.ProviderKindOAuth, wantVerifier: false, wantNonce: false},
		{name: "custom oidc pkce and nonce", providerKey: "custom", kind: domain.ProviderKindOIDC, wantVerifier: true, wantNonce: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeOAuthProvider{name: "P", authURL: "https://auth.example.com/start"}
			factory := &fakeOAuthFactory{provider: fake}
			svc := newOAuthStartService(oauthTestProviders{
				provider: &AuthProvider{ProviderKey: tt.providerKey, Kind: tt.kind, ClientID: "id", ClientSecret: "secret"},
			}, factory.build)

			if _, err := svc.BeginOAuth(context.Background(), tt.providerKey, oauthPurposeLogin, 0, ""); err != nil {
				t.Fatalf("BeginOAuth: %v", err)
			}
			if (fake.gotAuth.Verifier != "") != tt.wantVerifier {
				t.Fatalf("verifier present = %q, want %v", fake.gotAuth.Verifier, tt.wantVerifier)
			}
			if (fake.gotAuth.Nonce != "") != tt.wantNonce {
				t.Fatalf("nonce present = %q, want %v", fake.gotAuth.Nonce, tt.wantNonce)
			}
			if fake.gotAuth.State == "" {
				t.Fatal("state must be non-empty")
			}
			if fake.gotAuth.RedirectURI != "https://example.com/oauth/callback/"+tt.providerKey {
				t.Fatalf("redirect uri = %q", fake.gotAuth.RedirectURI)
			}
		})
	}
}

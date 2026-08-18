package oauth

// RegistrationMode 是固定 provider 的注册模式（产品策略，管理端不可配置）。
type RegistrationMode string

const (
	// RegistrationVerifiedEmail 表示未绑定身份在适配器返回可信已验证邮箱时走现有注册路径。
	RegistrationVerifiedEmail RegistrationMode = "verified_email"
	// RegistrationBindOnly 表示未绑定身份只能由已登录用户主动绑定，不能注册或按邮箱匹配。
	RegistrationBindOnly RegistrationMode = "bind_only"
)

// CallbackMode 是授权回调的接收方式。
type CallbackMode string

const (
	// CallbackQuery 表示回调参数以 query 字符串传递（默认）。
	CallbackQuery CallbackMode = "query"
	// CallbackFormPost 表示回调参数以 application/x-www-form-urlencoded POST 传递。
	CallbackFormPost CallbackMode = "form_post"
)

// ConfigSpec 描述固定 provider 的配置 schema。
type ConfigSpec struct {
	// PublicFields 是允许进入 public_config 的字段（JSON key），不含机密字段。
	PublicFields []string
	// SecretField 是机密字段的 JSON key（client_secret 或 private_key）；空表示该 provider 无机密。
	SecretField string
	// InstanceURLRequired 要求管理端显式提供 instance_url。
	InstanceURLRequired bool
	// InstanceURLDefault 是 instance_url 留空时使用的默认值；空表示无默认值。
	InstanceURLDefault string
	// FixedPublic 是预设锁定的公开字段值（如 github 的 auth_url/token_url、google 的 issuer_url），
	// 管理端提交的同名字段会被覆盖。
	FixedPublic map[string]string
}

// ProviderSpec 是固定内置 OAuth/OIDC provider 的元数据。
// 平台层不使用 domain.ProviderKind，kind 以普通字符串表达，避免对 domain 层的依赖。
type ProviderSpec struct {
	// Key 是固定 provider key，每种内置 provider 只允许一条配置。
	Key string
	// Name 是展示名。
	Name string
	// Kind 是必需的 provider 类型（"oauth" 或 "oidc"）。
	Kind string
	// Registration 是注册模式。
	Registration RegistrationMode
	// PKCE 表示授权码流程是否使用 S256 PKCE。
	PKCE bool
	// Nonce 表示返回 ID Token 的流程是否发送并校验 nonce。
	Nonce bool
	// Callback 是回调接收方式。
	Callback CallbackMode
	// Config 是配置 schema。
	Config ConfigSpec
}

// Catalog 是固定内置 provider 的只读目录，按 key 升序。
// 未知 key 不在目录中，上层按自定义 OIDC 处理。
var Catalog = []ProviderSpec{
	{
		Key:          "apple",
		Name:         "Apple",
		Kind:         "oidc",
		Registration: RegistrationVerifiedEmail,
		PKCE:         false,
		Nonce:        true,
		Callback:     CallbackFormPost,
		Config: ConfigSpec{
			PublicFields: []string{"client_id", "team_id", "key_id"},
			SecretField:  "private_key",
		},
	},
	{
		Key:          "discord",
		Name:         "Discord",
		Kind:         "oauth",
		Registration: RegistrationVerifiedEmail,
		PKCE:         false,
		Nonce:        false,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields: []string{"client_id"},
			SecretField:  "client_secret",
		},
	},
	{
		Key:          "gitea",
		Name:         "Gitea",
		Kind:         "oidc",
		Registration: RegistrationVerifiedEmail,
		PKCE:         true,
		Nonce:        true,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields:        []string{"client_id", "instance_url"},
			SecretField:         "client_secret",
			InstanceURLRequired: true,
		},
	},
	{
		Key:          "github",
		Name:         "GitHub",
		Kind:         "oauth",
		Registration: RegistrationVerifiedEmail,
		PKCE:         true,
		Nonce:        false,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields: []string{"client_id", "auth_url", "token_url"},
			SecretField:  "client_secret",
			FixedPublic: map[string]string{
				"auth_url":  "https://github.com/login/oauth/authorize",
				"token_url": "https://github.com/login/oauth/access_token",
			},
		},
	},
	{
		Key:          "gitlab",
		Name:         "GitLab",
		Kind:         "oidc",
		Registration: RegistrationVerifiedEmail,
		PKCE:         true,
		Nonce:        true,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields:       []string{"client_id", "instance_url"},
			SecretField:        "client_secret",
			InstanceURLDefault: "https://gitlab.com",
		},
	},
	{
		Key:          "google",
		Name:         "Google",
		Kind:         "oidc",
		Registration: RegistrationVerifiedEmail,
		PKCE:         true,
		Nonce:        true,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields: []string{"client_id", "issuer_url"},
			SecretField:  "client_secret",
			FixedPublic: map[string]string{
				"issuer_url": "https://accounts.google.com",
			},
		},
	},
	{
		Key:          "line",
		Name:         "LINE",
		Kind:         "oidc",
		Registration: RegistrationBindOnly,
		PKCE:         true,
		Nonce:        true,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields: []string{"client_id"},
			SecretField:  "client_secret",
		},
	},
	{
		Key:          "mastodon",
		Name:         "Mastodon",
		Kind:         "oauth",
		Registration: RegistrationBindOnly,
		PKCE:         true,
		Nonce:        false,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields:        []string{"client_id", "instance_url"},
			SecretField:         "client_secret",
			InstanceURLRequired: true,
		},
	},
	{
		Key:          "microsoft",
		Name:         "Microsoft",
		Kind:         "oidc",
		Registration: RegistrationBindOnly,
		PKCE:         true,
		Nonce:        true,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields: []string{"client_id"},
			SecretField:  "client_secret",
		},
	},
	{
		Key:          "twitter",
		Name:         "Twitter",
		Kind:         "oauth",
		Registration: RegistrationVerifiedEmail,
		PKCE:         true,
		Nonce:        false,
		Callback:     CallbackQuery,
		Config: ConfigSpec{
			PublicFields: []string{"client_id"},
			SecretField:  "client_secret",
		},
	},
}

// LookupProvider 按 key 查找固定内置 provider；未知 key 返回 false。
func LookupProvider(key string) (*ProviderSpec, bool) {
	for i := range Catalog {
		if Catalog[i].Key == key {
			return &Catalog[i], true
		}
	}
	return nil, false
}

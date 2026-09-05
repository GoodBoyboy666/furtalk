// Package identity 身份与授权用例的业务层。
// 数据经 repository 读写；设置策略与 OAuth provider 解密由 setting 层提供；
package identity

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/onetime"
	"furtalk/internal/repository"
)

// mapEphemeralError keeps cache capacity details out of the HTTP contract and
// logs only the fixed namespace name. Cache records and keys are never logged.
func (s *Service) mapEphemeralError(ctx context.Context, namespace string, err error) error {
	if errors.Is(err, cache.ErrCapacity) {
		logging.FromContext(ctx, s.log).WarnContext(ctx, "ephemeral namespace capacity exhausted", "namespace", namespace)
		return domain.ErrUnavailable
	}
	return err
}

// 邮箱验证码与密码策略的进程常量。
const (
	emailCodeTTL         = 5 * time.Minute
	emailCodeMaxAttempts = 3
	emailCodeLength      = 6
	minPasswordLength    = 8
	emailCodePurpose     = "login"
	// passwordResetPurpose 密码重置验证码的用途键，与登录验证码隔离。
	passwordResetPurpose = "password_reset"
	// passwordResetCodeTTL 密码重置验证码的有效期。
	passwordResetCodeTTL = 10 * time.Minute
	// passwordResetMaxAttempts 密码重置验证码允许的最大失败次数。
	passwordResetMaxAttempts = 5
	// EmailCodeAction 邮箱验证码发送的 CAPTCHA 策略操作键。
	EmailCodeAction = "email_code"
	// EmailCodeLoginAction 邮箱验证码登录的 CAPTCHA 策略操作键。
	EmailCodeLoginAction = "email_code_login"
	// PasswordLoginAction 邮箱密码登录的 CAPTCHA 策略操作键。
	PasswordLoginAction = "password_login"
	// PasswordResetAction 匿名请求密码重置验证码的 CAPTCHA 策略操作键。
	// 默认关闭；开启时只门禁请求验证码阶段，提交验证码与新密码不重复要求。
	PasswordResetAction = "password_reset"
)

// Service 实现身份用例，是模块的门面。
type Service struct {
	txRunner        TxRunner
	users           *repository.UserRepo
	passkeys        *repository.PasskeyRepo
	identities      *repository.ExternalIdentityRepo
	prefs           *repository.PreferenceRepo
	emailCodes      EmailCodeStore
	passkeyStore    *cache.Namespace
	oauthState      *cache.Namespace
	oauthHandoff    *cache.Namespace
	cache           cache.Store
	policy          PolicyReader
	captchaPolicy   CaptchaPolicyReader
	captcha         CaptchaVerifier
	providers       OAuthProviderReader
	signer          TokenSigner
	mailer          mailer.Mailer
	templates       mailer.TemplateRenderer
	log             *slog.Logger
	now             func() time.Time
	codeTTL         time.Duration
	maxAttempts     int
	passkeyAdapter  PasskeyAdapter
	oauth           OAuthProviderFactory
	baseURL         string
	failFast        func(error)
	commentDeleter  domain.CommentDeleter
	authzLocks      authzLockRegistry
	adminMutation   sync.Mutex
	credentialLocks userLockRegistry
	admission       PasswordLoginAdmission
	passwordBudget  *argon2Budget
}

// Dependencies  identity 模块构建函数的装配输入。
type Dependencies struct {
	TxRunner       TxRunner
	Users          *repository.UserRepo
	Passkeys       *repository.PasskeyRepo
	Identities     *repository.ExternalIdentityRepo
	Prefs          *repository.PreferenceRepo
	Cache          cache.Store
	OneTime        *onetime.Store
	Policy         PolicyReader
	CaptchaPolicy  CaptchaPolicyReader
	Captcha        CaptchaVerifier
	Providers      OAuthProviderReader
	Signer         TokenSigner
	Mailer         mailer.Mailer
	Templates      mailer.TemplateRenderer
	PasskeyAdapter PasskeyAdapter
	OAuthFactory   OAuthProviderFactory
	BaseURL        string
	FailFast       func(error)
	CommentDeleter domain.CommentDeleter
	Admission      PasswordLoginAdmission
	Logger         *slog.Logger
}

// PasswordLoginAdmission 公开密码登录使用的窄流程预算端口。
// 生产实现由 app 注入共享的 ratelimit.PolicyRegistry。
type PasswordLoginAdmission interface {
	Allow(policy, subject string) bool
}

// NewService 构建身份服务。
func NewService(deps Dependencies) *Service {
	deps.Logger = logging.Normalize(deps.Logger)
	if deps.FailFast == nil {
		deps.FailFast = func(error) {}
	}
	oneTime := deps.OneTime
	if oneTime == nil && deps.Cache != nil {
		// Directly constructed services in focused tests may only provide the
		// existing cache backend; production wiring supplies the shared wrapper.
		oneTime, _ = onetime.New(deps.Cache)
	}
	return &Service{
		txRunner:       deps.TxRunner,
		users:          deps.Users,
		passkeys:       deps.Passkeys,
		identities:     deps.Identities,
		prefs:          deps.Prefs,
		emailCodes:     cacheEmailCodeStore{store: deps.Cache, onetime: oneTime},
		passkeyStore:   cache.NewNamespace(deps.Cache, "passkey", passkeyKeyPrefix, 2000),
		oauthState:     cache.NewNamespace(deps.Cache, "oauth_state", oauthStatePrefix, 2000),
		oauthHandoff:   cache.NewNamespace(deps.Cache, "oauth_handoff", oauthHandoffPrefix, 500),
		cache:          deps.Cache,
		policy:         deps.Policy,
		captchaPolicy:  deps.CaptchaPolicy,
		captcha:        deps.Captcha,
		providers:      deps.Providers,
		signer:         deps.Signer,
		mailer:         deps.Mailer,
		templates:      deps.Templates,
		log:            deps.Logger,
		now:            time.Now,
		codeTTL:        emailCodeTTL,
		maxAttempts:    emailCodeMaxAttempts,
		passkeyAdapter: deps.PasskeyAdapter,
		oauth:          deps.OAuthFactory,
		baseURL:        deps.BaseURL,
		failFast:       deps.FailFast,
		commentDeleter: deps.CommentDeleter,
		admission:      deps.Admission,
		passwordBudget: newArgon2Budget(publicPasswordLoginConcurrency),
	}
}

// runAdminMutation 在进程内串行化管理员变更，并在事务内锁定活跃管理员集合。
// 管理员互斥锁覆盖事务提交或回滚，避免提交前释放造成新的检查竞态。
func (s *Service) runAdminMutation(ctx context.Context, fn func(context.Context) error) error {
	s.adminMutation.Lock()
	defer s.adminMutation.Unlock()
	return s.txRunner.RunInTx(ctx, func(txCtx context.Context) error {
		if _, err := s.users.LockActiveAdmins(txCtx); err != nil {
			return err
		}
		return fn(txCtx)
	})
}

// SetCommentDeleter 安装评论清理写接口。
// comment.Service 与 identity.Service 相互引用，组合根构造两侧后调用本方法接线。
func (s *Service) SetCommentDeleter(w domain.CommentDeleter) {
	s.commentDeleter = w
}

// PolicyReader 提供身份用例所需的动态实例策略（来自 setting 层）。
type PolicyReader interface {
	// Policy 返回公开注册开关与当前评论模式。
	Policy(ctx context.Context) (publicRegistration bool, commentMode string, err error)
	// EmailPolicy 返回当前邮箱域名名单与 Gravatar 头像基址。
	EmailPolicy(ctx context.Context) (whitelist, blacklist []string, gravatarBase string, err error)
}

// CaptchaPolicyReader 提供身份用例所需的动态 CAPTCHA action 策略（来自 setting 层）。
type CaptchaPolicyReader interface {
	// CaptchaPolicy 返回当前 action 到是否强制验证的映射。
	CaptchaPolicy(ctx context.Context) (map[string]bool, error)
}

// CaptchaVerifier 邮箱验证码发送前的 CAPTCHA 校验边界。
// 只返回 nil 或 domain 的 CAPTCHA 错误（必要时包装这些 sentinel）。
type CaptchaVerifier interface {
	Verify(ctx context.Context, action, token string) error
}

// OAuthProviderReader 提供已启用且已配置的 OAuth/OIDC 提供商数据（来自 setting 层）。
type OAuthProviderReader interface {
	OAuthProviders(ctx context.Context) ([]AuthProvider, error)
	OAuthProvider(ctx context.Context, providerKey string) (*AuthProvider, error)
}

// AuthProvider 是 identity 消费的 OAuth/OIDC 提供商投影。
// 具体 setting DTO 由组合根逐字段转换，避免 sibling feature 类型泄漏。
type AuthProvider struct {
	ProviderKey     string
	Kind            domain.ProviderKind
	Enabled         bool
	Configured      bool
	ClientID        string
	ClientSecret    string
	AuthURL         string
	TokenURL        string
	IssuerURL       string
	InstanceURL     string
	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey string
}

// TxRunner 身份用例使用的事务边界。
type TxRunner interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

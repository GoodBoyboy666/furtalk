package comment

import (
	"context"
	"log/slog"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/logging"
	"furtalk/internal/repository"
)

// 业务限制常量。
const (
	maxBodyLength      = 4000
	maxPageKeyLength   = 512
	maxPageURLLength   = 2048
	maxPageTitleLength = 512
	defaultLimit       = 50
	maxLimit           = 100
	defaultLatestLimit = 25
	maxLatestLimit     = 25
	authCodeTTL        = 60 * time.Second
	authCodeBytes      = 16
	maxNicknameLength  = 100
)

// CommentAction 是评论创建的 CAPTCHA 策略操作键。
const (
	CommentAction = "comment"
)

// Service 实现线程、评论与 widget 凭证生命周期用例，是模块的门面。
type Service struct {
	txRunner  TxRunner
	threads   *repository.ThreadRepo
	comments  *repository.CommentRepo
	sites     *repository.SiteRepo
	users     *repository.UserRepo
	settings  SettingsReader
	providers CaptchaProviderReader
	userW     domain.UserWriter
	captcha   CaptchaVerifier
	authz     PrincipalResolver
	signer    TokenSigner
	codes     AuthCodeStore
	verifier  WidgetCredentialVerifier
	spam      *SpamGateway
	bus       EventPublisher
	log       *slog.Logger
	now       func() time.Time
	codeTTL   time.Duration
}

// Dependencies 是 comment 模块 builder 的装配输入。
type Dependencies struct {
	TxRunner  TxRunner
	Threads   *repository.ThreadRepo
	Comments  *repository.CommentRepo
	Sites     *repository.SiteRepo
	Users     *repository.UserRepo
	Settings  SettingsReader
	Providers CaptchaProviderReader
	UserW     domain.UserWriter
	Captcha   CaptchaVerifier
	Authz     PrincipalResolver
	Signer    TokenSigner
	Codes     AuthCodeStore
	Verifier  WidgetCredentialVerifier
	Spam      *SpamGateway
	Bus       EventPublisher
	Logger    *slog.Logger
}

// NewService 构建评论服务。
func NewService(deps Dependencies) *Service {
	deps.Logger = logging.Normalize(deps.Logger)
	return &Service{
		txRunner:  deps.TxRunner,
		threads:   deps.Threads,
		comments:  deps.Comments,
		sites:     deps.Sites,
		users:     deps.Users,
		settings:  deps.Settings,
		providers: deps.Providers,
		userW:     deps.UserW,
		captcha:   deps.Captcha,
		authz:     deps.Authz,
		signer:    deps.Signer,
		codes:     deps.Codes,
		verifier:  deps.Verifier,
		spam:      deps.Spam,
		bus:       deps.Bus,
		log:       deps.Logger,
		now:       func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) },
		codeTTL:   authCodeTTL,
	}
}

// SettingsReader 提供评论用例所需的动态实例策略。
type SettingsReader interface {
	CommentPolicy(ctx context.Context) (domain.CommentPolicy, error)
}

// CaptchaProviderReader 读取当前选择的 CAPTCHA provider 解密配置。
type CaptchaProviderReader interface {
	SelectedCaptcha(ctx context.Context) (*CaptchaConfig, error)
}

// CaptchaVerifier 是评论与 widget 会话用例消费的 CAPTCHA 验证边界。
type CaptchaVerifier interface {
	Verify(ctx context.Context, action, token string) error
}

// PrincipalResolver 把用户 id 解析为其当前的授权状态。
type PrincipalResolver interface {
	Resolve(ctx context.Context, userID int64) (domain.Principal, error)
}

// TokenSigner 签发绑定到站点和凭证 epoch 的 widget JWT。
type TokenSigner interface {
	SignWidget(userID, siteID int64, kind, epoch string) (string, error)
	Lifetime() time.Duration
}

// AuthCodeStore 持久化并原子消费授权码。
type AuthCodeStore interface {
	SetAuthCode(ctx context.Context, codeHash string, record AuthCodeRecord, ttl time.Duration) error
	ConsumeAuthCode(ctx context.Context, codeHash string) (AuthCodeRecord, error)
}

// WidgetCredential 是 widget 令牌的已验证数据。
// 令牌只存在 widget_authenticated 一种；live 评论模式不能从令牌推导，
// 消费方必须结合实时 CommentPolicy 与角色矩阵。
type WidgetCredential interface {
	UserID() int64
	SiteID() int64
	Epoch() int64
	ExpiresAt() time.Time
}

// WidgetCredentialVerifier 解析并验证 widget 令牌。
type WidgetCredentialVerifier interface {
	Verify(ctx context.Context, raw string) (WidgetCredential, error)
}

// WidgetSettingsReader 提供当前评论模式与凭证 epoch。
type WidgetSettingsReader interface {
	WidgetConfig(ctx context.Context) (mode string, epoch int64, err error)
}

// TxRunner 是评论用例使用的事务边界。
type TxRunner interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// EventPublisher 是提交后事件的发布边界。
type EventPublisher interface {
	Publish(domain.CommentEvent) error
}

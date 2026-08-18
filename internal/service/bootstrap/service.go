// Package bootstrap 是首次运行引导用例的业务层。
// 创建首位管理员经 FirstAdminWriter 由 identity 层代写用户（含密码哈希）；
// bootstrap 单例行经 repository 持久化。
package bootstrap

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/value"
	"furtalk/internal/repository"
)

// 引导流程的进程常量。
const (
	setupTokenTTL     = 10 * time.Minute
	setupTokenByteLen = 32
	minPasswordLength = 8
	minNicknameLength = 1
)

// AdminInput 携带创建首位管理员所需的 setup token 与管理员凭据。
type AdminInput struct {
	SetupToken string
	Email      string
	Nickname   string
	Password   string
}

// TxRunner 提供 bootstrap 用例使用的事务边界。
type TxRunner interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// FirstAdminWriter 由 identity.Service 实现，供 bootstrap 原子地创建首位管理员。
// 密码哈希与邮箱规范化等不变量保留在 identity 层。
type FirstAdminWriter interface {
	CreateUserWithPassword(ctx context.Context, user *domain.User, password string) error
	FindUserByEmailNormalized(ctx context.Context, normalized string) (*domain.User, error)
}

type setupToken struct {
	mu        sync.Mutex
	raw       string
	hash      string
	expiresAt time.Time
	used      bool
}

func newSetupToken(ttl time.Duration) (*setupToken, error) {
	raw, err := cryptox.RandomToken(setupTokenByteLen)
	if err != nil {
		return nil, fmt.Errorf("generate setup token: %w", err)
	}
	return &setupToken{
		raw:       raw,
		hash:      cryptox.SHA256Hex([]byte(raw)),
		expiresAt: time.Now().Add(ttl),
	}, nil
}

// plaintext 返回用于控制台输出的活跃令牌。
func (t *setupToken) plaintext(now time.Time) (string, bool) {
	if t == nil {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.used || t.hash == "" || t.expiresAt.Before(now) {
		return "", false
	}
	return t.raw, true
}

// verify 以常量时间原子地检查并消费令牌。
func (t *setupToken) verify(candidate string, now time.Time) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.used || t.hash == "" || t.expiresAt.Before(now) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cryptox.SHA256Hex([]byte(candidate))), []byte(t.hash)) != 1 {
		return false
	}
	t.used = true
	return true
}

// Service 实现首次运行引导用例。
type Service struct {
	txRunner  TxRunner
	users     FirstAdminWriter
	bootstrap *repository.BootstrapRepo
	token     *setupToken
	log       *slog.Logger
	now       func() time.Time
}

// NewService 构建 bootstrap 服务。
// 仅当实例尚未初始化且初始化状态读取成功时才生成并输出明文 setup token；
// 已初始化的启动与状态读取失败路径一律不输出 token。
func NewService(txRunner TxRunner, users FirstAdminWriter, bootstrap *repository.BootstrapRepo, log *slog.Logger) (*Service, error) {
	log = logging.Normalize(log)
	s := &Service{txRunner: txRunner, users: users, bootstrap: bootstrap, log: log, now: time.Now}

	if bootstrap == nil {
		return s, nil
	}
	initialized, err := s.bootstrap.IsInitialized(context.Background())
	if err != nil {
		// 状态读取失败时不得输出明文 token，仅记录错误，仍可继续提供
		// status/bootstrap/admin 接口以暴露可用性。
		log.WarnContext(context.Background(), "bootstrap state read failed", logging.Error(err))
		return s, nil
	}
	if initialized {
		return s, nil
	}

	token, err := newSetupToken(setupTokenTTL)
	if err != nil {
		return nil, err
	}
	s.token = token
	if raw := s.SetupToken(); raw != "" {
		s.log.Info("bootstrap setup token generated",
			logging.SetupToken(raw),
			"expires_at", token.expiresAt.UTC().Format(time.RFC3339))
	}
	return s, nil
}

// SetupToken 返回当前可用的明文令牌。
func (s *Service) SetupToken() string {
	raw, ok := s.token.plaintext(s.now())
	if !ok {
		return ""
	}
	return raw
}

// Status 返回实例是否仍需要首次运行引导。
func (s *Service) Status(ctx context.Context) (bool, error) {
	initialized, err := s.bootstrap.IsInitialized(ctx)
	if err != nil {
		return false, err
	}
	return !initialized, nil
}

// CreateAdmin 校验 setup token，并在一个事务内原子地创建第一个管理员以及 bootstrap 单例。
func (s *Service) CreateAdmin(ctx context.Context, input AdminInput) error {
	if err := validateInput(input); err != nil {
		return err
	}
	original, normalized, err := value.NormalizeEmail(input.Email)
	if err != nil {
		return domain.ErrValidation
	}
	if !s.token.verify(input.SetupToken, s.now()) {
		return domain.ErrTokenInvalid
	}

	err = s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		initialized, err := s.bootstrap.IsInitialized(ctx)
		if err != nil {
			return err
		}
		if initialized {
			return domain.ErrAlreadyInitialized
		}
		existing, err := s.users.FindUserByEmailNormalized(ctx, normalized)
		if err == nil && existing != nil {
			return domain.ErrEmailExists
		}
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		now := s.now().UTC()
		admin := &domain.User{
			Email:           original,
			EmailNormalized: normalized,
			Nickname:        strings.TrimSpace(input.Nickname),
			Role:            domain.RoleAdmin,
			Status:          domain.UserStatusActive,
			EmailVerifiedAt: &now,
		}
		if err := s.users.CreateUserWithPassword(ctx, admin, input.Password); err != nil {
			return err
		}
		return s.bootstrap.Create(ctx, now, admin.ID)
	})
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return domain.ErrAlreadyInitialized
		}
		return err
	}
	return nil
}

func validateInput(input AdminInput) error {
	if strings.TrimSpace(input.SetupToken) == "" {
		return domain.ErrTokenInvalid
	}
	if strings.TrimSpace(input.Email) == "" {
		return domain.ErrValidation
	}
	if len(strings.TrimSpace(input.Nickname)) < minNicknameLength {
		return domain.ErrValidation
	}
	if len(input.Password) < minPasswordLength {
		return domain.ErrValidation
	}
	return nil
}

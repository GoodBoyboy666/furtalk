package bootstrap

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/logging"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"

	"gorm.io/gorm"
)

// bootstrapTestPolicy 返回公开注册开启与认证评论模式的实例策略。
type bootstrapTestPolicy struct{}

func (bootstrapTestPolicy) Policy(context.Context) (bool, string, error) {
	return true, domain.CommentModeAuthenticated, nil
}

func (bootstrapTestPolicy) EmailPolicy(context.Context) ([]string, []string, string, error) {
	return nil, nil, "https://www.gravatar.com/avatar", nil
}

// bootstrapTestSigner 签发固定 token 的第一方 signer 替身。
type bootstrapTestSigner struct {
	lifetime time.Duration
}

func (s bootstrapTestSigner) SignFirstParty(int64, int64) (string, error) {
	return "session-token", nil
}
func (s bootstrapTestSigner) Lifetime() time.Duration { return s.lifetime }

// bootstrapTestCaptchaPolicy 返回固定的空 CAPTCHA action 策略。
type bootstrapTestCaptchaPolicy struct {
	policy map[string]bool
}

func (p bootstrapTestCaptchaPolicy) CaptchaPolicy(context.Context) (map[string]bool, error) {
	return p.policy, nil
}

// bootstrapTestVerifier 是恒通过的 CAPTCHA 验证器替身。
type bootstrapTestVerifier struct{}

func (bootstrapTestVerifier) Verify(context.Context, string, string) error { return nil }

// newBootstrapAdminTestDB 打开临时 SQLite 数据库并迁移用户与 bootstrap 单例表。
func newBootstrapAdminTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "bootstrap-admin-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.SetWAL(db); err != nil {
		t.Fatalf("set WAL: %v", err)
	}
	if err := database.AutoMigrate(db, &model.User{}, &model.BootstrapState{}, &model.NotificationPreferences{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// newBootstrapIdentity 装配使用同一数据库与内存缓存的 identity 服务。
func newBootstrapIdentity(t *testing.T, db *gorm.DB) *identity.Service {
	t.Helper()
	return identity.NewService(identity.Dependencies{
		TxRunner:       gormtx.NewRunner(db),
		Users:          repository.NewUserRepo(db),
		Prefs:          repository.NewPreferenceRepo(db),
		Cache:          cache.NewMemory(10000),
		Policy:         bootstrapTestPolicy{},
		CaptchaPolicy:  bootstrapTestCaptchaPolicy{map[string]bool{}},
		Captcha:        bootstrapTestVerifier{},
		Signer:         bootstrapTestSigner{lifetime: 7 * 24 * time.Hour},
		PasskeyAdapter: nil,
	})
}

// newBootstrapAdminService 构建使用真实仓储的 bootstrap 服务。
func newBootstrapAdminService(t *testing.T, db *gorm.DB, users FirstAdminWriter) *Service {
	t.Helper()
	svc, err := NewService(gormtx.NewRunner(db), users, repository.NewBootstrapRepo(db), logging.New(io.Discard))
	if err != nil {
		t.Fatalf("new bootstrap service: %v", err)
	}
	return svc
}

// freshToken 构造一个未消费的 setup token 并注入服务，模拟新实例启动。
func freshToken(t *testing.T, svc *Service, ttl time.Duration) string {
	t.Helper()
	token, err := newSetupToken(ttl)
	if err != nil {
		t.Fatalf("new setup token: %v", err)
	}
	svc.token = token
	return token.raw
}

// TestCreateAdminSuccessAllowsImmediateLogin 验证成功的引导创建活动管理员后
// 可立即通过 identity.LoginWithPassword 登录，且实例进入已初始化状态。
func TestCreateAdminSuccessAllowsImmediateLogin(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()
	identitySvc := newBootstrapIdentity(t, db)
	svc := newBootstrapAdminService(t, db, identitySvc)

	token := svc.SetupToken()
	input := AdminInput{SetupToken: token, Email: "admin@example.com", Nickname: "Admin", Password: "correct-horse-1"}
	if err := svc.CreateAdmin(ctx, input); err != nil {
		t.Fatalf("create admin: %v", err)
	}

	required, err := svc.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if required {
		t.Fatal("instance must be initialized after a successful bootstrap")
	}

	session, err := identitySvc.LoginWithPassword(ctx, "admin@example.com", "correct-horse-1", "")
	if err != nil {
		t.Fatalf("immediate password login failed: %v", err)
	}
	if session == nil || session.Token == "" {
		t.Fatal("immediate password login returned an empty session")
	}

	// 管理员资料必须标记已配置密码且邮箱已验证。
	profile, err := identitySvc.Get(ctx, 1)
	if err != nil {
		t.Fatalf("get admin profile: %v", err)
	}
	if !profile.HasPassword || !profile.EmailVerified || profile.Role != domain.RoleAdmin {
		t.Fatalf("admin profile = %+v, want password + verified + admin", profile)
	}
}

// TestCreateAdminInvalidToken 验证错误的 setup token 返回 ErrTokenInvalid。
func TestCreateAdminInvalidToken(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()
	svc := newBootstrapAdminService(t, db, newBootstrapIdentity(t, db))

	input := AdminInput{SetupToken: "wrong-token", Email: "admin@example.com", Nickname: "Admin", Password: "correct-horse-1"}
	if err := svc.CreateAdmin(ctx, input); !errors.Is(err, domain.ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

// TestCreateAdminExpiredToken 验证过期的 setup token 返回 ErrTokenInvalid。
func TestCreateAdminExpiredToken(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()
	svc := newBootstrapAdminService(t, db, newBootstrapIdentity(t, db))

	token := freshToken(t, svc, -time.Minute)
	input := AdminInput{SetupToken: token, Email: "admin@example.com", Nickname: "Admin", Password: "correct-horse-1"}
	if err := svc.CreateAdmin(ctx, input); !errors.Is(err, domain.ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

// TestCreateAdminTokenConsumed 验证成功的引导会一次性消费 token，后续调用不可复用。
func TestCreateAdminTokenConsumed(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()
	svc := newBootstrapAdminService(t, db, newBootstrapIdentity(t, db))

	token := svc.SetupToken()
	input := AdminInput{SetupToken: token, Email: "admin@example.com", Nickname: "Admin", Password: "correct-horse-1"}
	if err := svc.CreateAdmin(ctx, input); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if raw := svc.SetupToken(); raw != "" {
		t.Fatal("consumed token must not be exposed as plaintext")
	}
	second := AdminInput{SetupToken: token, Email: "other@example.com", Nickname: "Other", Password: "correct-horse-2"}
	if err := svc.CreateAdmin(ctx, second); !errors.Is(err, domain.ErrTokenInvalid) {
		t.Fatalf("second create err = %v, want ErrTokenInvalid", err)
	}
}

// TestCreateAdminAlreadyInitialized 验证已初始化实例无法再创建管理员。
func TestCreateAdminAlreadyInitialized(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()
	svc := newBootstrapAdminService(t, db, newBootstrapIdentity(t, db))

	input := AdminInput{SetupToken: svc.SetupToken(), Email: "admin@example.com", Nickname: "Admin", Password: "correct-horse-1"}
	if err := svc.CreateAdmin(ctx, input); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	_ = freshToken(t, svc, time.Hour)
	second := AdminInput{SetupToken: svc.SetupToken(), Email: "other@example.com", Nickname: "Other", Password: "correct-horse-2"}
	if err := svc.CreateAdmin(ctx, second); !errors.Is(err, domain.ErrAlreadyInitialized) {
		t.Fatalf("second create err = %v, want ErrAlreadyInitialized", err)
	}
}

// TestCreateAdminDuplicateEmail 验证已存在邮箱在初始化前即被拒绝。
func TestCreateAdminDuplicateEmail(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()
	identitySvc := newBootstrapIdentity(t, db)
	svc := newBootstrapAdminService(t, db, identitySvc)

	existing := &domain.User{
		Email:           "admin@example.com",
		EmailNormalized: "admin@example.com",
		Nickname:        "existing",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
	}
	if err := repository.NewUserRepo(db).Create(ctx, existing); err != nil {
		t.Fatalf("seed existing user: %v", err)
	}
	input := AdminInput{SetupToken: svc.SetupToken(), Email: "admin@example.com", Nickname: "Admin", Password: "correct-horse-1"}
	if err := svc.CreateAdmin(ctx, input); !errors.Is(err, domain.ErrEmailExists) {
		t.Fatalf("err = %v, want ErrEmailExists", err)
	}
}

// failingFirstAdminWriter 成功写入用户后注入错误，使外层事务回滚。
type failingFirstAdminWriter struct {
	users *repository.UserRepo
}

func (w failingFirstAdminWriter) CreateUserWithPassword(ctx context.Context, user *domain.User, password string) error {
	if err := w.users.CreateWithPassword(ctx, user, "$argon2id$fake", time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)); err != nil {
		return err
	}
	return errors.New("injected failure after user insert")
}

func (w failingFirstAdminWriter) FindUserByEmailNormalized(ctx context.Context, normalized string) (*domain.User, error) {
	return w.users.FindByEmailNormalized(ctx, normalized)
}

// TestCreateAdminForcedRollback 验证用户写入后注入失败时，
// 用户、密码状态与 bootstrap 单例一起回滚，不留部分状态。
func TestCreateAdminForcedRollback(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()
	users := repository.NewUserRepo(db)
	svc := newBootstrapAdminService(t, db, failingFirstAdminWriter{users: users})

	input := AdminInput{SetupToken: svc.SetupToken(), Email: "admin@example.com", Nickname: "Admin", Password: "correct-horse-1"}
	if err := svc.CreateAdmin(ctx, input); err == nil {
		t.Fatal("create admin must fail on injected error")
	}

	if _, err := users.FindByEmailNormalized(ctx, "admin@example.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("user must be rolled back, err = %v", err)
	}
	initialized, err := repository.NewBootstrapRepo(db).IsInitialized(ctx)
	if err != nil {
		t.Fatalf("check bootstrap state: %v", err)
	}
	if initialized {
		t.Fatal("bootstrap singleton must be rolled back")
	}
}

// TestCreateAdminConcurrentInitialization 验证并发初始化时唯一约束保证
// 恰好一个成功，且不会留下部分状态。
func TestCreateAdminConcurrentInitialization(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		svc := newBootstrapAdminService(t, db, newBootstrapIdentity(t, db))
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			input := AdminInput{
				SetupToken: svc.SetupToken(),
				Email:      "admin" + string(rune('a'+idx)) + "@example.com",
				Nickname:   "Admin",
				Password:   "correct-horse-1",
			}
			results <- svc.CreateAdmin(ctx, input)
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	success := 0
	for err := range results {
		if err == nil {
			success++
			continue
		}
		if errors.Is(err, domain.ErrAlreadyInitialized) {
			continue
		}
		// SQLite 在 read-then-write 竞争下可能以瞬时的 database is locked 失败；
		// 关键不变量是事务整体回滚，不产生部分状态。
		if !strings.Contains(strings.ToLower(err.Error()), "database is locked") {
			t.Fatalf("loser error = %v, want ErrAlreadyInitialized or a transient lock error", err)
		}
	}
	if success != 1 {
		t.Fatalf("success count = %d, want exactly 1", success)
	}
	var count int64
	if err := db.Model(&model.BootstrapState{}).Count(&count).Error; err != nil {
		t.Fatalf("count bootstrap state: %v", err)
	}
	if count != 1 {
		t.Fatalf("bootstrap singleton count = %d, want 1", count)
	}
}

// TestBootstrapSingletonRejectsSecondCreate 直接验证 bootstrap 单例唯一约束
// 是并发初始化的最终权威：第二行插入被拒绝并映射为 domain.ErrConflict。
func TestBootstrapSingletonRejectsSecondCreate(t *testing.T) {
	db := newBootstrapAdminTestDB(t)
	ctx := context.Background()
	repo := repository.NewBootstrapRepo(db)
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

	if err := repo.Create(ctx, now, 1); err != nil {
		t.Fatalf("first singleton create: %v", err)
	}
	if err := repo.Create(ctx, now, 2); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second singleton create err = %v, want domain.ErrConflict", err)
	}
}

package identity

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
)

// adminTestCache 记录缓存删除键，供 authz 失效断言使用。
type adminTestCache struct {
	mu      sync.Mutex
	deleted []string
	err     error
}

func (c *adminTestCache) Get(ctx context.Context, key string, out any) error {
	return cache.ErrNotFound
}

func (c *adminTestCache) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return nil
}

func (c *adminTestCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.deleted = append(c.deleted, key)
	return nil
}

func (c *adminTestCache) AtomicConsume(ctx context.Context, key string) (string, error) {
	return "", cache.ErrNotFound
}

func (c *adminTestCache) GetOrLoad(ctx context.Context, key string, out any, ttl time.Duration, load func() (any, error)) error {
	return nil
}

// adminTestStore 是管理员用户用例的缓存替身集合。
type adminTestStore struct {
	cache adminTestCache
}

// newAdminTestService 装配管理员用户管理所需的最小服务：真实 SQLite 用户/偏好仓储。
func newAdminTestService(t *testing.T) (*Service, *adminTestStore) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "identity-admin-test.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.User{}, &model.NotificationPreferences{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	store := &adminTestStore{}
	svc := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
		Prefs:    repository.NewPreferenceRepo(db),
		Cache:    &store.cache,
		Policy:   loginTestPolicy{},
		Signer:   loginTestSigner{lifetime: 7 * 24 * time.Hour},
	})
	return svc, store
}

// mustCreateUser 通过 AdminCreateUser 创建用户并返回 Profile。
func mustCreateUser(t *testing.T, svc *Service, input AdminCreateUserInput) *Profile {
	t.Helper()
	profile, err := svc.AdminCreateUser(context.Background(), input)
	if err != nil {
		t.Fatalf("AdminCreateUser(%+v): %v", input, err)
	}
	return profile
}

// TestAdminCreateUserWithPasswordAndVerified 验证创建原子写入资料、密码哈希与验证时间。
func TestAdminCreateUserWithPasswordAndVerified(t *testing.T) {
	svc, _ := newAdminTestService(t)
	website := "https://example.com"
	password := "supersecret"
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email:         "  Admin@Example.com  ",
		Nickname:      "  Admin  ",
		WebsiteURL:    &website,
		Role:          domain.RoleAdmin,
		Password:      &password,
		EmailVerified: true,
	})

	if profile.ID <= 0 {
		t.Fatal("created profile must have an ID")
	}
	if profile.Email != "Admin@Example.com" {
		t.Fatalf("email = %q, want preserved original case", profile.Email)
	}
	if profile.Nickname != "Admin" {
		t.Fatalf("nickname = %q, want trimmed value", profile.Nickname)
	}
	if profile.WebsiteURL == nil || *profile.WebsiteURL != website {
		t.Fatalf("website = %v, want %q", profile.WebsiteURL, website)
	}
	if profile.Role != domain.RoleAdmin || profile.Status != domain.UserStatusActive {
		t.Fatalf("role/status = %q/%q, want admin/active", profile.Role, profile.Status)
	}
	if !profile.EmailVerified {
		t.Fatal("email_verified must be true when the flag is on")
	}
	if !profile.HasPassword {
		t.Fatal("user created with password must report has_password = true")
	}
	hash, err := svc.users.PasswordHash(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !verifyPassword(hash, password) {
		t.Fatal("stored password hash must verify the plaintext")
	}
}

// TestAdminCreateUserDefaults 验证默认行为：验证关闭、无密码、网站为空。
func TestAdminCreateUserDefaults(t *testing.T) {
	svc, _ := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email:    "user@example.com",
		Nickname: "user",
		Role:     domain.RoleUser,
	})
	if profile.EmailVerified {
		t.Fatal("email_verified must default to false")
	}
	if profile.HasPassword {
		t.Fatal("has_password must default to false")
	}
	if profile.WebsiteURL != nil {
		t.Fatalf("website = %v, want nil", profile.WebsiteURL)
	}
}

// TestAdminCreateUserPasswordDoesNotVerifyEmail 验证设置密码不会自动验证邮箱。
func TestAdminCreateUserPasswordDoesNotVerifyEmail(t *testing.T) {
	svc, _ := newAdminTestService(t)
	password := "supersecret"
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email:    "pw@example.com",
		Nickname: "pw",
		Role:     domain.RoleUser,
		Password: &password,
	})
	if profile.HasPassword != true {
		t.Fatal("user with password must report has_password = true")
	}
	if profile.EmailVerified {
		t.Fatal("setting a password must not auto-verify the email")
	}
}

// TestAdminCreateUserValidationErrors 验证非法输入返回 ErrValidation 且零残留。
func TestAdminCreateUserValidationErrors(t *testing.T) {
	svc, _ := newAdminTestService(t)
	cases := []AdminCreateUserInput{
		{Email: "bad", Nickname: "n", Role: domain.RoleUser},
		{Email: "a@example.com", Nickname: "", Role: domain.RoleUser},
		{Email: "a@example.com", Nickname: "n", Role: domain.Role("moderator")},
		{Email: "a@example.com", Nickname: "n", Role: domain.RoleUser, Password: stringPtr("short")},
		{Email: "a@example.com", Nickname: "n", Role: domain.RoleUser, WebsiteURL: stringPtr("ftp://example.com")},
	}
	for i, input := range cases {
		if _, err := svc.AdminCreateUser(context.Background(), input); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("case %d err = %v, want ErrValidation", i, err)
		}
	}
	// 全部失败后没有任何用户行残留。
	rows, err := svc.users.List(context.Background(), "", domain.CommentSortDesc, 50, 0)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("validation failures left %d user rows, want 0", len(rows))
	}
}

// TestAdminCreateUserConflict 验证重复邮箱映射为 ErrConflict。
func TestAdminCreateUserConflict(t *testing.T) {
	svc, _ := newAdminTestService(t)
	mustCreateUser(t, svc, AdminCreateUserInput{Email: "dup@example.com", Nickname: "a", Role: domain.RoleUser})
	if _, err := svc.AdminCreateUser(context.Background(), AdminCreateUserInput{
		Email: "DUP@example.com", Nickname: "b", Role: domain.RoleUser,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate email err = %v, want ErrConflict", err)
	}
}

// TestAdminUpdateUserEmailPreservesVerification 验证邮箱变化默认保留验证状态。
func TestAdminUpdateUserEmailPreservesVerification(t *testing.T) {
	svc, _ := newAdminTestService(t)
	verified := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "old@example.com", Nickname: "v", Role: domain.RoleUser, EmailVerified: true,
	})
	unverified := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "old2@example.com", Nickname: "u", Role: domain.RoleUser,
	})

	email := "new@example.com"
	updated, err := svc.AdminUpdateUser(context.Background(), verified.ID, AdminUpdateUserInput{Email: &email})
	if err != nil {
		t.Fatalf("update verified user email: %v", err)
	}
	if !updated.EmailVerified {
		t.Fatal("email change must preserve an existing verified state")
	}
	if updated.Email != "new@example.com" {
		t.Fatalf("email = %q, want new@example.com", updated.Email)
	}

	email2 := "new2@example.com"
	updated2, err := svc.AdminUpdateUser(context.Background(), unverified.ID, AdminUpdateUserInput{Email: &email2})
	if err != nil {
		t.Fatalf("update unverified user email: %v", err)
	}
	if updated2.EmailVerified {
		t.Fatal("email change must not auto-verify an unverified user")
	}
}

// TestAdminUpdateUserEmailVerifiedFlag 验证显式 true/false 设置或清除验证时间。
func TestAdminUpdateUserEmailVerifiedFlag(t *testing.T) {
	svc, _ := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "flag@example.com", Nickname: "flag", Role: domain.RoleUser,
	})

	on := true
	updated, err := svc.AdminUpdateUser(context.Background(), profile.ID, AdminUpdateUserInput{EmailVerified: &on})
	if err != nil {
		t.Fatalf("enable verification: %v", err)
	}
	if !updated.EmailVerified {
		t.Fatal("explicit true must verify the email")
	}

	off := false
	updated, err = svc.AdminUpdateUser(context.Background(), profile.ID, AdminUpdateUserInput{EmailVerified: &off})
	if err != nil {
		t.Fatalf("disable verification: %v", err)
	}
	if updated.EmailVerified {
		t.Fatal("explicit false must clear the verification state")
	}
}

// TestAdminUpdateUserWebsiteNullVsOmitted 验证省略保留、显式 null 清除网站。
func TestAdminUpdateUserWebsiteNullVsOmitted(t *testing.T) {
	svc, _ := newAdminTestService(t)
	website := "https://example.com"
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "site@example.com", Nickname: "site", Role: domain.RoleUser, WebsiteURL: &website,
	})

	// 省略不改变网站。
	nickname := "site-2"
	updated, err := svc.AdminUpdateUser(context.Background(), profile.ID, AdminUpdateUserInput{Nickname: &nickname})
	if err != nil {
		t.Fatalf("update nickname only: %v", err)
	}
	if updated.WebsiteURL == nil || *updated.WebsiteURL != website {
		t.Fatalf("omitted website_url must be preserved, got %v", updated.WebsiteURL)
	}

	// 显式 null 清除网站。
	updated, err = svc.AdminUpdateUser(context.Background(), profile.ID, AdminUpdateUserInput{
		WebsiteURL: OptionalNullableString{Set: true, Value: nil},
	})
	if err != nil {
		t.Fatalf("clear website: %v", err)
	}
	if updated.WebsiteURL != nil {
		t.Fatalf("explicit null website_url = %v, want nil", updated.WebsiteURL)
	}
}

// TestAdminUpdateUserRoleStatusInvalidatesAuthzCache 验证角色/状态变化提交后失效缓存。
func TestAdminUpdateUserRoleStatusInvalidatesAuthzCache(t *testing.T) {
	svc, store := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "rs@example.com", Nickname: "rs", Role: domain.RoleUser,
	})

	role := domain.RoleAdmin
	if _, err := svc.AdminUpdateUser(context.Background(), profile.ID, AdminUpdateUserInput{Role: &role}); err != nil {
		t.Fatalf("promote to admin: %v", err)
	}
	if len(store.cache.deleted) != 1 || store.cache.deleted[0] != authzKey(profile.ID) {
		t.Fatalf("cache deletes = %v, want [%s]", store.cache.deleted, authzKey(profile.ID))
	}

	// 资料-only 更新不触发失效。
	nickname := "rs-2"
	if _, err := svc.AdminUpdateUser(context.Background(), profile.ID, AdminUpdateUserInput{Nickname: &nickname}); err != nil {
		t.Fatalf("update nickname: %v", err)
	}
	if len(store.cache.deleted) != 1 {
		t.Fatalf("profile-only update must not invalidate authz cache, deletes = %v", store.cache.deleted)
	}
}

// TestAdminUpdateUserLastAdminGuard 验证不能降级或禁用最后一名活跃管理员。
func TestAdminUpdateUserLastAdminGuard(t *testing.T) {
	svc, store := newAdminTestService(t)
	admin := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "admin@example.com", Nickname: "admin", Role: domain.RoleAdmin,
	})

	role := domain.RoleUser
	if _, err := svc.AdminUpdateUser(context.Background(), admin.ID, AdminUpdateUserInput{Role: &role}); !errors.Is(err, domain.ErrLastAdmin) {
		t.Fatalf("demote last admin err = %v, want ErrLastAdmin", err)
	}
	status := domain.UserStatusDisabled
	if _, err := svc.AdminUpdateUser(context.Background(), admin.ID, AdminUpdateUserInput{Status: &status}); !errors.Is(err, domain.ErrLastAdmin) {
		t.Fatalf("disable last admin err = %v, want ErrLastAdmin", err)
	}
	// 守卫失败不得触发缓存失效。
	if len(store.cache.deleted) != 0 {
		t.Fatalf("guard failure must not invalidate cache, deletes = %v", store.cache.deleted)
	}

	// 增加第二名管理员后，第一名可以被降级。
	second := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "admin2@example.com", Nickname: "admin2", Role: domain.RoleAdmin,
	})
	if _, err := svc.AdminUpdateUser(context.Background(), admin.ID, AdminUpdateUserInput{Role: &role}); err != nil {
		t.Fatalf("demote admin with second admin: %v", err)
	}
	if _, err := svc.AdminUpdateUser(context.Background(), second.ID, AdminUpdateUserInput{Role: &role}); !errors.Is(err, domain.ErrLastAdmin) {
		t.Fatalf("demote remaining admin err = %v, want ErrLastAdmin", err)
	}
}

// TestAdminUpdateUserEmailConflict 验证邮箱冲突零部分写入。
func TestAdminUpdateUserEmailConflict(t *testing.T) {
	svc, _ := newAdminTestService(t)
	first := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "first@example.com", Nickname: "first", Role: domain.RoleUser,
	})
	_ = first // first 的邮箱占用用于制造冲突
	second := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "second@example.com", Nickname: "second", Role: domain.RoleUser,
	})

	email := "first@example.com"
	nickname := "second-renamed"
	_, err := svc.AdminUpdateUser(context.Background(), second.ID, AdminUpdateUserInput{
		Email: &email, Nickname: &nickname,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("email conflict err = %v, want ErrConflict", err)
	}
	row, err := svc.users.FindByID(context.Background(), second.ID)
	if err != nil {
		t.Fatalf("find second user: %v", err)
	}
	if row.Nickname != "second" {
		t.Fatalf("partial write: nickname = %q, want unchanged second", row.Nickname)
	}
}

// TestAdminUpdateUserCacheInvalidationFailure 验证失效失败走 fail-fast 契约。
func TestAdminUpdateUserCacheInvalidationFailure(t *testing.T) {
	svc, store := newAdminTestService(t)
	failed := false
	svc.failFast = func(err error) { failed = true }
	store.cache.err = errors.New("cache down")
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "cf@example.com", Nickname: "cf", Role: domain.RoleUser,
	})

	role := domain.RoleAdmin
	if _, err := svc.AdminUpdateUser(context.Background(), profile.ID, AdminUpdateUserInput{Role: &role}); !errors.Is(err, domain.ErrCacheInvalidation) {
		t.Fatalf("err = %v, want ErrCacheInvalidation", err)
	}
	if !failed {
		t.Fatal("failFast must be invoked on cache invalidation failure")
	}
	// 数据库写入已提交。
	row, err := svc.users.FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if row.Role != domain.RoleAdmin {
		t.Fatalf("role = %q, want committed admin", row.Role)
	}
}

// TestAdminResetPassword 验证重置密码替换密码、保留验证状态并递增会话代次，
// 且提交后失效 authz 缓存。
func TestAdminResetPassword(t *testing.T) {
	svc, store := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "reset@example.com", Nickname: "reset", Role: domain.RoleUser, EmailVerified: true,
	})
	before, err := svc.users.FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user before reset: %v", err)
	}

	if err := svc.AdminResetPassword(context.Background(), profile.ID, "newpassword123"); err != nil {
		t.Fatalf("reset password: %v", err)
	}
	hash, err := svc.users.PasswordHash(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !verifyPassword(hash, "newpassword123") {
		t.Fatal("reset password must verify the new plaintext")
	}
	updated, err := svc.Get(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if !updated.EmailVerified {
		t.Fatal("reset password must preserve verification state")
	}
	if updated.Nickname != "reset" {
		t.Fatal("reset password must not change profile fields")
	}
	after, err := svc.users.FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user after reset: %v", err)
	}
	if after.SessionVersion != before.SessionVersion+1 {
		t.Fatalf("session version after reset = %d, want %d", after.SessionVersion, before.SessionVersion+1)
	}
	if len(store.cache.deleted) != 1 || store.cache.deleted[0] != authzKey(profile.ID) {
		t.Fatalf("cache deletes after reset = %v, want [%s]", store.cache.deleted, authzKey(profile.ID))
	}
}

// TestAdminResetPasswordValidation 验证过短密码与不存在用户返回错误且零写入。
func TestAdminResetPasswordValidation(t *testing.T) {
	svc, _ := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "short@example.com", Nickname: "short", Role: domain.RoleUser,
	})
	if err := svc.AdminResetPassword(context.Background(), profile.ID, "short"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short password err = %v, want ErrValidation", err)
	}
	if err := svc.AdminResetPassword(context.Background(), 9999, "validpassword123"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing user err = %v, want ErrNotFound", err)
	}
	has, err := svc.users.HasPassword(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("has password: %v", err)
	}
	if has {
		t.Fatal("failed reset must not write a password")
	}
}

// TestAdminDeleteUserSelfRejected 验证管理员不能删除自己，返回 ErrForbidden 且零写入。
func TestAdminDeleteUserSelfRejected(t *testing.T) {
	svc, store := newAdminTestService(t)
	admin := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "self@example.com", Nickname: "self", Role: domain.RoleAdmin,
	})
	if err := svc.AdminDeleteUser(context.Background(), admin.ID, admin.ID, domain.UserDeleteModeSoft, false); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self delete err = %v, want ErrForbidden", err)
	}
	if err := svc.AdminDeleteUser(context.Background(), admin.ID, admin.ID, domain.UserDeleteModeHard, true); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self hard delete err = %v, want ErrForbidden", err)
	}
	if len(store.cache.deleted) != 0 {
		t.Fatalf("self delete must not invalidate cache, deletes = %v", store.cache.deleted)
	}
	if _, err := svc.users.FindByID(context.Background(), admin.ID); err != nil {
		t.Fatalf("admin must still exist: %v", err)
	}
}

// TestAdminDeleteUserLastAdminGuard 验证删除最后一名活跃管理员返回 ErrLastAdmin。
func TestAdminDeleteUserLastAdminGuard(t *testing.T) {
	svc, _ := newAdminTestService(t)
	admin := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "only@example.com", Nickname: "only", Role: domain.RoleAdmin,
	})
	if err := svc.AdminDeleteUser(context.Background(), admin.ID+1, admin.ID, domain.UserDeleteModeSoft, false); !errors.Is(err, domain.ErrLastAdmin) {
		t.Fatalf("soft delete last admin err = %v, want ErrLastAdmin", err)
	}
	if err := svc.AdminDeleteUser(context.Background(), admin.ID+1, admin.ID, domain.UserDeleteModeHard, true); !errors.Is(err, domain.ErrLastAdmin) {
		t.Fatalf("hard delete last admin err = %v, want ErrLastAdmin", err)
	}
	// 增加第二名管理员后可删除第一名。
	second := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "second@example.com", Nickname: "second", Role: domain.RoleAdmin,
	})
	if err := svc.AdminDeleteUser(context.Background(), second.ID, admin.ID, domain.UserDeleteModeSoft, false); err != nil {
		t.Fatalf("soft delete admin with second admin: %v", err)
	}
}

// TestAdminDeleteUserHardRequiresConfirm 验证硬删除缺少确认返回 ErrConfirmationRequired。
func TestAdminDeleteUserHardRequiresConfirm(t *testing.T) {
	svc, _ := newAdminTestService(t)
	admin := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "a@example.com", Nickname: "a", Role: domain.RoleAdmin,
	})
	_ = mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "b@example.com", Nickname: "b", Role: domain.RoleAdmin,
	})
	if err := svc.AdminDeleteUser(context.Background(), admin.ID, admin.ID, domain.UserDeleteModeHard, false); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self hard delete err = %v, want ErrForbidden", err)
	}
}

// TestAdminSoftDeleteUserRestoreAccountOnly 验证软删除把用户置为 deleted 并记录生命周期，
// 恢复只恢复账号状态，不触碰评论。
func TestAdminSoftDeleteUserRestoreAccountOnly(t *testing.T) {
	svc, store := newAdminTestService(t)
	admin := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "adm@example.com", Nickname: "adm", Role: domain.RoleAdmin,
	})
	_ = mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "adm2@example.com", Nickname: "adm2", Role: domain.RoleAdmin,
	})
	target := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "target@example.com", Nickname: "target", Role: domain.RoleUser,
	})

	if err := svc.AdminDeleteUser(context.Background(), admin.ID, target.ID, domain.UserDeleteModeSoft, false); err != nil {
		t.Fatalf("soft delete user: %v", err)
	}
	row, err := svc.users.FindByID(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("find soft-deleted user: %v", err)
	}
	if row.Status != domain.UserStatusDeleted || row.DeletedAt == nil || row.StatusBeforeDelete == nil || *row.StatusBeforeDelete != domain.UserStatusActive {
		t.Fatalf("soft-deleted user = %+v", row)
	}
	if len(store.cache.deleted) != 1 || store.cache.deleted[0] != authzKey(target.ID) {
		t.Fatalf("cache deletes = %v, want [%s]", store.cache.deleted, authzKey(target.ID))
	}

	// 恢复账号：回到 active，清除删除标记。
	restored, err := svc.AdminRestoreUser(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("restore user: %v", err)
	}
	if restored.Status != domain.UserStatusActive || restored.DeletedAt != nil {
		t.Fatalf("restored user = %+v", restored)
	}
	if len(store.cache.deleted) != 2 {
		t.Fatalf("restore must invalidate cache, deletes = %v", store.cache.deleted)
	}

	// 重复恢复返回冲突。
	if _, err := svc.AdminRestoreUser(context.Background(), target.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("re-restore err = %v, want ErrConflict", err)
	}
}

// TestAdminHardDeleteUserRemovesRow 验证硬删除物理移除用户行并失效 authz 缓存。
func TestAdminHardDeleteUserRemovesRow(t *testing.T) {
	svc, store := newAdminTestService(t)
	admin := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "h1@example.com", Nickname: "h1", Role: domain.RoleAdmin,
	})
	_ = mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "h2@example.com", Nickname: "h2", Role: domain.RoleAdmin,
	})
	target := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "victim@example.com", Nickname: "victim", Role: domain.RoleUser,
	})

	if err := svc.AdminDeleteUser(context.Background(), admin.ID, target.ID, domain.UserDeleteModeHard, true); err != nil {
		t.Fatalf("hard delete user: %v", err)
	}
	if _, err := svc.users.FindByID(context.Background(), target.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("hard-deleted user still exists: %v", err)
	}
	if len(store.cache.deleted) != 1 || store.cache.deleted[0] != authzKey(target.ID) {
		t.Fatalf("cache deletes = %v, want [%s]", store.cache.deleted, authzKey(target.ID))
	}
}

// TestAdminDeleteUserInvalidMode 验证非法 mode 返回 ErrValidation 且零写入。
func TestAdminDeleteUserInvalidMode(t *testing.T) {
	svc, _ := newAdminTestService(t)
	admin := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "m1@example.com", Nickname: "m1", Role: domain.RoleAdmin,
	})
	_ = mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "m2@example.com", Nickname: "m2", Role: domain.RoleAdmin,
	})
	target := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "m3@example.com", Nickname: "m3", Role: domain.RoleUser,
	})
	if err := svc.AdminDeleteUser(context.Background(), admin.ID, target.ID, "purge", true); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid mode err = %v, want ErrValidation", err)
	}
	row, err := svc.users.FindByID(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("find target: %v", err)
	}
	if row.Status != domain.UserStatusActive {
		t.Fatalf("invalid mode must not change status, got %+v", row)
	}
}

// TestAdminListWithTotal 验证列表携带与搜索条件匹配的真实总数。
func TestAdminListWithTotal(t *testing.T) {
	svc, _ := newAdminTestService(t)
	for i := 0; i < 3; i++ {
		mustCreateUser(t, svc, AdminCreateUserInput{
			Email:    "user" + string(rune('a'+i)) + "@example.com",
			Nickname: "user" + string(rune('a'+i)),
			Role:     domain.RoleUser,
		})
	}
	result, err := svc.ListWithTotal(context.Background(), "", domain.CommentSortDesc, 1, 2)
	if err != nil {
		t.Fatalf("list with total: %v", err)
	}
	if len(result.Users) != 2 {
		t.Fatalf("page users = %d, want 2", len(result.Users))
	}
	if result.Total != 3 {
		t.Fatalf("total = %d, want 3 (independent of limit)", result.Total)
	}

	pageTwo, err := svc.ListWithTotal(context.Background(), "", domain.CommentSortDesc, 2, 2)
	if err != nil {
		t.Fatalf("list page two: %v", err)
	}
	if len(pageTwo.Users) != 1 || pageTwo.Total != 3 {
		t.Fatalf("page two = %d users total %d, want 1/3", len(pageTwo.Users), pageTwo.Total)
	}

	matched, err := svc.ListWithTotal(context.Background(), "userb", domain.CommentSortDesc, 1, 50)
	if err != nil {
		t.Fatalf("search list: %v", err)
	}
	if len(matched.Users) != 1 || matched.Total != 1 {
		t.Fatalf("search result = %d users total %d, want 1/1", len(matched.Users), matched.Total)
	}
}

func stringPtr(s string) *string { return &s }

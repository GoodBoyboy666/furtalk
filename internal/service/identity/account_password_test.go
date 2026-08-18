package identity

import (
	"context"
	"errors"
	"testing"

	"furtalk/internal/domain"
)

// TestChangePasswordFirstTimeIgnoresCurrent 验证无密码用户首设密码不要求当前密码，
// 提交的 current_password 被忽略，并重签新版本会话。
func TestChangePasswordFirstTimeIgnoresCurrent(t *testing.T) {
	svc, _ := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "first@example.com", Nickname: "first", Role: domain.RoleUser,
	})

	current := "should-be-ignored"
	session, err := svc.ChangePassword(context.Background(), profile.ID, &current, "newpassword123")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if session == nil || session.Token == "" || session.CSRFToken == "" || len(session.CSRFToken) != 43 {
		t.Fatalf("ChangePassword must re-issue a session with token and CSRF, got %+v", session)
	}
	hash, err := svc.users.PasswordHash(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !verifyPassword(hash, "newpassword123") {
		t.Fatal("stored hash must verify the new password")
	}
}

// TestChangePasswordFirstTimeNilCurrent 验证无密码用户不提供 current_password 也可以设密。
func TestChangePasswordFirstTimeNilCurrent(t *testing.T) {
	svc, _ := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "nil@example.com", Nickname: "nil", Role: domain.RoleUser,
	})

	if _, err := svc.ChangePassword(context.Background(), profile.ID, nil, "newpassword123"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	has, err := svc.users.HasPassword(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("has password: %v", err)
	}
	if !has {
		t.Fatal("first password must be set")
	}
}

// TestChangePasswordMissingCurrent 验证已有密码用户缺少当前密码返回通用凭据错误且零写入。
func TestChangePasswordMissingCurrent(t *testing.T) {
	svc, _ := newAdminTestService(t)
	password := "oldpassword123"
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "missing@example.com", Nickname: "missing", Role: domain.RoleUser, Password: &password,
	})

	_, err := svc.ChangePassword(context.Background(), profile.ID, nil, "newpassword123")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	hash, err := svc.users.PasswordHash(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !verifyPassword(hash, "oldpassword123") {
		t.Fatal("failed change must keep the original hash")
	}
	if verifyPassword(hash, "newpassword123") {
		t.Fatal("failed change must not write the new password")
	}
}

// TestChangePasswordWrongCurrentZeroWrite 验证错误当前密码返回通用凭据错误且零写入。
func TestChangePasswordWrongCurrentZeroWrite(t *testing.T) {
	svc, _ := newAdminTestService(t)
	password := "oldpassword123"
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "wrong@example.com", Nickname: "wrong", Role: domain.RoleUser, Password: &password,
	})

	current := "wrong-current"
	_, err := svc.ChangePassword(context.Background(), profile.ID, &current, "newpassword123")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	hash, err := svc.users.PasswordHash(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !verifyPassword(hash, "oldpassword123") {
		t.Fatal("failed change must keep the original hash")
	}
	if verifyPassword(hash, "newpassword123") {
		t.Fatal("failed change must not write the new password")
	}
}

// TestChangePasswordSuccess 验证正确当前密码后替换为新密码并重签新版本会话。
func TestChangePasswordSuccess(t *testing.T) {
	svc, _ := newAdminTestService(t)
	password := "oldpassword123"
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "success@example.com", Nickname: "success", Role: domain.RoleUser, Password: &password,
	})

	current := "oldpassword123"
	session, err := svc.ChangePassword(context.Background(), profile.ID, &current, "newpassword456")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if session == nil || session.Token == "" || session.CSRFToken == "" || len(session.CSRFToken) != 43 {
		t.Fatalf("ChangePassword must re-issue a session with token and CSRF, got %+v", session)
	}
	hash, err := svc.users.PasswordHash(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("password hash: %v", err)
	}
	if !verifyPassword(hash, "newpassword456") {
		t.Fatal("stored hash must verify the new password")
	}
	if verifyPassword(hash, "oldpassword123") {
		t.Fatal("stored hash must not verify the old password")
	}
}

// TestChangePasswordBumpsSessionVersion 验证改密在密码写入的同一事务内递增会话代次。
func TestChangePasswordBumpsSessionVersion(t *testing.T) {
	svc, _ := newAdminTestService(t)
	password := "oldpassword123"
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "bump@example.com", Nickname: "bump", Role: domain.RoleUser, Password: &password,
	})

	current := "oldpassword123"
	before, err := svc.users.FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user before change: %v", err)
	}
	if _, err := svc.ChangePassword(context.Background(), profile.ID, &current, "newpassword456"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	user, err := svc.users.FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if user.SessionVersion <= before.SessionVersion {
		t.Fatalf("session version = %d after change, want > %d", user.SessionVersion, before.SessionVersion)
	}
}

// TestChangePasswordValidation 验证过短新密码返回 ErrValidation 且零写入。
func TestChangePasswordValidation(t *testing.T) {
	svc, _ := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "short@example.com", Nickname: "short", Role: domain.RoleUser,
	})

	if _, err := svc.ChangePassword(context.Background(), profile.ID, nil, "short"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("short password err = %v, want ErrValidation", err)
	}
	has, err := svc.users.HasPassword(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("has password: %v", err)
	}
	if has {
		t.Fatal("failed validation must not write a password")
	}
}

// TestChangePasswordUnknownUser 验证不存在的用户返回 ErrNotFound。
func TestChangePasswordUnknownUser(t *testing.T) {
	svc, _ := newAdminTestService(t)
	if _, err := svc.ChangePassword(context.Background(), 9999, nil, "newpassword123"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestRevokeAllSessions 验证主动注销全部设备递增会话代次并使全部旧 JWT 失效。
func TestRevokeAllSessions(t *testing.T) {
	svc, _ := newAdminTestService(t)
	profile := mustCreateUser(t, svc, AdminCreateUserInput{
		Email: "revoke@example.com", Nickname: "revoke", Role: domain.RoleUser,
	})

	before, err := svc.users.FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if err := svc.RevokeAllSessions(context.Background(), profile.ID); err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}
	after, err := svc.users.FindByID(context.Background(), profile.ID)
	if err != nil {
		t.Fatalf("find user after revoke: %v", err)
	}
	if after.SessionVersion != before.SessionVersion+1 {
		t.Fatalf("session version after revoke = %d, want %d", after.SessionVersion, before.SessionVersion+1)
	}
}

// TestRevokeAllSessionsUnknownUser 验证不存在用户返回 ErrNotFound。
func TestRevokeAllSessionsUnknownUser(t *testing.T) {
	svc, _ := newAdminTestService(t)
	if err := svc.RevokeAllSessions(context.Background(), 9999); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

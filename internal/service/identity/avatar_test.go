package identity

import (
	"context"
	"testing"

	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/gravatar"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
)

// TestProfileOfDerivesAvatarURL 证明用户资料派生头像 URL，且切换基址后立即变化。
func TestProfileOfDerivesAvatarURL(t *testing.T) {
	db := newCaptchaLoginDB(t)
	if err := database.AutoMigrate(db, &model.NotificationPreferences{}); err != nil {
		t.Fatalf("auto migrate preferences: %v", err)
	}
	ctx := context.Background()
	svc := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
		Prefs:    repository.NewPreferenceRepo(db),
		Policy: configurableEmailPolicy{
			whitelist: []string{"example.com"},
		},
	})
	user := insertVerifiedUser(t, db, "user@example.com")

	profile, err := svc.profileOf(ctx, user)
	if err != nil {
		t.Fatalf("profileOf: %v", err)
	}
	want := gravatar.URL(user.EmailNormalized, "https://www.gravatar.com/avatar")
	if profile.AvatarURL != want {
		t.Fatalf("avatar = %q, want %q", profile.AvatarURL, want)
	}
	if profile.Email == "" {
		t.Fatal("profile email must be present for the current user")
	}

	// 切换基址后同一用户的新资料使用新基址。
	svc2 := NewService(Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    repository.NewUserRepo(db),
		Prefs:    repository.NewPreferenceRepo(db),
		Policy: configurableEmailPolicy{
			whitelist: []string{"example.com"},
			baseURL:   "https://avatars.example.com/avatar/",
		},
	})
	second, err := svc2.profileOf(ctx, user)
	if err != nil {
		t.Fatalf("profileOf second: %v", err)
	}
	wantSwitched := gravatar.URL(user.EmailNormalized, "https://avatars.example.com/avatar/")
	if second.AvatarURL != wantSwitched {
		t.Fatalf("avatar after base switch = %q, want %q", second.AvatarURL, wantSwitched)
	}
}

package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
)

func TestEmailCodeStoreUsesIndependentPurposeQuotas(t *testing.T) {
	backend := cache.NewMemory(cache.DefaultMemoryLimit)
	store, err := NewEmailCodeStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < emailCodeLoginLimit; i++ {
		if err := store.SetEmailCode(context.Background(), emailCodePurpose, fmt.Sprintf("login-%d@example.com", i), "digest", time.Minute); err != nil {
			t.Fatalf("login quota write %d = %v", i, err)
		}
	}
	if err := store.SetEmailCode(context.Background(), emailCodePurpose, "login-over@example.com", "digest", time.Minute); !errors.Is(err, cache.ErrCapacity) {
		t.Fatalf("login over quota = %v, want ErrCapacity", err)
	}
	for i := 0; i < passwordResetLimit; i++ {
		if err := store.SetEmailCode(context.Background(), passwordResetPurpose, fmt.Sprintf("reset-%d@example.com", i), "digest", time.Minute); err != nil {
			t.Fatalf("reset quota write %d = %v", i, err)
		}
	}
	if err := store.SetEmailCode(context.Background(), passwordResetPurpose, "reset-over@example.com", "digest", time.Minute); !errors.Is(err, cache.ErrCapacity) {
		t.Fatalf("reset over quota = %v, want ErrCapacity", err)
	}
}

type capacityEmailCodeStore struct{}

func (capacityEmailCodeStore) SetEmailCode(context.Context, string, string, string, time.Duration) error {
	return cache.ErrCapacity
}

func (capacityEmailCodeStore) DeleteEmailCode(context.Context, string, string) error {
	return nil
}

func (capacityEmailCodeStore) AtomicVerifyEmailCode(context.Context, string, string, string, int) (bool, error) {
	return false, nil
}

func TestSendEmailCodeCapacityMapsUnavailable(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := captchaLoginService(t, db, map[string]bool{}, nil)
	svc.emailCodes = capacityEmailCodeStore{}
	svc.mailer = &capturingMailer{}

	err := svc.SendEmailCode(context.Background(), "new@example.com", "")
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("capacity error = %v, want ErrUnavailable", err)
	}
}

func TestRequestPasswordResetCapacityKeepsGenericSuccess(t *testing.T) {
	store := cache.NewMemory(cache.DefaultMemoryLimit)
	svc := newResetTestService(t, store, map[string]bool{}, nil, &capturingMailer{})
	email := seedResetUser(t, svc, "user@example.com", nil)
	svc.emailCodes = capacityEmailCodeStore{}

	if err := svc.RequestPasswordReset(context.Background(), email, ""); err != nil {
		t.Fatalf("capacity reset request = %v, want generic success", err)
	}
	mailer := svc.mailer.(*capturingMailer)
	if len(mailer.messages) != 0 {
		t.Fatalf("capacity reset mail count = %d, want 0", len(mailer.messages))
	}
}

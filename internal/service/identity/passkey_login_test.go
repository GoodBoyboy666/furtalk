package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/passkey"
	"furtalk/internal/repository"
)

type passkeyLoginServiceAdapter struct {
	beginCalls       int
	finishCalls      int
	finishCredential *passkey.Credential
	finishCounter    uint32
	finishErr        error
}

func (a *passkeyLoginServiceAdapter) BeginRegistration(passkey.User) (json.RawMessage, []byte, error) {
	return nil, nil, nil
}

func (a *passkeyLoginServiceAdapter) FinishRegistration(passkey.User, []byte, []byte) (*passkey.Credential, error) {
	return nil, nil
}

func (a *passkeyLoginServiceAdapter) BeginLogin() (json.RawMessage, []byte, error) {
	a.beginCalls++
	return json.RawMessage(`{"publicKey":{}}`), []byte(`{"challenge":"service-test-challenge"}`), nil
}

func (a *passkeyLoginServiceAdapter) FinishLogin([]byte, []byte, func([]byte, []byte) (*passkey.User, error)) (*passkey.Credential, uint32, error) {
	a.finishCalls++
	if a.finishErr != nil {
		return nil, 0, a.finishErr
	}
	return a.finishCredential, a.finishCounter, nil
}

func TestBeginPasskeyLoginConsumesChallengeOnlyOnce(t *testing.T) {
	adapter := &passkeyLoginServiceAdapter{finishErr: domain.ErrInvalidCredentials}
	svc := NewService(Dependencies{
		Cache:          cache.NewMemory(10),
		PasskeyAdapter: adapter,
	})

	options, err := svc.BeginPasskeyLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginPasskeyLogin() error = %v", err)
	}
	if options.Challenge != "service-test-challenge" {
		t.Fatalf("challenge = %q, want service-test-challenge", options.Challenge)
	}
	if adapter.beginCalls != 1 {
		t.Fatalf("BeginLogin calls = %d, want 1", adapter.beginCalls)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		_, err = svc.VerifyPasskeyLogin(context.Background(), options.Challenge, json.RawMessage(`{}`))
		if !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("attempt %d error = %v, want ErrInvalidCredentials", attempt, err)
		}
	}
	if adapter.finishCalls != 1 {
		t.Fatalf("FinishLogin calls = %d, want 1 after replay", adapter.finishCalls)
	}
}

func TestVerifyPasskeyLoginRejectsCounterRollback(t *testing.T) {
	db := newPasskeyLoginDB(t)
	users := repository.NewUserRepo(db)
	passkeys := repository.NewPasskeyRepo(db)
	user := &domain.User{
		Email: "passkey-counter@example.com", EmailNormalized: "passkey-counter@example.com",
		Nickname: "counter", Role: domain.RoleUser, Status: domain.UserStatusActive,
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	rawID := []byte("counter-credential")
	row := &domain.PasskeyCredential{
		UserID: user.ID, CredentialID: encodeCredentialID(rawID), PublicKey: []byte("pk"), SignCount: 5,
	}
	if err := passkeys.Create(context.Background(), row); err != nil {
		t.Fatalf("create passkey: %v", err)
	}
	adapter := &passkeyLoginServiceAdapter{
		finishCredential: &passkey.Credential{ID: rawID},
		finishCounter:    4,
	}
	svc := NewService(Dependencies{
		Users:          users,
		Passkeys:       passkeys,
		Cache:          cache.NewMemory(10),
		PasskeyAdapter: adapter,
	})

	options, err := svc.BeginPasskeyLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginPasskeyLogin() error = %v", err)
	}
	if _, err := svc.VerifyPasskeyLogin(context.Background(), options.Challenge, json.RawMessage(`{}`)); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("VerifyPasskeyLogin() error = %v, want ErrInvalidCredentials", err)
	}
	stored, err := passkeys.GetByCredentialID(context.Background(), encodeCredentialID(rawID))
	if err != nil {
		t.Fatalf("get passkey: %v", err)
	}
	if stored.SignCount != 5 {
		t.Fatalf("sign count = %d, want unchanged 5", stored.SignCount)
	}
}

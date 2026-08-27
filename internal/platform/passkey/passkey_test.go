package passkey

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func newTestAdapter(t *testing.T) *Adapter {
	t.Helper()
	adapter, err := New(Config{
		RPID:                "furtalk.example.com",
		RPOrigins:           []string{"https://furtalk.example.com"},
		RPDisplayName:       "Furtalk",
		LoginTimeout:        time.Minute,
		RegistrationTimeout: time.Minute,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return adapter
}

func TestBeginRegistrationRequiresResidentKeyAndUserVerification(t *testing.T) {
	adapter := newTestAdapter(t)
	options, sessionRaw, err := adapter.BeginRegistration(User{
		ID:          []byte("user-handle"),
		Name:        "alice",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	var creation protocol.CredentialCreation
	if err := json.Unmarshal(options, &creation); err != nil {
		t.Fatalf("decode creation options: %v", err)
	}
	selection := creation.Response.AuthenticatorSelection
	if selection.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Fatalf("residentKey = %q, want %q", selection.ResidentKey, protocol.ResidentKeyRequirementRequired)
	}
	if selection.RequireResidentKey == nil || !*selection.RequireResidentKey {
		t.Fatalf("requireResidentKey = %v, want true", selection.RequireResidentKey)
	}
	if selection.UserVerification != protocol.VerificationRequired {
		t.Fatalf("userVerification = %q, want %q", selection.UserVerification, protocol.VerificationRequired)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionRaw, &session); err != nil {
		t.Fatalf("decode registration session: %v", err)
	}
	if session.UserVerification != protocol.VerificationRequired {
		t.Fatalf("registration session userVerification = %q, want %q", session.UserVerification, protocol.VerificationRequired)
	}
}

func TestBeginLoginIsDiscoverableAndRequiresUserVerification(t *testing.T) {
	adapter := newTestAdapter(t)
	options, sessionRaw, err := adapter.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	var assertion protocol.CredentialAssertion
	if err := json.Unmarshal(options, &assertion); err != nil {
		t.Fatalf("decode login options: %v", err)
	}
	if len(assertion.Response.AllowedCredentials) != 0 {
		t.Fatalf("allowCredentials = %v, want empty", assertion.Response.AllowedCredentials)
	}
	if assertion.Response.UserVerification != protocol.VerificationRequired {
		t.Fatalf("userVerification = %q, want %q", assertion.Response.UserVerification, protocol.VerificationRequired)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionRaw, &session); err != nil {
		t.Fatalf("decode login session: %v", err)
	}
	if len(session.UserID) != 0 {
		t.Fatalf("login session user ID = %x, want empty discoverable session", session.UserID)
	}
	if len(session.AllowedCredentialIDs) != 0 {
		t.Fatalf("login session allowed credentials = %v, want empty", session.AllowedCredentialIDs)
	}
	if session.UserVerification != protocol.VerificationRequired {
		t.Fatalf("login session userVerification = %q, want %q", session.UserVerification, protocol.VerificationRequired)
	}
}

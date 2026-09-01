package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/crypto"
	"furtalk/internal/platform/ratelimit"
)

type passwordAdmissionCall struct {
	policy  string
	subject string
}

type passwordAdmissionStub struct {
	allow bool
	calls []passwordAdmissionCall
}

func (a *passwordAdmissionStub) Allow(policy, subject string) bool {
	a.calls = append(a.calls, passwordAdmissionCall{policy: policy, subject: subject})
	return a.allow
}

func TestArgon2BudgetIsNonBlockingAndCapacityBounded(t *testing.T) {
	budget := newArgon2Budget(publicPasswordLoginConcurrency)
	releases := make([]func(), 0, publicPasswordLoginConcurrency)
	for i := 0; i < publicPasswordLoginConcurrency; i++ {
		release, ok := budget.acquire()
		if !ok || release == nil {
			t.Fatalf("acquire %d failed, want success", i)
		}
		releases = append(releases, release)
	}
	if release, ok := budget.acquire(); ok || release != nil {
		t.Fatalf("third acquire succeeded, want immediate rejection")
	}
	releases[0]()
	if release, ok := budget.acquire(); !ok || release == nil {
		t.Fatalf("acquire after release failed, want success")
	} else {
		release()
	}
	releases[1]()
}

func TestPasswordLoginAdmissionUsesDigestAndTrustedIP(t *testing.T) {
	admission := &passwordAdmissionStub{allow: true}
	svc := &Service{
		admission:      admission,
		passwordBudget: newArgon2Budget(1),
		captchaPolicy:  staticCaptchaPolicy{policy: map[string]bool{}},
	}
	// Fill the gate so the test stops before touching a nil repository while
	// still exercising both dedicated policy subjects.
	release, ok := svc.passwordBudget.acquire()
	if !ok {
		t.Fatal("fill password budget")
	}
	defer release()

	_, err := svc.LoginWithPasswordFromInput(context.Background(), PasswordLoginInput{
		Email: " User@Example.com ", Password: "password", ClientIP: "203.0.113.7",
	})
	if !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	if len(admission.calls) != 2 {
		t.Fatalf("admission calls = %+v, want IP and email", admission.calls)
	}
	if admission.calls[0].policy != ratelimit.PolicyPasswordLoginIP || admission.calls[0].subject != "ip:203.0.113.7" {
		t.Fatalf("IP admission = %+v", admission.calls[0])
	}
	wantDigest := cryptox.SHA256Hex([]byte("user@example.com"))
	if admission.calls[1].policy != ratelimit.PolicyPasswordLoginEmail || admission.calls[1].subject != "email:"+wantDigest {
		t.Fatalf("email admission = %+v, want digest subject", admission.calls[1])
	}
	if strings.Contains(admission.calls[1].subject, "user@example.com") {
		t.Fatal("email admission subject contains plaintext email")
	}
}

func TestPasswordLoginCaptchaFailureSkipsAdmissionAndArgon2(t *testing.T) {
	admission := &passwordAdmissionStub{allow: true}
	svc := &Service{
		admission: admission,
		captchaPolicy: staticCaptchaPolicy{policy: map[string]bool{
			PasswordLoginAction: true,
		}},
		captcha:        &recordingCaptchaVerifier{err: domain.ErrCaptchaFailed},
		passwordBudget: newArgon2Budget(1),
	}
	if _, err := svc.LoginWithPasswordFromInput(context.Background(), PasswordLoginInput{
		Email: "user@example.com", Password: "password", CaptchaToken: "bad", ClientIP: "203.0.113.7",
	}); !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("error = %v, want ErrCaptchaFailed", err)
	}
	if len(admission.calls) != 0 {
		t.Fatalf("admission calls = %+v, want none after CAPTCHA failure", admission.calls)
	}
}

package app

import (
	"testing"

	"furtalk/internal/handler"
	"furtalk/internal/platform/ratelimit"
	"furtalk/internal/service/identity"
)

func TestDefaultFlowPoliciesPreserveApplicationBudgets(t *testing.T) {
	want := map[string]ratelimit.Config{
		handler.PolicyPasskeyLoginOptions:        {Rate: 0.5, Burst: 5},
		handler.PolicyOAuthStart:                 {Rate: 0.2, Burst: 5},
		handler.PolicyOAuthHandoff:               {Rate: 0.5, Burst: 5},
		handler.PolicyPasskeyRegistrationOptions: {Rate: 0.2, Burst: 3},
		handler.PolicyWidgetAuthCode:             {Rate: 1, Burst: 10},
		identity.PolicyPasswordLoginIP:           {Rate: 0.5, Burst: 5},
		identity.PolicyPasswordLoginEmail:        {Rate: 0.2, Burst: 3},
	}
	got := defaultFlowPolicies()
	if len(got) != len(want) {
		t.Fatalf("policy count = %d, want %d", len(got), len(want))
	}
	for name, budget := range want {
		if got[name] != budget {
			t.Fatalf("policy %q = %+v, want %+v", name, got[name], budget)
		}
	}
}

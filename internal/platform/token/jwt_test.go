package jwt

import (
	"strings"
	"testing"
	"time"
)

func testService() *Service {
	return NewService(Config{Issuer: "https://furtalk.example.com", Key: []byte("0123456789abcdef0123456789abcdef"), Lifetime: time.Hour})
}

// TestSignFirstPartyRequiresPositiveSessionVersion 验证第一方签发必须携带正版本。
func TestSignFirstPartyRequiresPositiveSessionVersion(t *testing.T) {
	t.Parallel()
	svc := testService()
	for _, version := range []int64{0, -1} {
		if _, err := svc.SignFirstParty(1, version); err == nil {
			t.Fatalf("SignFirstParty with version %d must fail", version)
		}
	}
}

// TestSignFirstPartyRoundTripsSessionVersion 验证签发的第一方 token 解析后携带正版本。
func TestSignFirstPartyRoundTripsSessionVersion(t *testing.T) {
	t.Parallel()
	svc := testService()
	raw, err := svc.SignFirstParty(42, 7)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := svc.Parse(raw, AudienceFirstParty, TokenKindFirstParty)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.SessionVersion != 7 {
		t.Fatalf("session version = %d, want 7", claims.SessionVersion)
	}
	if claims.TokenKind != TokenKindFirstParty {
		t.Fatalf("token kind = %q, want first_party", claims.TokenKind)
	}
}

// TestWidgetTokenUnaffectedBySessionVersion 验证 widget token 不携带会话代次，
// 解析后保持零值，符合 widget 凭据契约。
func TestWidgetTokenUnaffectedBySessionVersion(t *testing.T) {
	t.Parallel()
	svc := testService()
	raw, err := svc.SignWidget(1, 2, TokenKindWidgetAuthenticated, "5")
	if err != nil {
		t.Fatalf("sign widget: %v", err)
	}
	if strings.Contains(raw, "session_version") {
		t.Fatal("widget token must not carry session_version claim")
	}
	claims, err := svc.Parse(raw, AudienceWidgetAuthenticated, TokenKindWidgetAuthenticated)
	if err != nil {
		t.Fatalf("parse widget: %v", err)
	}
	if claims.SessionVersion != 0 {
		t.Fatalf("widget session version = %d, want 0", claims.SessionVersion)
	}
}

// TestUnsubscribeTokenUnaffectedBySessionVersion 验证退订 token 不携带会话代次。
func TestUnsubscribeTokenUnaffectedBySessionVersion(t *testing.T) {
	t.Parallel()
	svc := testService()
	raw, err := svc.SignUnsubscribe(1, "reply", time.Minute)
	if err != nil {
		t.Fatalf("sign unsubscribe: %v", err)
	}
	if strings.Contains(raw, "session_version") {
		t.Fatal("unsubscribe token must not carry session_version claim")
	}
	userID, kind, err := svc.ParseUnsubscribe(raw)
	if err != nil {
		t.Fatalf("parse unsubscribe: %v", err)
	}
	if userID != 1 || kind != "reply" {
		t.Fatalf("unsubscribe = (%d, %q), want (1, reply)", userID, kind)
	}
}

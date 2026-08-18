package logging

import (
	"bytes"
	"log/slog"
	"testing"
)

// TestRedactRecordAttrs 验证记录属性中的敏感键被替换为占位符。
func TestRedactRecordAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON)
	logger.Info("sensitive record",
		"setup_token", "raw-token",
		"password", "pw",
		"api_token", "tok",
		"provider_secret", "sec",
		"request_id", "req-1",
		"error", "boom",
	)
	record := decode(t, &buf)
	for _, key := range []string{"setup_token", "password", "api_token", "provider_secret"} {
		if record[key] != "[REDACTED]" {
			t.Fatalf("%s = %#v, want [REDACTED]", key, record[key])
		}
	}
	if record["request_id"] != "req-1" {
		t.Fatalf("request_id = %v, want req-1", record["request_id"])
	}
	if record["error"] != "boom" {
		t.Fatalf("error = %v, want boom", record["error"])
	}
}

// TestRedactWithAttrs 验证 Logger.With 扩展属性也会被脱敏。
func TestRedactWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON).With(
		slog.String("authorization", "Bearer secret"),
		slog.String("user_id", "42"),
	)
	logger.Info("with attrs", "message", "ok")
	record := decode(t, &buf)
	if record["authorization"] != "[REDACTED]" {
		t.Fatalf("authorization = %#v, want [REDACTED]", record["authorization"])
	}
	if record["user_id"] != "42" {
		t.Fatalf("user_id = %v, want 42", record["user_id"])
	}
}

// TestRedactGroup 验证 group 内部属性递归脱敏，非敏感子属性保留。
func TestRedactGroup(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON)
	logger.Info("group",
		slog.Group("auth",
			slog.String("token", "secret"),
			slog.String("provider", "google"),
		),
	)
	record := decode(t, &buf)
	group, ok := record["auth"].(map[string]any)
	if !ok {
		t.Fatalf("auth group missing: %#v", record["auth"])
	}
	if group["token"] != "[REDACTED]" {
		t.Fatalf("auth.token = %#v, want [REDACTED]", group["token"])
	}
	if group["provider"] != "google" {
		t.Fatalf("auth.provider = %v, want google", group["provider"])
	}
}

// TestSetupTokenAllowed 验证 SetupToken helper 构造的属性输出明文。
func TestSetupTokenAllowed(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON)
	logger.Info("bootstrap", SetupToken("plain-token"), "expires_at", "2026-08-08T00:00:00Z")
	record := decode(t, &buf)
	if record["setup_token"] != "plain-token" {
		t.Fatalf("setup_token = %#v, want plain-token", record["setup_token"])
	}
}

// TestSetupTokenPlainStringRedacted 验证普通 setup_token 字符串属性被脱敏。
func TestSetupTokenPlainStringRedacted(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON)
	logger.Info("bootstrap", slog.String("setup_token", "plain-token"))
	record := decode(t, &buf)
	if record["setup_token"] != "[REDACTED]" {
		t.Fatalf("setup_token = %#v, want [REDACTED]", record["setup_token"])
	}
}

// TestSetupTokenAllowedThroughWith 验证 SetupToken 放行属性经 Logger.With 后仍为明文。
func TestSetupTokenAllowedThroughWith(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON).With(SetupToken("with-token"))
	logger.Info("bootstrap")
	record := decode(t, &buf)
	if record["setup_token"] != "with-token" {
		t.Fatalf("setup_token = %#v, want with-token", record["setup_token"])
	}
}

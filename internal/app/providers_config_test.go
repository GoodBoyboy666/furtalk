package app

import (
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/config"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/mailer"
	"furtalk/internal/platform/passkey"
	"furtalk/internal/platform/ratelimit"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
)

// TestConfigProjections 验证组合根把中央配置投影为 consumer-owned 最小配置的完整映射。
// 每个字段都显式断言，platform、feature 与 app-private 字段在重构后不会漂移。
func TestConfigProjections(t *testing.T) {
	cfg := config.Config{
		HTTP: config.HTTPConfig{
			Address:         "127.0.0.1:8080",
			PublicBaseURL:   "https://furtalk.example.com",
			RateLimitRate:   42.5,
			RateLimitBurst:  200,
			ShutdownTimeout: 10 * time.Second,
			BodyLimit:       1 << 20,
		},
		Database: config.DatabaseConfig{
			Dialect:  "postgres",
			Host:     "host",
			Port:     5432,
			Name:     "db",
			User:     "user",
			Password: "pass",
			SSLMode:  "require",
		},
		Cache: config.CacheConfig{
			RedisURL: "redis://localhost:6379/0",
		},
		Tokens: config.TokensConfig{
			JWTIssuer:         "https://furtalk.example.com",
			JWTAlgorithm:      "HS256",
			JWTKey:            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SecretKey:         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			JWTLifetime:       time.Hour,
			WidgetJWTLifetime: 30 * time.Minute,
		},
		WebAuthn: config.WebAuthnConfig{
			RPID:      "furtalk.example.com",
			RPOrigins: []string{"https://furtalk.example.com"},
			RPName:    "Furtalk",
		},
		OAuth: config.OAuthConfig{ClientTimeout: time.Second},
		SMTP: config.SMTPConfig{
			Host:     "smtp.example.com",
			Port:     587,
			From:     "noreply@example.com",
			TLS:      "starttls",
			Username: "mailuser",
			Password: "mailpass",
			Timeout:  30 * time.Second,
		},
	}

	got := configProjections(cfg)

	if !reflect.DeepEqual(got.Database, database.Config{
		Dialect:  "postgres",
		Host:     "host",
		Port:     5432,
		Name:     "db",
		User:     "user",
		Password: "pass",
		SSLMode:  "require",
	}) {
		t.Errorf("database projection = %+v", got.Database)
	}
	if !reflect.DeepEqual(got.Cache, cache.Config{RedisURL: "redis://localhost:6379/0"}) {
		t.Errorf("cache projection = %+v", got.Cache)
	}
	if !reflect.DeepEqual(got.RateLimit, ratelimit.Config{Rate: 42.5, Burst: 200}) {
		t.Errorf("rate limit projection = %+v", got.RateLimit)
	}

	wantSMTP := mailer.SMTPConfig{
		Host:     "smtp.example.com",
		Port:     587,
		From:     "noreply@example.com",
		TLS:      "starttls",
		Username: "mailuser",
		Password: "mailpass",
		Timeout:  30 * time.Second,
	}
	if !reflect.DeepEqual(got.SMTP, wantSMTP) {
		t.Errorf("smtp projection = %+v, want %+v", got.SMTP, wantSMTP)
	}
	if got.SMTP.TLSConfig != nil {
		t.Error("smtp projection must keep TLSConfig nil in production")
	}

	wantPasskey := passkey.Config{
		RPID:                "furtalk.example.com",
		RPOrigins:           []string{"https://furtalk.example.com"},
		RPDisplayName:       "Furtalk",
		LoginTimeout:        5 * time.Minute,
		RegistrationTimeout: 5 * time.Minute,
	}
	if !reflect.DeepEqual(got.Passkey, wantPasskey) {
		t.Errorf("passkey projection = %+v, want %+v", got.Passkey, wantPasskey)
	}

	if !reflect.DeepEqual(got.HTTP, cfg.HTTP) {
		t.Errorf("http projection = %+v", got.HTTP)
	}

	wantSigner := identity.SignerConfig{
		Issuer:   "https://furtalk.example.com",
		Key:      []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Lifetime: time.Hour,
	}
	if !reflect.DeepEqual(got.Signer, wantSigner) {
		t.Errorf("signer projection = %+v, want %+v", got.Signer, wantSigner)
	}

	wantWidgetSigner := comment.WidgetSignerConfig{
		Issuer:   "https://furtalk.example.com",
		Key:      []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Lifetime: 30 * time.Minute,
	}
	if !reflect.DeepEqual(got.WidgetSigner, wantWidgetSigner) {
		t.Errorf("widget signer projection = %+v, want %+v", got.WidgetSigner, wantWidgetSigner)
	}

	if !reflect.DeepEqual(got.OAuthFactory, identity.OAuthFactoryConfig{ClientTimeout: time.Second}) {
		t.Errorf("oauth factory projection = %+v", got.OAuthFactory)
	}

	wantServices := servicesConfig{
		ProviderSecretKey: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		PublicBaseURL:     "https://furtalk.example.com",
	}
	if !reflect.DeepEqual(got.Services, wantServices) {
		t.Errorf("services projection = %+v, want %+v", got.Services, wantServices)
	}
}

// TestConfigProjectionsUsesExplicitPasskeyAndIssuer 验证显式 RP 与 JWT issuer
// 被逐字段直接映射，修改 PublicBaseURL 不改变 RP 或 issuer。
func TestConfigProjectionsUsesExplicitPasskeyAndIssuer(t *testing.T) {
	cfg := config.Config{
		HTTP: config.HTTPConfig{
			PublicBaseURL: "https://other.example.com",
		},
		Tokens: config.TokensConfig{
			JWTIssuer:         "https://jwt.example.com",
			JWTLifetime:       5 * time.Minute,
			WidgetJWTLifetime: 5 * time.Minute,
		},
		WebAuthn: config.WebAuthnConfig{
			RPID:      "passkeys.example.com",
			RPOrigins: []string{"https://passkeys.example.com"},
			RPName:    "Furtalk",
		},
	}

	got := configProjections(cfg)

	if got.Passkey.RPID != "passkeys.example.com" {
		t.Errorf("rp id = %q, want explicit passkeys.example.com", got.Passkey.RPID)
	}
	if len(got.Passkey.RPOrigins) != 1 || got.Passkey.RPOrigins[0] != "https://passkeys.example.com" {
		t.Errorf("origins = %v, want explicit [https://passkeys.example.com]", got.Passkey.RPOrigins)
	}
	if got.Passkey.RPDisplayName != "Furtalk" {
		t.Errorf("rp display name = %q, want Furtalk", got.Passkey.RPDisplayName)
	}
	if got.Passkey.LoginTimeout != 5*time.Minute || got.Passkey.RegistrationTimeout != 5*time.Minute {
		t.Errorf("passkey timeouts = %v/%v, want 5m/5m", got.Passkey.LoginTimeout, got.Passkey.RegistrationTimeout)
	}
	if got.Signer.Issuer != "https://jwt.example.com" || got.WidgetSigner.Issuer != "https://jwt.example.com" {
		t.Errorf("signer issuers = %q/%q, want explicit https://jwt.example.com", got.Signer.Issuer, got.WidgetSigner.Issuer)
	}

	cfg.HTTP.PublicBaseURL = "https://changed.example.com"
	again := configProjections(cfg)
	if again.Passkey.RPID != "passkeys.example.com" || again.Signer.Issuer != "https://jwt.example.com" {
		t.Errorf("changing public_base_url must not alter RP or issuer: %q/%q",
			again.Passkey.RPID, again.Signer.Issuer)
	}
}

// TestNewLoggerUsesConfiguredFormat 验证组合根按 config.Logging.Format 选择 handler：
// text 输出 slog 文本，json 输出结构化 JSON，两者共享同一脱敏 handler 契约。
func TestNewLoggerUsesConfiguredFormat(t *testing.T) {
	for _, tt := range []struct {
		name   string
		format string
		check  func(t *testing.T, line string)
	}{
		{
			name:   "text",
			format: "text",
			check: func(t *testing.T, line string) {
				t.Helper()
				if !strings.Contains(line, "level=INFO") || !strings.Contains(line, "msg=hello") {
					t.Fatalf("text log line = %q, want level=INFO and msg=hello", line)
				}
			},
		},
		{
			name:   "json",
			format: "json",
			check: func(t *testing.T, line string) {
				t.Helper()
				var record map[string]any
				if err := json.Unmarshal([]byte(line), &record); err != nil {
					t.Fatalf("decode json log line: %v\nraw: %s", err, line)
				}
				if record["level"] != "INFO" || record["msg"] != "hello" {
					t.Fatalf("json record = %v, want level INFO and msg hello", record)
				}
			},
		},
		{
			name:   "default empty falls back to text",
			format: "",
			check: func(t *testing.T, line string) {
				t.Helper()
				if !strings.Contains(line, "level=INFO") || !strings.Contains(line, "msg=hello") {
					t.Fatalf("text log line = %q, want level=INFO and msg=hello", line)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{Logging: config.LoggingConfig{Format: tt.format}}
			line := captureStdout(t, func() {
				newLogger(cfg).Info("hello", "key", "value")
			})
			tt.check(t, line)
		})
	}
}

// captureStdout 运行 fn 期间接管 os.Stdout 并返回其全部输出。
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	defer w.Close()

	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out)
}

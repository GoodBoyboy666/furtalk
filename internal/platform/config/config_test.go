package config

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateRPID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		ok    bool
	}{
		{name: "localhost", value: "localhost", ok: true},
		{name: "dns", value: "furtalk.example.com", ok: true},
		{name: "ipv4", value: "127.0.0.1", ok: true},
		{name: "ipv6 loopback", value: "::1", ok: true},
		{name: "ipv6 global", value: "2001:db8::1", ok: true},
		{name: "dns port", value: "furtalk.example.com:8443", ok: false},
		{name: "ipv4 port", value: "127.0.0.1:8443", ok: false},
		{name: "bracketed ipv6", value: "[::1]", ok: false},
		{name: "bracketed ipv6 port", value: "[::1]:8443", ok: false},
		{name: "scheme", value: "https://furtalk.example.com", ok: false},
		{name: "path", value: "furtalk.example.com/path", ok: false},
		{name: "userinfo", value: "user@furtalk.example.com", ok: false},
		{name: "empty label", value: "comments..example.com", ok: false},
		{name: "leading hyphen", value: "-furtalk.example.com", ok: false},
		{name: "underscore", value: "comments_api.example.com", ok: false},
		{name: "surrounding whitespace", value: " furtalk.example.com ", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRPID(tt.value)
			if tt.ok && err != nil {
				t.Fatalf("validateRPID(%q) returned %v", tt.value, err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("validateRPID(%q) succeeded", tt.value)
			}
		})
	}
}

func TestExplicitPasskeyRPIDRejectsPort(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig("https://furtalk.example.com")
	cfg.WebAuthn.RPID = "furtalk.example.com:443"
	cfg.WebAuthn.RPOrigins = []string{"https://furtalk.example.com"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an RPID containing a port")
	}
}

func TestValidateRejectsNonPositiveHTTPServerLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*HTTPConfig)
	}{
		{name: "read header timeout", mutate: func(c *HTTPConfig) { c.ReadHeaderTimeout = 0 }},
		{name: "read timeout", mutate: func(c *HTTPConfig) { c.ReadTimeout = 0 }},
		{name: "write timeout", mutate: func(c *HTTPConfig) { c.WriteTimeout = 0 }},
		{name: "idle timeout", mutate: func(c *HTTPConfig) { c.IdleTimeout = 0 }},
		{name: "max header bytes", mutate: func(c *HTTPConfig) { c.MaxHeaderBytes = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig("https://furtalk.example.com")
			tt.mutate(&cfg.HTTP)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() accepted a non-positive HTTP server limit")
			}
		})
	}
}

func TestValidateOAuthClientTimeoutBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value time.Duration
		want  bool
	}{
		{name: "zero", value: 0, want: false},
		{name: "negative", value: -time.Second, want: false},
		{name: "default", value: defaultOAuthTimeout, want: true},
		{name: "maximum", value: maxOAuthClientTimeout, want: true},
		{name: "over maximum", value: maxOAuthClientTimeout + time.Nanosecond, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig("https://furtalk.example.com")
			cfg.OAuth.ClientTimeout = tt.value
			err := cfg.Validate()
			if tt.want && err != nil {
				t.Fatalf("Validate() returned %v for %s", err, tt.name)
			}
			if !tt.want && err == nil {
				t.Fatalf("Validate() accepted %s timeout %s", tt.name, tt.value)
			}
		})
	}
}

func validTestConfig(baseURL string) Config {
	return Config{
		HTTP: HTTPConfig{
			Address:           ":8080",
			PublicBaseURL:     baseURL,
			ShutdownTimeout:   time.Second,
			ReadHeaderTimeout: time.Second,
			ReadTimeout:       time.Second,
			WriteTimeout:      time.Second,
			IdleTimeout:       time.Second,
			MaxHeaderBytes:    1024,
			BodyLimit:         1 << 20,
			RateLimitRate:     10,
			RateLimitBurst:    100,
		},
		Database: DatabaseConfig{Dialect: "sqlite", Path: ":memory:"},
		Tokens: TokensConfig{
			JWTIssuer:         baseURL,
			JWTAlgorithm:      "HS256",
			JWTKey:            strings.Repeat("j", 32),
			JWTLifetime:       time.Hour,
			WidgetJWTLifetime: time.Hour,
			SecretKey:         strings.Repeat("s", 32),
		},
		WebAuthn: WebAuthnConfig{
			RPID:      "furtalk.example.com",
			RPOrigins: []string{"https://furtalk.example.com"},
			RPName:    "Furtalk",
		},
		OAuth: OAuthConfig{ClientTimeout: defaultOAuthTimeout},
	}
}

func TestLoadNestedConfigFile(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  address: ":9090"
  public_base_url: "https://furtalk.example.com"
  read_header_timeout: "4s"
  read_timeout: "12s"
  write_timeout: "45s"
  idle_timeout: "50s"
  max_header_bytes: 32768
  trusted_proxies:
    - "10.0.0.0/8"
  rate_limit_rate: 25
database:
  dialect: sqlite
  path: ":memory:"
cache:
  redis_url: "redis://localhost:6379/1"
tokens:
  jwt_issuer: "https://furtalk.example.com"
  jwt_algorithm: HS256
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
webauthn:
  rp_id: "furtalk.example.com"
  rp_origins:
    - "https://furtalk.example.com"
  rp_name: "Example Comments"
oauth:
  client_timeout: "20s"
logging:
  format: json
smtp:
  host: "smtp.example.com"
  port: 2525
  from: "noreply@example.com"
  tls: none
  username: user
  password: secret
  timeout: "5s"
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.HTTP.Address != ":9090" || c.HTTP.RateLimitRate != 25 ||
		c.HTTP.ReadHeaderTimeout != 4*time.Second || c.HTTP.ReadTimeout != 12*time.Second ||
		c.HTTP.WriteTimeout != 45*time.Second || c.HTTP.IdleTimeout != 50*time.Second ||
		c.HTTP.MaxHeaderBytes != 32768 {
		t.Fatalf("HTTP config = %+v", c.HTTP)
	}
	if got := c.HTTP.TrustedProxies; len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("trusted proxies = %v", got)
	}
	if c.Database.Path != ":memory:" || c.Cache.RedisURL != "redis://localhost:6379/1" {
		t.Fatalf("database/cache config = %+v / %+v", c.Database, c.Cache)
	}
	if c.Tokens.JWTLifetime != defaultJWTLifetime || c.WebAuthn.RPName != "Example Comments" {
		t.Fatalf("tokens/WebAuthn config = %+v / %+v", c.Tokens, c.WebAuthn)
	}
	if c.OAuth.ClientTimeout != 20*time.Second || c.SMTP.Port != 2525 || c.SMTP.Timeout != 5*time.Second {
		t.Fatalf("OAuth/SMTP config = %+v / %+v", c.OAuth, c.SMTP)
	}
	if c.Logging.Format != "json" {
		t.Fatalf("logging format = %q, want json", c.Logging.Format)
	}
}

func TestLoadNestedEnvironmentOverridesFile(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  address: ":9090"
  public_base_url: "https://furtalk.example.com"
database:
  dialect: sqlite
  path: ":memory:"
tokens:
  jwt_issuer: "https://file.example.com"
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
webauthn:
  rp_id: "furtalk.example.com"
  rp_origins:
    - "https://furtalk.example.com"
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)
	t.Setenv("FURTALK_HTTP_ADDRESS", ":7070")
	t.Setenv("FURTALK_TOKENS_JWT_ISSUER", "https://env.example.com")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.HTTP.Address != ":7070" || c.Tokens.JWTIssuer != "https://env.example.com" {
		t.Fatalf("environment did not override file: %+v", c)
	}
}

func TestLoadEnvironmentOnlyNestedValues(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_HTTP_ADDRESS", ":7071")
	t.Setenv("FURTALK_HTTP_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.0.0/16")
	t.Setenv("FURTALK_HTTP_READ_HEADER_TIMEOUT", "3s")
	t.Setenv("FURTALK_HTTP_MAX_HEADER_BYTES", "16384")
	t.Setenv("FURTALK_TOKENS_JWT_LIFETIME", "2h")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.HTTP.Address != ":7071" || len(c.HTTP.TrustedProxies) != 2 ||
		c.HTTP.ReadHeaderTimeout != 3*time.Second || c.HTTP.MaxHeaderBytes != 16384 ||
		c.Tokens.JWTLifetime != 2*time.Hour {
		t.Fatalf("environment-only values were not decoded: %+v", c)
	}
}

func TestLoadLoggingFormatFromEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_LOGGING_FORMAT", "json")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.Logging.Format != "json" {
		t.Fatalf("logging format = %q, want json from environment", c.Logging.Format)
	}
}

func TestLoadLoggingFormatEnvironmentOverridesFile(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  address: ":9090"
  public_base_url: "https://furtalk.example.com"
database:
  dialect: sqlite
  path: ":memory:"
tokens:
  jwt_issuer: "https://furtalk.example.com"
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
webauthn:
  rp_id: "furtalk.example.com"
  rp_origins:
    - "https://furtalk.example.com"
logging:
  format: text
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)
	t.Setenv("FURTALK_LOGGING_FORMAT", "json")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.Logging.Format != "json" {
		t.Fatalf("logging format = %q, want environment json to override file", c.Logging.Format)
	}
}

func TestLoadRejectsInvalidLoggingFormat(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_LOGGING_FORMAT", "pretty")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "logging.format") {
		t.Fatalf("Load() error = %v, want invalid logging.format", err)
	}
}

func TestLoadRejectsInvalidLoggingFormatFromFile(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  public_base_url: "https://furtalk.example.com"
database:
  dialect: sqlite
  path: ":memory:"
tokens:
  jwt_issuer: "https://furtalk.example.com"
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
webauthn:
  rp_id: "furtalk.example.com"
  rp_origins:
    - "https://furtalk.example.com"
logging:
  format: YAML
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "logging.format") {
		t.Fatalf("Load() error = %v, want invalid logging.format from file", err)
	}
}

func TestLoadSilentLoggingFormatDefault(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.Logging.Format != "text" {
		t.Fatalf("logging format = %q, want silent default text", c.Logging.Format)
	}
	for _, w := range c.Warnings() {
		if w.Key == "logging.format" {
			t.Fatalf("logging.format must not warn: %+v", w)
		}
	}
}

func TestLoadRejectsUnknownNestedKey(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  public_base_url: "https://furtalk.example.com"
  unknown: true
tokens:
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("Load() error = %v, want unknown-key decode error", err)
	}
}

func TestLoadRejectsInvalidTypedValue(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  public_base_url: "https://furtalk.example.com"
  body_limit: invalid
tokens:
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "body_limit") {
		t.Fatalf("Load() error = %v, want body_limit decode error", err)
	}
}

func TestLoadNestedTOMLConfig(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.toml")
	contents := []byte(`
[http]
address = ":9091"
public_base_url = "https://furtalk.example.com"
trusted_proxies = "10.0.0.0/8, 192.168.0.0/16"
shutdown_timeout = "15s"

[database]
dialect = "sqlite"
path = ":memory:"

[tokens]
jwt_issuer = "https://furtalk.example.com"
jwt_key = "` + strings.Repeat("j", 32) + `"
secret_key = "` + strings.Repeat("s", 32) + `"

[webauthn]
rp_id = "furtalk.example.com"
rp_origins = ["https://furtalk.example.com"]
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.HTTP.Address != ":9091" || c.HTTP.ShutdownTimeout != 15*time.Second {
		t.Fatalf("HTTP config = %+v", c.HTTP)
	}
	if got := c.HTTP.TrustedProxies; len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.0.0/16" {
		t.Fatalf("trusted proxies = %v", got)
	}
}

func TestLoadUsesExactDefaults(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.HTTP.Address != ":8080" || c.HTTP.ShutdownTimeout != defaultShutdownTimeout ||
		c.HTTP.ReadHeaderTimeout != defaultReadHeaderTimeout || c.HTTP.ReadTimeout != defaultReadTimeout ||
		c.HTTP.WriteTimeout != defaultWriteTimeout || c.HTTP.IdleTimeout != defaultIdleTimeout ||
		c.HTTP.MaxHeaderBytes != defaultMaxHeaderBytes ||
		c.HTTP.BodyLimit != defaultBodyLimit || c.HTTP.RateLimitRate != defaultRateLimitRate ||
		c.HTTP.RateLimitBurst != defaultRateLimitBurst {
		t.Fatalf("HTTP defaults = %+v", c.HTTP)
	}
	if c.Tokens.JWTLifetime != defaultJWTLifetime || c.Tokens.WidgetJWTLifetime != defaultWidgetLifetime {
		t.Fatalf("token defaults = %+v", c.Tokens)
	}
	if c.WebAuthn.RPName != "Furtalk" || c.OAuth.ClientTimeout != defaultOAuthTimeout {
		t.Fatalf("WebAuthn/OAuth defaults = %+v / %+v", c.WebAuthn, c.OAuth)
	}
	if c.SMTP.Port != defaultSMTPPort || c.SMTP.TLS != "starttls" || c.SMTP.Timeout != defaultSMTPTimeout {
		t.Fatalf("SMTP defaults = %+v", c.SMTP)
	}
}

func TestLoadIgnoresEmptyEnvironmentValue(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  address: ":9092"
  public_base_url: "https://furtalk.example.com"
database:
  dialect: sqlite
  path: ":memory:"
tokens:
  jwt_issuer: "https://furtalk.example.com"
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
webauthn:
  rp_id: "furtalk.example.com"
  rp_origins:
    - "https://furtalk.example.com"
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)
	t.Setenv("FURTALK_HTTP_ADDRESS", "")
	t.Setenv("FURTALK_TOKENS_JWT_ALGORITHM", "")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.HTTP.Address != ":9092" || c.Tokens.JWTAlgorithm != "HS256" {
		t.Fatalf("empty environment value replaced file/default: %+v", c)
	}
}

func TestLoadRejectsInvalidEnvironmentType(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_HTTP_BODY_LIMIT", "invalid")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "body_limit") {
		t.Fatalf("Load() error = %v, want body_limit decode error", err)
	}
}

func TestLoadKeepsSecretKeyRaw(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "raw text", value: strings.Repeat("s", 32), want: strings.Repeat("s", 32)},
		{name: "base64 text stays literal", value: encoded, want: encoded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearConfigEnvironment(t)
			t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
			setValidEnvironment(t)
			t.Setenv("FURTALK_TOKENS_SECRET_KEY", tt.value)

			c, err := Load()
			if err != nil {
				t.Fatalf("Load() returned error: %v", err)
			}
			if c.Tokens.SecretKey != tt.want {
				t.Fatalf("secret key = %q, want %q", c.Tokens.SecretKey, tt.want)
			}
		})
	}
}

func TestLoadRejectsShortSecretKey(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_TOKENS_SECRET_KEY", "too-short")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "secret key") {
		t.Fatalf("Load() error = %v, want raw secret key length error", err)
	}
}

func TestLoadRejectsShortJWTKey(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_TOKENS_JWT_KEY", "too-short")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "JWT key") {
		t.Fatalf("Load() error = %v, want raw JWT key length error", err)
	}
}

func TestLoadRejectsLegacyFlatConfigKey(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
addr: ":9090"
http:
  public_base_url: "https://furtalk.example.com"
tokens:
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "addr") {
		t.Fatalf("Load() error = %v, want legacy flat-key error", err)
	}
}

func TestLoadIgnoresLegacyEnvironmentName(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_ADDR", ":9090")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if c.HTTP.Address != ":8080" {
		t.Fatalf("HTTP address = %q, legacy environment name must be ignored", c.HTTP.Address)
	}
}

// findRepoRoot 向上查找包含 configs/config.example.yaml 的仓库根目录。
func findRepoRoot(t *testing.T) (string, error) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "configs", "config.example.yaml")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("configs/config.example.yaml not found above " + dir)
		}
		dir = parent
	}
}

// TestExampleSecretsFailValidation 证明直接复制示例配置的 JWT/secret key 无法
// 通过启动校验。占位值必须短于 32 字节，任何至少 32 字节的示例值都会让
// 部署人员带着可预测密钥上线。
func TestExampleSecretsFailValidation(t *testing.T) {
	t.Parallel()
	root, err := findRepoRoot(t)
	if err != nil {
		t.Skipf("repo root not found: %v", err)
	}

	readSecret := func(name string) string {
		path := filepath.Join(root, "configs", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(data)
	}

	cases := []struct {
		name   string
		value  string
		reason string
	}{
		{name: "example yaml jwt key", value: exampleYAMLSecret(t, readSecret("config.example.yaml"), "jwt_key"), reason: "JWT key"},
		{name: "example yaml secret key", value: exampleYAMLSecret(t, readSecret("config.example.yaml"), "secret_key"), reason: "secret key"},
		{name: "example env jwt key", value: exampleEnvSecret(t, readSecret(".env.example"), "FURTALK_TOKENS_JWT_KEY"), reason: "JWT key"},
		{name: "example env secret key", value: exampleEnvSecret(t, readSecret(".env.example"), "FURTALK_TOKENS_SECRET_KEY"), reason: "secret key"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.value) >= 32 {
				t.Fatalf("example %s placeholder is %d bytes, want < 32 so validation rejects it", tt.reason, len(tt.value))
			}
			cfg := validTestConfig("https://furtalk.example.com")
			cfg.Tokens.JWTKey = tt.value
			cfg.Tokens.SecretKey = tt.value
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate() accepted example %s placeholder", tt.reason)
			}
		})
	}
}

// exampleYAMLSecret 从示例 YAML 提取给定键的字符串字面量值。
func exampleYAMLSecret(t *testing.T, content, key string) string {
	t.Helper()
	prefix := key + ":"
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			value := strings.TrimPrefix(line, prefix)
			value = strings.TrimSpace(value)
			value = strings.Trim(value, `"`)
			return value
		}
	}
	t.Fatalf("key %q not found in example content", key)
	return ""
}

// exampleEnvSecret 从示例 .env 提取给定变量名的值。
func exampleEnvSecret(t *testing.T, content, key string) string {
	t.Helper()
	prefix := key + "="
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) && !strings.HasPrefix(line, "#") {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	t.Fatalf("key %q not found in example content", key)
	return ""
}

func TestValidateRejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "http.public_base_url", mutate: func(c *Config) { c.HTTP.PublicBaseURL = "" }},
		{name: "database.dialect", mutate: func(c *Config) { c.Database.Dialect = "" }},
		{name: "database.path", mutate: func(c *Config) { c.Database.Path = "" }},
		{name: "tokens.jwt_issuer", mutate: func(c *Config) { c.Tokens.JWTIssuer = "" }},
		{name: "tokens.jwt_key", mutate: func(c *Config) { c.Tokens.JWTKey = "" }},
		{name: "tokens.secret_key", mutate: func(c *Config) { c.Tokens.SecretKey = "" }},
		{name: "webauthn.rp_id", mutate: func(c *Config) { c.WebAuthn.RPID = "" }},
		{name: "webauthn.rp_origins", mutate: func(c *Config) { c.WebAuthn.RPOrigins = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig("https://furtalk.example.com")
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() accepted missing %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.name) {
				t.Fatalf("Validate() error = %v, want it to name %s", err, tt.name)
			}
		})
	}
}

func TestValidateDatabaseRequirementsAreDialectSpecific(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "sqlite path",
			mutate: func(c *Config) {
				c.Database.Path = ""
			},
			want: "database.path",
		},
		{
			name: "postgres host",
			mutate: func(c *Config) {
				c.Database = DatabaseConfig{Dialect: "postgres", Port: 5432, Name: "furtalk", User: "user", Password: "password", SSLMode: "require"}
			},
			want: "database.host",
		},
		{
			name: "postgres port",
			mutate: func(c *Config) {
				c.Database = DatabaseConfig{Dialect: "postgres", Host: "localhost", Name: "furtalk", User: "user", Password: "password", SSLMode: "require"}
			},
			want: "database.port",
		},
		{
			name: "postgres name",
			mutate: func(c *Config) {
				c.Database = DatabaseConfig{Dialect: "postgres", Host: "localhost", Port: 5432, User: "user", Password: "password", SSLMode: "require"}
			},
			want: "database.name",
		},
		{
			name: "postgres user",
			mutate: func(c *Config) {
				c.Database = DatabaseConfig{Dialect: "postgres", Host: "localhost", Port: 5432, Name: "furtalk", Password: "password", SSLMode: "require"}
			},
			want: "database.user",
		},
		{
			name: "postgres password",
			mutate: func(c *Config) {
				c.Database = DatabaseConfig{Dialect: "postgres", Host: "localhost", Port: 5432, Name: "furtalk", User: "user", SSLMode: "require"}
			},
			want: "database.password",
		},
		{
			name: "postgres ssl mode",
			mutate: func(c *Config) {
				c.Database = DatabaseConfig{Dialect: "postgres", Host: "localhost", Port: 5432, Name: "furtalk", User: "user", Password: "password"}
			},
			want: "database.ssl_mode",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig("https://furtalk.example.com")
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %s", err, tt.want)
			}
		})
	}
}

func TestValidateIgnoresUnselectedDatabaseFields(t *testing.T) {
	cfg := validTestConfig("https://furtalk.example.com")
	cfg.Database.Host = "not-used"
	cfg.Database.Port = -1
	cfg.Database.Name = ""
	cfg.Database.User = ""
	cfg.Database.Password = ""
	cfg.Database.SSLMode = "not-a-postgres-mode"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("sqlite validation must ignore postgres fields: %v", err)
	}

	cfg.Database = DatabaseConfig{
		Dialect:  "postgres",
		Path:     "ignored-for-postgres",
		Host:     "localhost",
		Port:     5432,
		Name:     "furtalk",
		User:     "user",
		Password: "password",
		SSLMode:  "require",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("postgres validation must ignore sqlite path: %v", err)
	}
}

func TestValidateRejectsPostgresPortAndSSLMode(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*DatabaseConfig)
		want   string
	}{
		{name: "port below range", mutate: func(c *DatabaseConfig) { c.Port = -1 }, want: "database port"},
		{name: "port above range", mutate: func(c *DatabaseConfig) { c.Port = 65536 }, want: "database port"},
		{name: "ssl mode", mutate: func(c *DatabaseConfig) { c.SSLMode = "bogus" }, want: "database ssl_mode"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig("https://furtalk.example.com")
			cfg.Database = DatabaseConfig{Dialect: "postgres", Host: "localhost", Port: 5432, Name: "furtalk", User: "user", Password: "password", SSLMode: "require"}
			tt.mutate(&cfg.Database)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %s", err, tt.want)
			}
		})
	}
}

func TestLoadPostgresDatabaseFieldsFromEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_DATABASE_DIALECT", "postgres")
	t.Setenv("FURTALK_DATABASE_HOST", "[2001:db8::1]")
	t.Setenv("FURTALK_DATABASE_PORT", "5432")
	t.Setenv("FURTALK_DATABASE_NAME", "comments/prod")
	t.Setenv("FURTALK_DATABASE_USER", "reporting")
	t.Setenv("FURTALK_DATABASE_PASSWORD", "secret-value")
	t.Setenv("FURTALK_DATABASE_SSL_MODE", "verify-full")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Database.Dialect != "postgres" || cfg.Database.Host != "[2001:db8::1]" || cfg.Database.Port != 5432 ||
		cfg.Database.Name != "comments/prod" || cfg.Database.User != "reporting" ||
		cfg.Database.Password != "secret-value" || cfg.Database.SSLMode != "verify-full" {
		t.Fatalf("postgres database config = %+v", cfg.Database)
	}
}

func TestLoadPostgresDatabaseFieldsFromYAML(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  public_base_url: "https://furtalk.example.com"
database:
  dialect: postgres
  host: "db.example.com"
  port: 5433
  name: "furtalk"
  user: "service"
  password: "p@ssword"
  ssl_mode: verify-ca
tokens:
  jwt_issuer: "https://furtalk.example.com"
  jwt_key: "` + strings.Repeat("j", 32) + `"
  secret_key: "` + strings.Repeat("s", 32) + `"
webauthn:
  rp_id: "furtalk.example.com"
  rp_origins:
    - "https://furtalk.example.com"
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Database.Host != "db.example.com" || cfg.Database.Port != 5433 || cfg.Database.SSLMode != "verify-ca" {
		t.Fatalf("YAML postgres database config = %+v", cfg.Database)
	}
}

func TestLoadIgnoresMalformedUnselectedDatabaseFields(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_DATABASE_HOST", "[not-a-postgres-value]")
	t.Setenv("FURTALK_DATABASE_PORT", "not-an-integer")
	t.Setenv("FURTALK_DATABASE_NAME", "unused")
	t.Setenv("FURTALK_DATABASE_SSL_MODE", "not-a-mode")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("SQLite Load() must ignore malformed PostgreSQL fields: %v", err)
	}
	if cfg.Database.Path != ":memory:" || cfg.Database.Host != "" || cfg.Database.Port != 0 || cfg.Database.Name != "" {
		t.Fatalf("unselected PostgreSQL fields were decoded: %+v", cfg.Database)
	}
}

func TestLoadRejectsLegacyDatabaseDSN(t *testing.T) {
	legacyEnv := "FURTALK_DATABASE_" + "DSN"
	legacyKey := "database." + "dsn"
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv(legacyEnv, "file:legacy.db")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error with valid path and legacy DSN: %v", err)
	}
	if cfg.Database.Path != ":memory:" {
		t.Fatalf("legacy DSN changed database path to %q", cfg.Database.Path)
	}

	t.Setenv("FURTALK_DATABASE_PATH", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "database.path") {
		t.Fatalf("Load() error = %v, want missing database.path; legacy DSN must not be used", err)
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := "database:\n  dialect: sqlite\n  " + legacyKey[strings.IndexByte(legacyKey, '.')+1:] + ": ':memory:'\n"
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", configPath)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), legacyKey[strings.IndexByte(legacyKey, '.')+1:]) {
		t.Fatalf("Load() error = %v, want unknown legacy database key", err)
	}
}

func TestLoadRejectsMissingRequiredEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_TOKENS_JWT_ISSUER", "")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "tokens.jwt_issuer") {
		t.Fatalf("Load() error = %v, want missing tokens.jwt_issuer", err)
	}
}

func TestLoadWarnsOnMissingRecommendedFields(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	got := make(map[string]bool)
	for _, w := range c.Warnings() {
		if w.Key == "" || w.Default == nil {
			t.Fatalf("warning %+v must carry a key and a default", w)
		}
		got[w.Key] = true
	}
	want := []string{
		"http.address",
		"http.trusted_proxies",
		"http.shutdown_timeout",
		"http.read_header_timeout",
		"http.read_timeout",
		"http.write_timeout",
		"http.idle_timeout",
		"http.max_header_bytes",
		"http.body_limit",
		"http.rate_limit_rate",
		"http.rate_limit_burst",
		"tokens.jwt_lifetime",
		"tokens.widget_jwt_lifetime",
		"webauthn.rp_name",
		"oauth.client_timeout",
	}
	if len(got) != len(want) {
		t.Fatalf("warnings = %v, want %v", c.Warnings(), want)
	}
	for _, key := range want {
		if !got[key] {
			t.Errorf("missing warning for %s in %v", key, c.Warnings())
		}
	}
	if _, ok := got["cache.redis_url"]; ok {
		t.Error("optional cache.redis_url must not warn")
	}
	if c.HTTP.Address != ":8080" || c.OAuth.ClientTimeout != defaultOAuthTimeout {
		t.Fatalf("defaults not applied: %+v / %+v", c.HTTP.Address, c.OAuth.ClientTimeout)
	}
}

func TestLoadNoWarningWhenRecommendedExplicitInFile(t *testing.T) {
	clearConfigEnvironment(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
http:
  address: ":8080"
  public_base_url: "https://furtalk.example.com"
  trusted_proxies: []
  shutdown_timeout: "10s"
  read_header_timeout: "5s"
  read_timeout: "15s"
  write_timeout: "60s"
  idle_timeout: "60s"
  max_header_bytes: 65536
  body_limit: 1048576
  rate_limit_rate: 10
  rate_limit_burst: 100
database:
  dialect: sqlite
  path: ":memory:"
tokens:
  jwt_issuer: "https://furtalk.example.com"
  jwt_algorithm: HS256
  jwt_key: "` + strings.Repeat("j", 32) + `"
  jwt_lifetime: "168h"
  widget_jwt_lifetime: "24h"
  secret_key: "` + strings.Repeat("s", 32) + `"
webauthn:
  rp_id: "furtalk.example.com"
  rp_origins:
    - "https://furtalk.example.com"
  rp_name: "Furtalk"
oauth:
  client_timeout: "10s"
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FURTALK_CONFIG", configPath)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if warnings := c.Warnings(); len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none when every recommended field is explicit", warnings)
	}
}

func TestLoadNoWarningWhenExplicitValueEqualsDefault(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_HTTP_ADDRESS", ":8080")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	for _, w := range c.Warnings() {
		if w.Key == "http.address" {
			t.Fatalf("explicit value equal to default must not warn: %+v", w)
		}
	}
}

func TestLoadSMTPWarningsConditionalOnHost(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	for _, w := range c.Warnings() {
		switch w.Key {
		case "smtp.port", "smtp.tls", "smtp.timeout":
			t.Fatalf("disabled SMTP must not warn for %s: %+v", w.Key, w)
		}
	}

	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)
	t.Setenv("FURTALK_SMTP_HOST", "smtp.example.com")
	t.Setenv("FURTALK_SMTP_FROM", "noreply@example.com")

	c, err = Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	got := make(map[string]bool)
	for _, w := range c.Warnings() {
		got[w.Key] = true
	}
	for _, key := range []string{"smtp.port", "smtp.tls", "smtp.timeout"} {
		if !got[key] {
			t.Errorf("SMTP enabled but missing %s must warn: %v", key, c.Warnings())
		}
	}
}

func TestWarningsReturnsImmutableSnapshot(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("FURTALK_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	setValidEnvironment(t)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	warnings := c.Warnings()
	if len(warnings) == 0 {
		t.Fatal("expected warnings from env-only deployment")
	}
	warnings[0].Key = "mutated"
	if got := c.Warnings(); got[0].Key == "mutated" {
		t.Fatal("Warnings() must return a snapshot that does not leak mutation")
	}
}

func setValidEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("FURTALK_HTTP_PUBLIC_BASE_URL", "https://furtalk.example.com")
	t.Setenv("FURTALK_DATABASE_DIALECT", "sqlite")
	t.Setenv("FURTALK_DATABASE_PATH", ":memory:")
	t.Setenv("FURTALK_TOKENS_JWT_ISSUER", "https://furtalk.example.com")
	t.Setenv("FURTALK_TOKENS_JWT_ALGORITHM", "HS256")
	t.Setenv("FURTALK_TOKENS_JWT_KEY", strings.Repeat("j", 32))
	t.Setenv("FURTALK_TOKENS_SECRET_KEY", strings.Repeat("s", 32))
	t.Setenv("FURTALK_WEBAUTHN_RP_ID", "furtalk.example.com")
	t.Setenv("FURTALK_WEBAUTHN_RP_ORIGINS", "https://furtalk.example.com")
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	keys := []string{
		"FURTALK_CONFIG",
		"FURTALK_HTTP_ADDRESS",
		"FURTALK_HTTP_PUBLIC_BASE_URL",
		"FURTALK_HTTP_TRUSTED_PROXIES",
		"FURTALK_HTTP_SHUTDOWN_TIMEOUT",
		"FURTALK_HTTP_READ_HEADER_TIMEOUT",
		"FURTALK_HTTP_READ_TIMEOUT",
		"FURTALK_HTTP_WRITE_TIMEOUT",
		"FURTALK_HTTP_IDLE_TIMEOUT",
		"FURTALK_HTTP_MAX_HEADER_BYTES",
		"FURTALK_HTTP_BODY_LIMIT",
		"FURTALK_HTTP_RATE_LIMIT_RATE",
		"FURTALK_HTTP_RATE_LIMIT_BURST",
		"FURTALK_DATABASE_DIALECT",
		"FURTALK_DATABASE_PATH",
		"FURTALK_DATABASE_HOST",
		"FURTALK_DATABASE_PORT",
		"FURTALK_DATABASE_NAME",
		"FURTALK_DATABASE_USER",
		"FURTALK_DATABASE_PASSWORD",
		"FURTALK_DATABASE_SSL_MODE",
		"FURTALK_CACHE_REDIS_URL",
		"FURTALK_TOKENS_JWT_ISSUER",
		"FURTALK_TOKENS_JWT_ALGORITHM",
		"FURTALK_TOKENS_JWT_KEY",
		"FURTALK_TOKENS_JWT_LIFETIME",
		"FURTALK_TOKENS_WIDGET_JWT_LIFETIME",
		"FURTALK_TOKENS_SECRET_KEY",
		"FURTALK_WEBAUTHN_RP_ID",
		"FURTALK_WEBAUTHN_RP_ORIGINS",
		"FURTALK_WEBAUTHN_RP_NAME",
		"FURTALK_OAUTH_CLIENT_TIMEOUT",
		"FURTALK_SMTP_HOST",
		"FURTALK_SMTP_PORT",
		"FURTALK_SMTP_FROM",
		"FURTALK_SMTP_TLS",
		"FURTALK_SMTP_USERNAME",
		"FURTALK_SMTP_PASSWORD",
		"FURTALK_SMTP_TIMEOUT",
		"FURTALK_LOGGING_FORMAT",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
}

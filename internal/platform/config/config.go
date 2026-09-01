// Package config 加载并校验静态配置。
// 配置来源按优先级排列：环境变量（FURTALK_ 前缀）、可选配置文件、内置默认值。
package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const envPrefix = "FURTALK"

// Config 是静态配置的不可变快照，按功能拆分为嵌套 section。
// 每个 platform 构造器只接收自己需要的 section，不接触整份配置。
// warnings 由 Load 收集，程序化构造的配置不含告警记录。
type Config struct {
	HTTP     HTTPConfig     `mapstructure:"http"`
	Database DatabaseConfig `mapstructure:"database"`
	Cache    CacheConfig    `mapstructure:"cache"`
	Tokens   TokensConfig   `mapstructure:"tokens"`
	WebAuthn WebAuthnConfig `mapstructure:"webauthn"`
	OAuth    OAuthConfig    `mapstructure:"oauth"`
	SMTP     SMTPConfig     `mapstructure:"smtp"`
	Logging  LoggingConfig  `mapstructure:"logging"`

	warnings []Warning
}

// HTTPConfig 承载监听、公开地址、代理、请求体限制与限流等 HTTP 服务参数。
type HTTPConfig struct {
	Address           string        `mapstructure:"address"`
	PublicBaseURL     string        `mapstructure:"public_base_url"`
	TrustedProxies    []string      `mapstructure:"trusted_proxies"`
	ShutdownTimeout   time.Duration `mapstructure:"shutdown_timeout"`
	ReadHeaderTimeout time.Duration `mapstructure:"read_header_timeout"`
	ReadTimeout       time.Duration `mapstructure:"read_timeout"`
	WriteTimeout      time.Duration `mapstructure:"write_timeout"`
	IdleTimeout       time.Duration `mapstructure:"idle_timeout"`
	MaxHeaderBytes    int           `mapstructure:"max_header_bytes"`
	BodyLimit         int64         `mapstructure:"body_limit"`
	RateLimitRate     float64       `mapstructure:"rate_limit_rate"`
	RateLimitBurst    int           `mapstructure:"rate_limit_burst"`
}

// DatabaseConfig 承载按方言拆分的数据库连接字段。
type DatabaseConfig struct {
	Dialect  string `mapstructure:"dialect"`
	Path     string `mapstructure:"path"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Name     string `mapstructure:"name"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// CacheConfig 承载临时存储后端连接（Redis）。空 URL 表示进程内内存存储。
type CacheConfig struct {
	RedisURL string `mapstructure:"redis_url"`
}

// TokensConfig 承载 JWT 签发/验签参数与 provider 机密加密主密钥。
// JWTKey 与 SecretKey 都只接受配置提供的原始文本，按原始 UTF-8 字节参与校验。
type TokensConfig struct {
	JWTIssuer         string        `mapstructure:"jwt_issuer"`
	JWTAlgorithm      string        `mapstructure:"jwt_algorithm"`
	JWTKey            string        `mapstructure:"jwt_key"`
	JWTLifetime       time.Duration `mapstructure:"jwt_lifetime"`
	WidgetJWTLifetime time.Duration `mapstructure:"widget_jwt_lifetime"`
	SecretKey         string        `mapstructure:"secret_key"`
}

// WebAuthnConfig 承载 WebAuthn Relying Party 边界。
type WebAuthnConfig struct {
	RPID      string   `mapstructure:"rp_id"`
	RPOrigins []string `mapstructure:"rp_origins"`
	RPName    string   `mapstructure:"rp_name"`
}

// OAuthConfig 承载 OAuth/OIDC provider 客户端超时。
type OAuthConfig struct {
	ClientTimeout time.Duration `mapstructure:"client_timeout"`
}

// SMTPConfig 承载静态 SMTP 投递配置。
type SMTPConfig struct {
	Host     string        `mapstructure:"host"`
	Port     int           `mapstructure:"port"`
	From     string        `mapstructure:"from"`
	TLS      string        `mapstructure:"tls"`
	Username string        `mapstructure:"username"`
	Password string        `mapstructure:"password"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// LoggingConfig 承载后端日志输出格式选择。
// Format 只接受小写 "json" 或 "text"；缺省 text，机器采集需显式选择 json。
type LoggingConfig struct {
	Format string `mapstructure:"format"`
}

// Load 从嵌套环境变量、可选配置文件与内置默认值加载静态配置，
// 并调用 Validate 校验。任一来源的值非法时返回错误。
// 缺失必需字段时校验失败；建议字段缺失时收集告警随配置返回。
func Load() (Config, error) {
	v, err := newViper()
	if err != nil {
		return Config{}, err
	}

	// 先按方言屏蔽未选中的连接字段，避免例如 SQLite 部署因遗留的
	// PostgreSQL 端口环境变量类型错误而无法解码。未选中字段仍由
	// UnmarshalExact 识别未知键；这里只清除已知但不适用的字段值。
	ignoreUnselectedDatabaseFields(v)

	var c Config
	if err := v.UnmarshalExact(&c, viper.DecodeHook(configDecodeHook())); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	c.warnings = c.collectRecommendedWarnings(configFileKeys(v.ConfigFileUsed()))
	return c, nil
}

func ignoreUnselectedDatabaseFields(v *viper.Viper) {
	ignored := map[string]any{}
	switch strings.TrimSpace(v.GetString("database.dialect")) {
	case "sqlite":
		ignored = map[string]any{
			"database.host":     "",
			"database.port":     0,
			"database.name":     "",
			"database.user":     "",
			"database.password": "",
			"database.ssl_mode": "",
		}
	case "postgres":
		ignored = map[string]any{"database.path": ""}
	default:
		ignored = map[string]any{
			"database.path":     "",
			"database.host":     "",
			"database.port":     0,
			"database.name":     "",
			"database.user":     "",
			"database.password": "",
			"database.ssl_mode": "",
		}
	}
	for key, value := range ignored {
		v.Set(key, value)
	}
}

// 建议配置的默认值。集中声明使 Load 的默认注入与缺失告警共享同一数值。
const (
	defaultRateLimitRate     = 10
	defaultRateLimitBurst    = 100
	defaultShutdownTimeout   = 10 * time.Second
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 60 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultMaxHeaderBytes    = 64 << 10
	defaultBodyLimit         = int64(1 << 20)
	defaultJWTLifetime       = 7 * 24 * time.Hour
	defaultWidgetLifetime    = 24 * time.Hour
	defaultOAuthTimeout      = 10 * time.Second
	maxOAuthClientTimeout    = 60 * time.Second
	defaultSMTPPort          = 587
	defaultSMTPTimeout       = 30 * time.Second
	defaultLoggingFormat     = "text"
)

// recommendedDefault 描述一个建议配置项的 Viper 键与其安全默认值。
// onlyWithSMTPHost 为 true 时仅当 SMTP 启用才参与缺失告警。
// silent 为 true 时只注入默认值，不产生缺失告警（如 logging.format 的 text 缺省）。
type recommendedDefault struct {
	key              string
	def              any
	onlyWithSMTPHost bool
	silent           bool
}

// recommendedDefaults 是建议配置的唯一默认值来源表：configureDefaults 用它
// 注入默认值，Load 用它收集缺失告警，默认值只在表内声明一次而保持一致。
var recommendedDefaults = []recommendedDefault{
	{key: "http.address", def: ":8080"},
	{key: "http.trusted_proxies", def: []string{}},
	{key: "http.shutdown_timeout", def: defaultShutdownTimeout},
	{key: "http.read_header_timeout", def: defaultReadHeaderTimeout},
	{key: "http.read_timeout", def: defaultReadTimeout},
	{key: "http.write_timeout", def: defaultWriteTimeout},
	{key: "http.idle_timeout", def: defaultIdleTimeout},
	{key: "http.max_header_bytes", def: defaultMaxHeaderBytes},
	{key: "http.body_limit", def: defaultBodyLimit},
	{key: "http.rate_limit_rate", def: defaultRateLimitRate},
	{key: "http.rate_limit_burst", def: defaultRateLimitBurst},
	{key: "tokens.jwt_algorithm", def: "HS256"},
	{key: "tokens.jwt_lifetime", def: defaultJWTLifetime},
	{key: "tokens.widget_jwt_lifetime", def: defaultWidgetLifetime},
	{key: "webauthn.rp_name", def: "Furtalk"},
	{key: "oauth.client_timeout", def: defaultOAuthTimeout},
	{key: "smtp.port", def: defaultSMTPPort, onlyWithSMTPHost: true},
	{key: "smtp.tls", def: "starttls", onlyWithSMTPHost: true},
	{key: "smtp.timeout", def: defaultSMTPTimeout, onlyWithSMTPHost: true},
	{key: "logging.format", def: defaultLoggingFormat, silent: true},
}

// requiredConfigFields 是启动必须显式提供的字段；缺失或空值时阻止应用启动。
var requiredConfigFields = []struct {
	key   string
	value func(c Config) string
}{
	{key: "http.public_base_url", value: func(c Config) string { return c.HTTP.PublicBaseURL }},
	{key: "database.dialect", value: func(c Config) string { return c.Database.Dialect }},
	{key: "tokens.jwt_issuer", value: func(c Config) string { return c.Tokens.JWTIssuer }},
	{key: "tokens.jwt_key", value: func(c Config) string { return c.Tokens.JWTKey }},
	{key: "tokens.secret_key", value: func(c Config) string { return c.Tokens.SecretKey }},
	{key: "webauthn.rp_id", value: func(c Config) string { return c.WebAuthn.RPID }},
}

// Warning 描述一个因缺失而采用内置默认值的建议配置项。
type Warning struct {
	Key     string
	Default any
}

// Warnings 返回建议配置缺失告警的快照；副本的修改不影响内部记录。
func (c Config) Warnings() []Warning {
	return append([]Warning(nil), c.warnings...)
}

// collectRecommendedWarnings 依据环境变量与配置文件的存在性收集缺失告警。
// 非空环境变量或文件声明即为显式提供；显式值等于默认值不告警。
func (c Config) collectRecommendedWarnings(fileKeys map[string]bool) []Warning {
	smtpEnabled := strings.TrimSpace(c.SMTP.Host) != ""
	var warnings []Warning
	for _, d := range recommendedDefaults {
		if d.onlyWithSMTPHost && !smtpEnabled {
			continue
		}
		if d.silent {
			continue
		}
		if isExplicitlyConfigured(fileKeys, d.key) {
			continue
		}
		warnings = append(warnings, Warning{Key: d.key, Default: d.def})
	}
	return warnings
}

// isExplicitlyConfigured 判断配置项是否由非空环境变量或配置文件显式提供。
func isExplicitlyConfigured(fileKeys map[string]bool, key string) bool {
	if val, ok := os.LookupEnv(envNameForKey(key)); ok && strings.TrimSpace(val) != "" {
		return true
	}
	return fileKeys[key]
}

// envNameForKey 按 FURTALK_<SECTION>_<FIELD> 规则生成配置键对应的环境变量名。
func envNameForKey(key string) string {
	return envPrefix + "_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// configFileKeys 返回配置文件实际声明的扁平键集合，不包含默认值与环境变量。
// 文件缺失或读取失败时返回 nil，与纯环境变量部署一致。
func configFileKeys(path string) map[string]bool {
	if path == "" {
		return nil
	}
	raw := viper.New()
	raw.SetConfigFile(path)
	if err := raw.ReadInConfig(); err != nil {
		return nil
	}
	keys := make(map[string]bool, len(raw.AllKeys()))
	for _, key := range raw.AllKeys() {
		keys[key] = true
	}
	return keys
}

// checkRequired 校验必需静态配置字段是否显式提供；RP origins 为空切片视为缺失。
func (c Config) checkRequired() error {
	for _, f := range requiredConfigFields {
		if strings.TrimSpace(f.value(c)) == "" {
			return fmt.Errorf("missing required configuration: %s", f.key)
		}
	}
	switch c.Database.Dialect {
	case "sqlite":
		if strings.TrimSpace(c.Database.Path) == "" {
			return fmt.Errorf("missing required configuration: database.path")
		}
	case "postgres":
		for _, field := range []struct {
			key   string
			value string
		}{
			{key: "database.host", value: c.Database.Host},
			{key: "database.name", value: c.Database.Name},
			{key: "database.user", value: c.Database.User},
			{key: "database.password", value: c.Database.Password},
			{key: "database.ssl_mode", value: c.Database.SSLMode},
		} {
			if strings.TrimSpace(field.value) == "" {
				return fmt.Errorf("missing required configuration: %s", field.key)
			}
		}
		if c.Database.Port == 0 {
			return fmt.Errorf("missing required configuration: database.port")
		}
	}
	if len(c.WebAuthn.RPOrigins) == 0 {
		return fmt.Errorf("missing required configuration: webauthn.rp_origins")
	}
	return nil
}

// Validate 校验各 section 的静态配置并返回首个错误。
// 必需字段在格式/范围校验之前检查，缺失时直接返回字段错误。
func (c Config) Validate() error {
	if err := c.checkRequired(); err != nil {
		return err
	}
	if strings.TrimSpace(c.HTTP.Address) == "" {
		return errors.New("address must not be empty")
	}
	for name, value := range map[string]string{"public base URL": c.HTTP.PublicBaseURL, "JWT issuer": c.Tokens.JWTIssuer} {
		u, err := url.Parse(value)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("%s must be an absolute URL without path, query, or fragment", name)
		}
	}
	if len(c.Tokens.JWTKey) < 32 {
		return errors.New("JWT key must contain at least 32 raw bytes")
	}
	if len(c.Tokens.SecretKey) < 32 {
		return errors.New("secret key must contain at least 32 raw bytes")
	}
	if c.Database.Dialect != "sqlite" && c.Database.Dialect != "postgres" {
		return errors.New("database dialect must be sqlite or postgres")
	}
	if c.Database.Dialect == "postgres" {
		if c.Database.Port < 1 || c.Database.Port > 65535 {
			return errors.New("database port must be between 1 and 65535")
		}
		switch c.Database.SSLMode {
		case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		default:
			return fmt.Errorf("database ssl_mode must be disable, allow, prefer, require, verify-ca or verify-full, got %q", c.Database.SSLMode)
		}
	}
	if c.Tokens.JWTAlgorithm != "HS256" {
		return errors.New("JWT algorithm must be HS256")
	}
	if c.Logging.Format != "" && c.Logging.Format != "json" && c.Logging.Format != "text" {
		return fmt.Errorf("logging.format must be json or text, got %q", c.Logging.Format)
	}
	if c.HTTP.ShutdownTimeout <= 0 {
		return errors.New("shutdown timeout must be positive")
	}
	if c.HTTP.ReadHeaderTimeout <= 0 {
		return errors.New("read header timeout must be positive")
	}
	if c.HTTP.ReadTimeout <= 0 {
		return errors.New("read timeout must be positive")
	}
	if c.HTTP.WriteTimeout <= 0 {
		return errors.New("write timeout must be positive")
	}
	if c.HTTP.IdleTimeout <= 0 {
		return errors.New("idle timeout must be positive")
	}
	if c.HTTP.MaxHeaderBytes <= 0 {
		return errors.New("max header bytes must be positive")
	}
	if c.Tokens.JWTLifetime <= 0 {
		return errors.New("JWT lifetime must be positive")
	}
	if c.Tokens.WidgetJWTLifetime <= 0 {
		return errors.New("widget JWT lifetime must be positive")
	}
	if c.OAuth.ClientTimeout <= 0 {
		return errors.New("oauth client timeout must be positive")
	}
	if c.OAuth.ClientTimeout > maxOAuthClientTimeout {
		return errors.New("oauth client timeout must not exceed 60s")
	}
	if c.HTTP.BodyLimit <= 0 {
		return errors.New("body limit must be positive")
	}
	if c.HTTP.RateLimitRate <= 0 {
		return errors.New("rate limit rate must be positive")
	}
	if c.HTTP.RateLimitBurst <= 0 {
		return errors.New("rate limit burst must be positive")
	}
	for _, proxy := range c.HTTP.TrustedProxies {
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			return fmt.Errorf("trusted proxy %q must be a CIDR", proxy)
		}
	}
	rpid := strings.TrimSpace(c.WebAuthn.RPID)
	if err := validateRPID(rpid); err != nil {
		return err
	}
	if len(c.WebAuthn.RPOrigins) == 0 {
		return errors.New("passkey rp origins must not be empty")
	}
	for _, origin := range c.WebAuthn.RPOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("passkey rp origin %q must be an absolute URL without path, query, or fragment", origin)
		}
	}
	if strings.TrimSpace(c.SMTP.Host) != "" {
		if c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
			return errors.New("smtp port must be between 1 and 65535")
		}
		switch c.SMTP.TLS {
		case "starttls", "tls", "none":
		default:
			return fmt.Errorf("smtp tls must be starttls, tls or none, got %q", c.SMTP.TLS)
		}
		if _, err := mail.ParseAddress(c.SMTP.From); err != nil {
			return errors.New("smtp from must be a valid email address")
		}
		if c.SMTP.Timeout <= 0 {
			return errors.New("smtp timeout must be positive")
		}
	}
	return nil
}

// validateRPID 接受 DNS 主机名或 IP 字面量，不含 scheme、方括号、路径或端口。
// IPv6 冒号属于地址语法，net.ParseIP 识别完整值后即为合法。
func validateRPID(value string) error {
	rpid := strings.TrimSpace(value)
	if rpid == "" {
		return errors.New("passkey rp id must not be empty")
	}
	if rpid != value || strings.ContainsAny(rpid, "/?#@[]") {
		return fmt.Errorf("passkey rp id %q must be a hostname or IP literal without scheme, brackets, path, or port", value)
	}
	if net.ParseIP(rpid) != nil {
		return nil
	}
	if strings.Contains(rpid, ":") || !validHostname(rpid) {
		return fmt.Errorf("passkey rp id %q must be a valid hostname or IP literal without a port", value)
	}
	return nil
}

func validHostname(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

// newViper 构建独立 viper 实例。
// 配置文件可选：从 configs/ 自动发现 config.yaml / config.toml / config.json，
// 也可用 FURTALK_CONFIG 显式指定路径；文件缺失时静默跳过（兼容纯 env 部署）。
// 优先级：env（FURTALK_ 前缀）> 配置文件 > 默认值。
func newViper() (*viper.Viper, error) {
	v := viper.NewWithOptions(viper.ExperimentalBindStruct())
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	configureDefaults(v)
	if path := os.Getenv("FURTALK_CONFIG"); path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath("configs")
	}
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) || os.IsNotExist(err) {
			return v, nil
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return v, nil
}

func configureDefaults(v *viper.Viper) {
	for _, d := range recommendedDefaults {
		v.SetDefault(d.key, d.def)
	}
}

func configDecodeHook() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		stringToTrimmedSliceHook(),
	)
}

func stringToTrimmedSliceHook() mapstructure.DecodeHookFunc {
	return func(from, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.String || to.Kind() != reflect.Slice || to.Elem().Kind() != reflect.String {
			return data, nil
		}
		parts := strings.Split(data.(string), ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				result = append(result, part)
			}
		}
		return result, nil
	}
}

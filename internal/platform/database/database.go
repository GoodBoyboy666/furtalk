// Package database 管理数据库连接、SQLite WAL 与 SQLite 连接校验。
// 表结构由外部 Atlas Versioned migration 管理，应用进程不做任何 schema 变更。
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// SQLite 连接参数
const (
	sqliteBusyTimeoutMS = 5000
	sqlitePragmas       = "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
)

// Config 数据库连接需要的全部静态配置。
type Config struct {
	Dialect  string
	Path     string
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string
}

// NewDatabase 按配置的连接打开数据库，为 SQLite 启用 WAL 并校验 SQLite pragma。
func NewDatabase(cfg Config) (*gorm.DB, error) {
	db, err := Connect(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Dialect == "sqlite" {
		if err := SetWAL(db); err != nil {
			return nil, err
		}
		if err := CheckSQLite(db); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// Connect 按配置的连接信息打开数据库并返回 *gorm.DB。
func Connect(cfg Config) (*gorm.DB, error) {
	switch cfg.Dialect {
	case "sqlite":
		if strings.TrimSpace(cfg.Path) == "" {
			return nil, errors.New("database path must not be empty for sqlite")
		}
		db, err := gorm.Open(sqlite.Open(sqliteDSN(cfg.Path)), gormConfig())
		if err != nil {
			return nil, fmt.Errorf("open sqlite database: %w", err)
		}
		return db, nil
	case "postgres":
		dsn, err := PostgresURL(cfg)
		if err != nil {
			return nil, err
		}
		db, err := gorm.Open(postgres.New(postgres.Config{
			DSN:                  dsn,
			PreferSimpleProtocol: true,
		}), gormConfig())
		if err != nil {
			return nil, fmt.Errorf("open postgres database: %w", err)
		}
		return db, nil
	default:
		return nil, fmt.Errorf("unsupported database dialect %q", cfg.Dialect)
	}
}

// sqliteDSN 在用户提供的路径上追加每连接生效的 SQLite pragma。
func sqliteDSN(path string) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + strings.TrimPrefix(sqlitePragmas, "?")
}

// PostgresURL 根据拆分的连接字段生成 pgx/GORM 使用的 PostgreSQL URL。
func PostgresURL(cfg Config) (string, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return "", errors.New("database host must not be empty for postgres")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return "", errors.New("database port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.Name) == "" {
		return "", errors.New("database name must not be empty for postgres")
	}
	if strings.TrimSpace(cfg.User) == "" {
		return "", errors.New("database user must not be empty for postgres")
	}
	if strings.TrimSpace(cfg.Password) == "" {
		return "", errors.New("database password must not be empty for postgres")
	}
	if !validSSLMode(cfg.SSLMode) {
		return "", fmt.Errorf("database ssl_mode is invalid: %q", cfg.SSLMode)
	}

	host := strings.TrimSpace(cfg.Host)
	// 接受常见的带方括号 IPv6 配置形式，并按 JoinHostPort 要求保留单层括号。
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}

	databasePath := "/" + cfg.Name
	escapedPath := "/" + url.PathEscape(cfg.Name)
	dsnURL := &url.URL{
		Scheme: "postgres",
		Host:   net.JoinHostPort(host, strconv.Itoa(cfg.Port)),
		User:   url.UserPassword(cfg.User, cfg.Password),
		Path:   databasePath,
	}
	if escapedPath != databasePath {
		dsnURL.RawPath = escapedPath
	}
	query := url.Values{}
	query.Set("search_path", "public")
	query.Set("sslmode", cfg.SSLMode)
	dsnURL.RawQuery = query.Encode()
	return dsnURL.String(), nil
}

// validSSLMode 判断 SSL 模式是否受支持。
func validSSLMode(mode string) bool {
	switch mode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		return true
	default:
		return false
	}
}

// gormConfig 构建统一的 GORM 配置。
func gormConfig() *gorm.Config {
	return &gorm.Config{
		NowFunc: func() time.Time { return time.Now().UTC() },
	}
}

// AutoMigrate 为给定的 models 创建或更新表结构。
func AutoMigrate(db *gorm.DB, models ...any) error {
	if err := db.AutoMigrate(models...); err != nil {
		return fmt.Errorf("auto migrate schema: %w", err)
	}
	return nil
}

// CheckSQLite 抽查 SQLite 连接的 pragma 与日志模式。
func CheckSQLite(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("access sqlite connection pool: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < 5; i++ {
		if err := checkSQLiteConn(ctx, sqlDB); err != nil {
			return fmt.Errorf("sqlite pool check connection %d: %w", i, err)
		}
	}
	return nil
}

// checkSQLiteConn 校验单个 SQLite 连接的关键 pragma。
func checkSQLiteConn(ctx context.Context, sqlDB *sql.DB) error {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire dedicated connection: %w", err)
	}
	defer conn.Close()

	var foreignKeys int
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fmt.Errorf("read foreign_keys pragma: %w", err)
	}
	if foreignKeys != 1 {
		return fmt.Errorf("foreign_keys pragma is %d, want 1", foreignKeys)
	}

	var busyTimeout int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		return fmt.Errorf("read busy_timeout pragma: %w", err)
	}
	if busyTimeout <= 0 {
		return fmt.Errorf("busy_timeout pragma is %d, want > 0", busyTimeout)
	}

	var journalMode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("read journal_mode pragma: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("journal_mode is %q, want wal", journalMode)
	}
	return nil
}

// SetWAL 在 SQLite 数据库上启用 WAL 日志模式。
func SetWAL(db *gorm.DB) error {
	if err := db.Exec("PRAGMA journal_mode = WAL").Error; err != nil {
		return fmt.Errorf("enable WAL journal mode: %w", err)
	}
	return nil
}

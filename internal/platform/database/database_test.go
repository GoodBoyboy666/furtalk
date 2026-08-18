package database

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestNewDatabaseNoTables 验证生产数据库装配不创建任何业务表。
// schema 由外部 Atlas Versioned migration 管理，应用进程只连接已迁移的数据库；
// 该测试锁定"启动建库绝不建表"的边界，AutoMigrate 不得回归生产装配。
func TestNewDatabaseNoTables(t *testing.T) {
	// 用文件库而非 :memory:，因为 WAL 模式需要持久化文件，与生产路径一致。
	path := filepath.Join(t.TempDir(), "furtalk.db")
	db, err := NewDatabase(Config{Dialect: "sqlite", Path: path})
	if err != nil {
		t.Fatalf("NewDatabase: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	rows, err := sqlDB.Query("SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate tables: %v", err)
	}
	for _, name := range tables {
		switch name {
		case "sqlite_sequence":
		default:
			t.Errorf("生产装配创建了业务表 %q，schema 应由外部 Atlas migration 管理", name)
		}
	}
}

// TestAutoMigrateStillWorks 验证测试专用 AutoMigrate 仍然可用，供隔离测试库搭建。
func TestAutoMigrateStillWorks(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"+sqlitePragmas), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := AutoMigrate(db, &testRow{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	var count int64
	if err := db.Table("test_rows").Count(&count).Error; err != nil {
		t.Fatalf("count test_rows: %v", err)
	}
}

func TestPostgresURLEscapesConnectionFields(t *testing.T) {
	cfg := Config{
		Dialect:  "postgres",
		Host:     "db.example.com",
		Port:     5432,
		Name:     "comments/prod?blue",
		User:     "reporting:user",
		Password: "p@ss/w?&=word",
		SSLMode:  "verify-full",
	}

	got, err := PostgresURL(cfg)
	if err != nil {
		t.Fatalf("PostgresURL: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse generated URL: %v", err)
	}
	if parsed.Scheme != "postgres" || parsed.Host != "db.example.com:5432" {
		t.Fatalf("URL scheme/host = %q://%q", parsed.Scheme, parsed.Host)
	}
	if parsed.Path != "/comments/prod?blue" {
		t.Fatalf("decoded database path = %q", parsed.Path)
	}
	if parsed.EscapedPath() != "/comments%2Fprod%3Fblue" {
		t.Fatalf("escaped database path = %q", parsed.EscapedPath())
	}
	if parsed.User.Username() != cfg.User {
		t.Fatalf("decoded username = %q, want %q", parsed.User.Username(), cfg.User)
	}
	password, ok := parsed.User.Password()
	if !ok || password != cfg.Password {
		t.Fatalf("decoded password = %q, want %q", password, cfg.Password)
	}
	if parsed.Query().Get("search_path") != "public" || parsed.Query().Get("sslmode") != cfg.SSLMode {
		t.Fatalf("query = %v", parsed.Query())
	}
	if strings.Contains(got, cfg.Password) || strings.Contains(got, cfg.User) {
		t.Fatalf("generated URL contains unescaped credential text: %q", got)
	}
}

func TestPostgresURLSupportsIPv6AndBracketedIPv6(t *testing.T) {
	for _, host := range []string{"2001:db8::1", "[2001:db8::1]"} {
		t.Run(host, func(t *testing.T) {
			got, err := PostgresURL(Config{
				Dialect:  "postgres",
				Host:     host,
				Port:     5432,
				Name:     "furtalk",
				User:     "user",
				Password: "password",
				SSLMode:  "require",
			})
			if err != nil {
				t.Fatalf("PostgresURL: %v", err)
			}
			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatalf("parse generated URL: %v", err)
			}
			if parsed.Hostname() != "2001:db8::1" || parsed.Port() != "5432" {
				t.Fatalf("host/port = %q/%q", parsed.Hostname(), parsed.Port())
			}
		})
	}
}

func TestPostgresURLRejectsInvalidFields(t *testing.T) {
	base := Config{
		Dialect:  "postgres",
		Host:     "localhost",
		Port:     5432,
		Name:     "furtalk",
		User:     "user",
		Password: "password",
		SSLMode:  "require",
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "host", mutate: func(c *Config) { c.Host = "" }},
		{name: "port", mutate: func(c *Config) { c.Port = 0 }},
		{name: "name", mutate: func(c *Config) { c.Name = "" }},
		{name: "user", mutate: func(c *Config) { c.User = "" }},
		{name: "password", mutate: func(c *Config) { c.Password = "" }},
		{name: "ssl mode", mutate: func(c *Config) { c.SSLMode = "invalid" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if _, err := PostgresURL(cfg); err == nil {
				t.Fatal("PostgresURL accepted invalid configuration")
			} else if strings.Contains(err.Error(), cfg.Password) && cfg.Password != "" {
				t.Fatalf("PostgresURL error leaked the password: %v", err)
			}
		})
	}
}

func TestSQLiteDSNAppendsPragmasToPathAndURI(t *testing.T) {
	for _, path := range []string{"/tmp/furtalk.db", "file:test?mode=memory"} {
		t.Run(path, func(t *testing.T) {
			got := sqliteDSN(path)
			if !strings.Contains(got, "_pragma=foreign_keys(1)") || !strings.Contains(got, "_pragma=busy_timeout(5000)") {
				t.Fatalf("sqlite DSN = %q, missing required pragmas", got)
			}
			if strings.Count(got, "?") != 1 {
				t.Fatalf("sqlite DSN = %q, expected one query delimiter", got)
			}
		})
	}
}

// testRow 是 AutoMigrate 冒烟测试用的最小行。
type testRow struct {
	ID   int64  `gorm:"primaryKey;autoIncrement"`
	Name string `gorm:"column:name"`
}

func (testRow) TableName() string { return "test_rows" }

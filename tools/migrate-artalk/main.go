// Tool migrate-artalk imports an Artalk Artrans export into Furtalk.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
)

type config struct {
	input           string
	execute         bool
	targetSiteID    int64
	defaultSiteURL  string
	sourceTimezone  string
	ipMode          string
	uaMode          string
	databaseDialect string
	databasePath    string
	databaseHost    string
	databasePort    int
	databaseName    string
	databaseUser    string
	databasePass    string
	databaseSSLMode string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "迁移失败:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	location, err := time.LoadLocation(cfg.sourceTimezone)
	if err != nil {
		return fmt.Errorf("加载源时区 %q: %w", cfg.sourceTimezone, err)
	}
	input, closeInput, err := openInput(cfg.input)
	if err != nil {
		return err
	}
	defer closeInput()
	records, err := Parse(input)
	if err != nil {
		return err
	}

	dbCfg := database.Config{
		Dialect:  cfg.databaseDialect,
		Path:     cfg.databasePath,
		Host:     cfg.databaseHost,
		Port:     cfg.databasePort,
		Name:     cfg.databaseName,
		User:     cfg.databaseUser,
		Password: cfg.databasePass,
		SSLMode:  cfg.databaseSSLMode,
	}
	db, err := database.NewDatabase(dbCfg)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("访问目标数据库连接: %w", err)
	}
	defer sqlDB.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	importer := NewImporter(
		gormtx.NewRunner(db),
		repository.NewUserRepo(db),
		repository.NewSiteRepo(db),
		repository.NewThreadRepo(db),
		repository.NewCommentRepo(db),
	)
	report, err := importer.Import(ctx, records, Options{
		TargetSiteID:   cfg.targetSiteID,
		DefaultSiteURL: cfg.defaultSiteURL,
		SourceLocation: location,
		IPMode:         domain.PrivacyMode(cfg.ipMode),
		UAMode:         domain.PrivacyMode(cfg.uaMode),
		DryRun:         !cfg.execute,
	})
	if err != nil {
		return err
	}
	printReport(report)
	if !cfg.execute {
		fmt.Println("dry-run 已完成：所有目标数据库写入均已回滚；确认报告后加 --execute 正式迁移。")
	} else {
		fmt.Println("迁移事务已提交。")
	}
	return nil
}

func parseFlags(args []string) (config, error) {
	var cfg config
	set := flag.NewFlagSet("migrate-artalk", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	set.StringVar(&cfg.input, "input", "", "Artalk .artrans/.json/.gz 文件路径；- 表示标准输入")
	set.BoolVar(&cfg.execute, "execute", false, "正式提交迁移；缺省仅做 dry-run 并回滚")
	set.Int64Var(&cfg.targetSiteID, "target-site-id", 0, "把全部源站点导入指定的现有 Furtalk site ID")
	set.StringVar(&cfg.defaultSiteURL, "default-site-url", "", "源数据缺少可用站点 URL 时使用的 HTTPS origin")
	set.StringVar(&cfg.sourceTimezone, "source-timezone", "UTC", "无 UTC offset 的旧版时间所使用的 IANA 时区")
	set.StringVar(&cfg.ipMode, "ip-mode", "full", "IP 迁移模式：none、coarse 或 full")
	set.StringVar(&cfg.uaMode, "ua-mode", "full", "User-Agent 迁移模式：none、coarse 或 full")
	set.StringVar(&cfg.databaseDialect, "target-dialect", env("FURTALK_DATABASE_DIALECT"), "目标数据库方言：sqlite 或 postgres")
	set.StringVar(&cfg.databasePath, "target-path", env("FURTALK_DATABASE_PATH"), "目标 SQLite 数据库路径")
	set.StringVar(&cfg.databaseHost, "target-host", env("FURTALK_DATABASE_HOST"), "目标 PostgreSQL 主机")
	set.IntVar(&cfg.databasePort, "target-port", envInt("FURTALK_DATABASE_PORT"), "目标 PostgreSQL 端口")
	set.StringVar(&cfg.databaseName, "target-name", env("FURTALK_DATABASE_NAME"), "目标 PostgreSQL 数据库名")
	set.StringVar(&cfg.databaseUser, "target-user", env("FURTALK_DATABASE_USER"), "目标 PostgreSQL 用户")
	set.StringVar(&cfg.databasePass, "target-password", env("FURTALK_DATABASE_PASSWORD"), "目标 PostgreSQL 密码（推荐通过环境变量提供）")
	set.StringVar(&cfg.databaseSSLMode, "target-ssl-mode", env("FURTALK_DATABASE_SSL_MODE"), "目标 PostgreSQL SSL mode")
	set.Usage = func() {
		fmt.Fprintln(set.Output(), "用法: go run ./tools/migrate-artalk --input artalk.artrans [选项]")
		fmt.Fprintln(set.Output(), "默认执行完整 dry-run；只有指定 --execute 才会提交。")
		set.PrintDefaults()
	}
	if err := set.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.input == "" && set.NArg() == 1 {
		cfg.input = set.Arg(0)
	}
	if cfg.input == "" {
		return cfg, errors.New("必须提供 --input")
	}
	if set.NArg() > 1 || (set.NArg() == 1 && cfg.input != set.Arg(0)) {
		return cfg, errors.New("存在无法识别的位置参数")
	}
	if cfg.databaseDialect != "sqlite" && cfg.databaseDialect != "postgres" {
		return cfg, errors.New("--target-dialect 必须是 sqlite 或 postgres")
	}
	if cfg.databaseDialect == "sqlite" && strings.TrimSpace(cfg.databasePath) == "" {
		return cfg, errors.New("SQLite 目标必须提供 --target-path 或 FURTALK_DATABASE_PATH")
	}
	if cfg.databaseDialect == "sqlite" && !strings.HasPrefix(cfg.databasePath, "file:") && cfg.databasePath != ":memory:" {
		if info, err := os.Stat(cfg.databasePath); err != nil {
			return cfg, fmt.Errorf("目标 SQLite 数据库不可访问: %w", err)
		} else if info.IsDir() {
			return cfg, errors.New("目标 SQLite 路径是目录，不是数据库文件")
		}
	}
	if !validPrivacyMode(domain.PrivacyMode(cfg.ipMode)) {
		return cfg, errors.New("--ip-mode 必须是 none、coarse 或 full")
	}
	if !validPrivacyMode(domain.PrivacyMode(cfg.uaMode)) {
		return cfg, errors.New("--ua-mode 必须是 none、coarse 或 full")
	}
	return cfg, nil
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("打开 Artrans 文件: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}

func env(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func envInt(key string) int {
	value := env(key)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func printReport(report Report) {
	mode := "正式执行"
	if report.DryRun {
		mode = "dry-run"
	}
	fmt.Printf("Artalk → Furtalk 迁移报告（%s）\n", mode)
	fmt.Printf("  评论: 输入 %d，导入 %d（已发布 %d，待审核 %d）\n", report.InputComments, report.ImportedComments, report.PublishedComments, report.PendingComments)
	fmt.Printf("  用户: 新建 %d，复用 %d，合成邮箱 %d，无效网站 %d\n", report.CreatedUsers, report.ReusedUsers, report.SyntheticEmails, report.InvalidWebsites)
	fmt.Printf("  站点: 新建 %d，复用 %d；页面: 新建 %d，复用 %d\n", report.CreatedSites, report.ReusedSites, report.CreatedThreads, report.ReusedThreads)
	fmt.Printf("  隐私字段: 省略 IP %d，无效 IP %d，省略 UA %d\n", report.OmittedIPs, report.InvalidIPs, report.OmittedUAs)
	ignored := report.IgnoredCollapsed + report.IgnoredPinned + report.IgnoredVotes + report.IgnoredBadges + report.IgnoredPagePolicies
	if ignored > 0 {
		fmt.Printf("  无对应目标字段: 折叠 %d，置顶 %d，投票 %d，徽章 %d，页面仅管理员 %d\n", report.IgnoredCollapsed, report.IgnoredPinned, report.IgnoredVotes, report.IgnoredBadges, report.IgnoredPagePolicies)
	}
}

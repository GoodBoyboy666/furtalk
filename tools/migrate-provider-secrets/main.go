// Command migrate-provider-secrets converts provider secret envelopes from v1
// (raw 32-byte key) to v2 (HKDF-derived AES-256 key).
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

	crypto "furtalk/internal/platform/crypto"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
)

const legacyEnvelopeVersion byte = 1

var errDryRunRollback = errors.New("dry-run rollback")

type config struct {
	execute         bool
	databaseDialect string
	databasePath    string
	databaseHost    string
	databasePort    int
	databaseName    string
	databaseUser    string
	databasePass    string
	databaseSSLMode string
	newRawKey       []byte
	legacyRawKey    []byte
}

type KindReport struct {
	Scanned   int
	Converted int
	Current   int
	NoSecret  int
}

type Report struct {
	ByKind map[string]KindReport
	DryRun bool
}

type providerRecord struct {
	key        string
	version    int
	nonce      []byte
	ciphertext []byte
	update     func(context.Context, int, []byte, []byte) error
}

type converter struct {
	repo       *repository.SettingsRepo
	legacyKey  []byte
	currentKey []byte
}

var kindOrder = []string{"captcha", "auth", "spam", "notification"}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "provider secret migration failed:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	cfg, err := parseFlags(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	db, err := database.NewDatabase(database.Config{
		Dialect:  cfg.databaseDialect,
		Path:     cfg.databasePath,
		Host:     cfg.databaseHost,
		Port:     cfg.databasePort,
		Name:     cfg.databaseName,
		User:     cfg.databaseUser,
		Password: cfg.databasePass,
		SSLMode:  cfg.databaseSSLMode,
	})
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("access target database: %w", err)
	}
	defer sqlDB.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	report, err := migrate(ctx, gormtx.NewRunner(db), repository.NewSettingsRepo(db), cfg.legacyRawKey, cfg.newRawKey, cfg.execute)
	if err != nil {
		return err
	}
	if err := printReport(stdout, report); err != nil {
		return err
	}
	if report.DryRun {
		_, err = fmt.Fprintln(stdout, "dry-run completed: all database writes were rolled back; rerun with --execute after review.")
	} else {
		_, err = fmt.Fprintln(stdout, "provider secret migration committed.")
	}
	return err
}

func parseFlags(args []string) (config, error) {
	var cfg config
	set := flag.NewFlagSet("migrate-provider-secrets", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.BoolVar(&cfg.execute, "execute", false, "commit the conversion; default is a complete dry-run")
	set.StringVar(&cfg.databaseDialect, "target-dialect", env("FURTALK_DATABASE_DIALECT"), "target database dialect: sqlite or postgres")
	set.StringVar(&cfg.databasePath, "target-path", env("FURTALK_DATABASE_PATH"), "target SQLite database path")
	set.StringVar(&cfg.databaseHost, "target-host", env("FURTALK_DATABASE_HOST"), "target PostgreSQL host")
	set.IntVar(&cfg.databasePort, "target-port", envInt("FURTALK_DATABASE_PORT"), "target PostgreSQL port")
	set.StringVar(&cfg.databaseName, "target-name", env("FURTALK_DATABASE_NAME"), "target PostgreSQL database name")
	set.StringVar(&cfg.databaseUser, "target-user", env("FURTALK_DATABASE_USER"), "target PostgreSQL user")
	set.StringVar(&cfg.databasePass, "target-password", env("FURTALK_DATABASE_PASSWORD"), "target PostgreSQL password")
	set.StringVar(&cfg.databaseSSLMode, "target-ssl-mode", env("FURTALK_DATABASE_SSL_MODE"), "target PostgreSQL SSL mode")
	set.Usage = func() {
		fmt.Fprintln(set.Output(), "usage: migrate-provider-secrets [options]")
		fmt.Fprintln(set.Output(), "provider keys are read only from FURTALK_TOKENS_SECRET_KEY and FURTALK_TOKENS_LEGACY_SECRET_KEY.")
		set.PrintDefaults()
	}
	if err := set.Parse(args); err != nil {
		return cfg, err
	}
	if set.NArg() != 0 {
		return cfg, errors.New("positional arguments are not supported")
	}
	if cfg.databaseDialect != "sqlite" && cfg.databaseDialect != "postgres" {
		return cfg, errors.New("target dialect must be sqlite or postgres")
	}
	if cfg.databaseDialect == "sqlite" && strings.TrimSpace(cfg.databasePath) == "" {
		return cfg, errors.New("SQLite target requires --target-path or FURTALK_DATABASE_PATH")
	}
	if cfg.databaseDialect == "sqlite" && !strings.HasPrefix(cfg.databasePath, "file:") && cfg.databasePath != ":memory:" {
		info, err := os.Stat(cfg.databasePath)
		if err != nil {
			return cfg, errors.New("target SQLite database is not accessible")
		}
		if info.IsDir() {
			return cfg, errors.New("target SQLite path is a directory")
		}
	}
	if cfg.databaseDialect == "postgres" {
		if _, err := database.PostgresURL(database.Config{
			Dialect: cfg.databaseDialect, Host: cfg.databaseHost, Port: cfg.databasePort,
			Name: cfg.databaseName, User: cfg.databaseUser, Password: cfg.databasePass,
			SSLMode: cfg.databaseSSLMode,
		}); err != nil {
			return cfg, errors.New("invalid PostgreSQL target configuration")
		}
	}

	newRaw := []byte(env("FURTALK_TOKENS_SECRET_KEY"))
	if len(newRaw) < 32 {
		return cfg, errors.New("FURTALK_TOKENS_SECRET_KEY must contain at least 32 bytes")
	}
	legacyRaw := []byte(env("FURTALK_TOKENS_LEGACY_SECRET_KEY"))
	if len(legacyRaw) == 0 {
		if len(newRaw) != 32 {
			return cfg, errors.New("FURTALK_TOKENS_LEGACY_SECRET_KEY is required unless the new key is exactly 32 bytes")
		}
		legacyRaw = append([]byte(nil), newRaw...)
	}
	if len(legacyRaw) != 32 {
		return cfg, errors.New("FURTALK_TOKENS_LEGACY_SECRET_KEY must contain exactly 32 bytes")
	}
	cfg.newRawKey = newRaw
	cfg.legacyRawKey = legacyRaw
	return cfg, nil
}

func migrate(ctx context.Context, runner *gormtx.Runner, repo *repository.SettingsRepo, legacyRaw, newRaw []byte, execute bool) (Report, error) {
	legacyKey := append([]byte(nil), legacyRaw...)
	currentKey, err := crypto.DeriveProviderKey(newRaw)
	if err != nil {
		return Report{}, err
	}
	c := &converter{repo: repo, legacyKey: legacyKey, currentKey: currentKey}
	var report Report
	err = runner.RunInTx(ctx, func(txCtx context.Context) error {
		var convertErr error
		report, convertErr = c.convert(txCtx)
		if convertErr != nil {
			return convertErr
		}
		if !execute {
			return errDryRunRollback
		}
		return nil
	})
	if errors.Is(err, errDryRunRollback) {
		report.DryRun = true
		return report, nil
	}
	if err != nil {
		return Report{}, err
	}
	return report, nil
}

func (c *converter) convert(ctx context.Context) (Report, error) {
	report := Report{ByKind: make(map[string]KindReport, len(kindOrder))}
	captchaRows, err := c.repo.ListCaptchaProviders(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("scan captcha providers: %w", err)
	}
	captchaRecords := make([]providerRecord, 0, len(captchaRows))
	for _, row := range captchaRows {
		row := row
		captchaRecords = append(captchaRecords, providerRecord{
			key: row.ProviderKey, version: row.SecretKeyVersion, nonce: row.SecretNonce, ciphertext: row.SecretCiphertext,
			update: func(ctx context.Context, version int, nonce, ciphertext []byte) error {
				row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext = version, nonce, ciphertext
				return c.repo.UpsertCaptchaProvider(ctx, &row)
			},
		})
	}
	if report.ByKind["captcha"], err = c.convertRecords(ctx, "captcha", captchaRecords); err != nil {
		return Report{}, err
	}

	authRows, err := c.repo.ListAuthProviders(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("scan auth providers: %w", err)
	}
	authRecords := make([]providerRecord, 0, len(authRows))
	for _, row := range authRows {
		row := row
		authRecords = append(authRecords, providerRecord{
			key: row.ProviderKey, version: row.SecretKeyVersion, nonce: row.SecretNonce, ciphertext: row.SecretCiphertext,
			update: func(ctx context.Context, version int, nonce, ciphertext []byte) error {
				row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext = version, nonce, ciphertext
				return c.repo.UpsertAuthProvider(ctx, &row)
			},
		})
	}
	if report.ByKind["auth"], err = c.convertRecords(ctx, "auth", authRecords); err != nil {
		return Report{}, err
	}

	spamRows, err := c.repo.ListSpamProviders(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("scan spam providers: %w", err)
	}
	spamRecords := make([]providerRecord, 0, len(spamRows))
	for _, row := range spamRows {
		row := row
		spamRecords = append(spamRecords, providerRecord{
			key: row.ProviderKey, version: row.SecretKeyVersion, nonce: row.SecretNonce, ciphertext: row.SecretCiphertext,
			update: func(ctx context.Context, version int, nonce, ciphertext []byte) error {
				row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext = version, nonce, ciphertext
				return c.repo.UpsertSpamProvider(ctx, &row)
			},
		})
	}
	if report.ByKind["spam"], err = c.convertRecords(ctx, "spam", spamRecords); err != nil {
		return Report{}, err
	}

	notificationRows, err := c.repo.ListNotificationProviders(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("scan notification providers: %w", err)
	}
	notificationRecords := make([]providerRecord, 0, len(notificationRows))
	for _, row := range notificationRows {
		row := row
		notificationRecords = append(notificationRecords, providerRecord{
			key: row.ProviderKey, version: row.SecretKeyVersion, nonce: row.SecretNonce, ciphertext: row.SecretCiphertext,
			update: func(ctx context.Context, version int, nonce, ciphertext []byte) error {
				row.SecretKeyVersion, row.SecretNonce, row.SecretCiphertext = version, nonce, ciphertext
				return c.repo.UpsertNotificationProvider(ctx, &row)
			},
		})
	}
	if report.ByKind["notification"], err = c.convertRecords(ctx, "notification", notificationRecords); err != nil {
		return Report{}, err
	}
	return report, nil
}

func (c *converter) convertRecords(ctx context.Context, kind string, records []providerRecord) (KindReport, error) {
	var report KindReport
	for _, record := range records {
		report.Scanned++
		if len(record.ciphertext) == 0 {
			report.NoSecret++
			continue
		}
		switch record.version {
		case int(legacyEnvelopeVersion):
			plaintext, err := cryptoxDecrypt(c.legacyKey, legacyEnvelopeVersion, record.nonce, record.ciphertext)
			if err != nil {
				return KindReport{}, fmt.Errorf("convert %s provider %q: legacy envelope is unreadable", kind, record.key)
			}
			envelope, err := crypto.Encrypt(c.currentKey, crypto.ProviderEnvelopeVersion, plaintext)
			if err != nil {
				return KindReport{}, fmt.Errorf("convert %s provider %q: encrypt current envelope: %w", kind, record.key, err)
			}
			if err := record.update(ctx, int(crypto.ProviderEnvelopeVersion), append([]byte(nil), envelope[1:13]...), append([]byte(nil), envelope[13:]...)); err != nil {
				return KindReport{}, fmt.Errorf("convert %s provider %q: write current envelope: %w", kind, record.key, err)
			}
			report.Converted++
		case int(crypto.ProviderEnvelopeVersion):
			if _, err := cryptoxDecrypt(c.currentKey, crypto.ProviderEnvelopeVersion, record.nonce, record.ciphertext); err != nil {
				return KindReport{}, fmt.Errorf("validate %s provider %q: current envelope is unreadable", kind, record.key)
			}
			report.Current++
		default:
			return KindReport{}, fmt.Errorf("convert %s provider %q: unsupported envelope version", kind, record.key)
		}
	}
	return report, nil
}

func cryptoxDecrypt(key []byte, version byte, nonce, ciphertext []byte) ([]byte, error) {
	envelope := make([]byte, 0, 1+len(nonce)+len(ciphertext))
	envelope = append(envelope, version)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)
	return crypto.Decrypt(key, version, envelope)
}

func printReport(w io.Writer, report Report) error {
	mode := "execute"
	if report.DryRun {
		mode = "dry-run"
	}
	if _, err := fmt.Fprintf(w, "provider secret migration report (%s)\n", mode); err != nil {
		return err
	}
	for _, kind := range kindOrder {
		counts := report.ByKind[kind]
		if _, err := fmt.Fprintf(w, "  %s: scanned %d, converted %d, current %d, no_secret %d\n", kind, counts.Scanned, counts.Converted, counts.Current, counts.NoSecret); err != nil {
			return err
		}
	}
	return nil
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

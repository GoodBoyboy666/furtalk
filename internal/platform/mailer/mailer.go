// Package mailer 实现轻量的 SMTP/MIME 投递客户端，对外暴露 Mailer 接口。
// 支持隐式 TLS、显式 STARTTLS 与明文连接、 MIME text/HTML 正文，以及每次发送的 context 与超时。
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/wneessen/go-mail"
)

var (
	// ErrUnavailable 投递或连通性探针无法到达 SMTP 服务器。
	ErrUnavailable = errors.New("mailer: smtp server unavailable")
	// ErrConfig SMTP 配置无效。
	ErrConfig = errors.New("mailer: invalid smtp configuration")
)

// SMTPConfig 静态 SMTP 投递配置。
// TLS 选择传输方式："tls"（隐式 TLS）、"starttls"（显式 STARTTLS）或 "none"。
// 设置 TLSConfig 会覆盖客户端的 TLS 配置；生产环境保持 nil，执行正常的证书验证。
type SMTPConfig struct {
	Host      string
	Port      int
	From      string
	TLS       string
	Username  string
	Password  string
	Timeout   time.Duration
	TLSConfig *tls.Config
}

// Message 一封 MIME 邮件。From 为空时回退到 SMTP 配置中的 From；
// TextBody 与 HTMLBody 至少设置一个。
type Message struct {
	From     string
	To       string
	Subject  string
	TextBody string
	HTMLBody string
}

// Mailer 投递一封邮件。
// 实现可在多次发送间安全复用；每次 Send 在使用方的 context 上建立连接、投递并关闭。
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// NewProvider 根据静态 SMTP 配置组装 SMTP 邮件发送器。
// 未设置 host 时返回 nil，notification 消费方变为惰性（尽力而为，不投递）；
// host 已设置但配置非法时启动报错。
func NewProvider(smtpConfig SMTPConfig) (Mailer, error) {
	if smtpConfig.Host == "" {
		return nil, nil
	}
	m, err := NewSMTP(smtpConfig)
	if err != nil {
		return nil, fmt.Errorf("new smtp mailer: %w", err)
	}
	return m, nil
}

// NewSMTP 为给定配置构建基于 go-mail 的 Mailer。
func NewSMTP(cfg SMTPConfig) (Mailer, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("%w: host is required", ErrConfig)
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("%w: invalid port %d", ErrConfig, cfg.Port)
	}
	opts := []mail.Option{
		mail.WithPort(cfg.Port),
	}
	if cfg.Timeout > 0 {
		opts = append(opts, mail.WithTimeout(cfg.Timeout))
	}
	switch cfg.TLS {
	case "tls":
		opts = append(opts, mail.WithSSL(), mail.WithTLSPolicy(mail.NoTLS))
	case "starttls", "":
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default:
		return nil, fmt.Errorf("%w: unsupported tls mode %q", ErrConfig, cfg.TLS)
	}
	if cfg.TLSConfig != nil {
		opts = append(opts, mail.WithTLSConfig(cfg.TLSConfig))
	}
	if cfg.Username != "" {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthPlain), mail.WithUsername(cfg.Username), mail.WithPassword(cfg.Password))
	}
	client, err := mail.NewClient(cfg.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	return &smtpMailer{cfg: cfg, client: client}, nil
}

type smtpMailer struct {
	cfg    SMTPConfig
	client *mail.Client
}

// Send 组装 MIME 邮件并通过 SMTP 投递。
// 收件人、发件人或正文缺失时返回 ErrConfig，投递失败返回 ErrUnavailable。
func (m *smtpMailer) Send(ctx context.Context, msg Message) error {
	to := msg.To
	if to == "" {
		return fmt.Errorf("%w: recipient is required", ErrConfig)
	}
	from := msg.From
	if from == "" {
		from = m.cfg.From
	}
	if msg.TextBody == "" && msg.HTMLBody == "" {
		return fmt.Errorf("%w: message body is empty", ErrConfig)
	}
	gm := mail.NewMsg()
	if err := gm.From(from); err != nil {
		return fmt.Errorf("%w: from %q: %v", ErrConfig, from, err)
	}
	if err := gm.To(to); err != nil {
		return fmt.Errorf("%w: to %q: %v", ErrConfig, to, err)
	}
	gm.Subject(msg.Subject)
	if msg.TextBody != "" {
		gm.SetBodyString(mail.TypeTextPlain, msg.TextBody)
	}
	if msg.HTMLBody != "" {
		gm.AddAlternativeString(mail.TypeTextHTML, msg.HTMLBody)
	}
	if err := m.client.DialAndSendWithContext(ctx, gm); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// Probe 执行连通性检查：连接 SMTP 服务器，执行配置的 TLS/STARTTLS 握手并发送 EHLO，
// 不会发送任何邮件。
func Probe(ctx context.Context, cfg SMTPConfig) error {
	m, err := NewSMTP(cfg)
	if err != nil {
		return err
	}
	probe := m.(*smtpMailer)
	if err := probe.client.DialWithContext(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return probe.client.Close()
}

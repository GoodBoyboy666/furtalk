// 文件型 HTML 邮件模板的加载与渲染。
// 模板使用 Go 标准库 html/template 解析，随上下文自动转义动态值；
// 应用启动时一次读取并解析全部模板，运行期不重新读取、不监听目录。
package mailer

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
)

// TemplateKind 标识邮件模板场景，同时决定 configs/email 下的模板文件名。
type TemplateKind string

const (
	// KindLoginCode 是登录验证码邮件模板。
	KindLoginCode TemplateKind = "login_code"
	// KindPasswordResetCode 是密码重置验证码邮件模板。
	KindPasswordResetCode TemplateKind = "password_reset_code"
	// KindModeration 是新评论/待审核通知邮件模板。
	KindModeration TemplateKind = "moderation"
	// KindPublished 是评论发布通知邮件模板。
	KindPublished TemplateKind = "published"
	// KindReply 是评论回复通知邮件模板。
	KindReply TemplateKind = "reply"
)

// 模板文件扩展名。
const templateSuffix = ".html"

// LoginCodeData 是登录验证码模板的变量契约。
type LoginCodeData struct {
	Code             string
	ExpiresInMinutes int
}

// PasswordResetCodeData 是密码重置验证码模板的变量契约。
type PasswordResetCodeData struct {
	Code             string
	ExpiresInMinutes int
}

// ModerationData 是审核通知模板的变量契约。
// PageTitle 与 PageURL 是评论所属页面的元数据；PageURL 为空时不渲染链接。
type ModerationData struct {
	AuthorNickname     string
	CommentBody        string
	AwaitingModeration bool
	PageTitle          string
	PageURL            string
}

// PublishedData 是评论发布通知模板的变量契约。
// UnsubscribeURL 必须是渲染前生成的完整签名退订链接，只用于 href 上下文。
type PublishedData struct {
	AuthorNickname string
	CommentBody    string
	UnsubscribeURL string
}

// ReplyData 是评论回复通知模板的变量契约。
// UnsubscribeURL 必须是渲染前生成的完整签名退订链接，只用于 href 上下文。
// PageTitle 与 PageURL 是回复所属页面的元数据；PageURL 为空时不渲染链接。
type ReplyData struct {
	ReplyAuthorNickname  string
	ParentAuthorNickname string
	ReplyBody            string
	ParentCommentBody    string
	UnsubscribeURL       string
	PageTitle            string
	PageURL              string
}

// TemplateRenderer 渲染各场景的 HTML 邮件正文。
// 所有动态值以普通字符串传入，html/template 负责上下文自动转义；
// 禁止传入 template.HTML 等绕过转义的类型。
type TemplateRenderer interface {
	LoginCode(LoginCodeData) (string, error)
	PasswordResetCode(PasswordResetCodeData) (string, error)
	Moderation(ModerationData) (string, error)
	Published(PublishedData) (string, error)
	Reply(ReplyData) (string, error)
}

// TemplateSet 是启动期解析并冻结的只读模板集合。
// 运行期安全并发使用；模板内容在进程生命周期内保持不变。
type TemplateSet struct {
	loginCode         *template.Template
	passwordResetCode *template.Template
	moderation        *template.Template
	published         *template.Template
	reply             *template.Template
}

// LoadTemplates 读取并解析目录下的全部五个邮件模板。
// 固定文件清单由 TemplateKind 决定；每个模板解析后使用零值数据执行一次，
// 提前发现引用不存在结构字段的错误。
// 任一文件缺失、不可读、解析失败或字段校验失败，都返回包含模板 kind
// 与完整文件路径的错误，调用方应将其视为启动错误。
func LoadTemplates(dir string) (*TemplateSet, error) {
	set := &TemplateSet{}
	specs := []struct {
		kind TemplateKind
		dst  **template.Template
		zero func() any
	}{
		{KindLoginCode, &set.loginCode, func() any { return LoginCodeData{} }},
		{KindPasswordResetCode, &set.passwordResetCode, func() any { return PasswordResetCodeData{} }},
		{KindModeration, &set.moderation, func() any { return ModerationData{} }},
		{KindPublished, &set.published, func() any { return PublishedData{} }},
		{KindReply, &set.reply, func() any { return ReplyData{} }},
	}
	for _, spec := range specs {
		path := filepath.Join(dir, string(spec.kind)+templateSuffix)
		t, err := parseTemplateFile(path, spec.zero())
		if err != nil {
			return nil, err
		}
		*spec.dst = t
	}
	return set, nil
}

// parseTemplateFile 读取单个模板文件，解析并执行零值数据校验。
func parseTemplateFile(path string, zero any) (*template.Template, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load email template %s: %w", path, err)
	}
	t, err := template.New(filepath.Base(path)).Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("parse email template %s: %w", path, err)
	}
	if err := t.Execute(io.Discard, zero); err != nil {
		return nil, fmt.Errorf("validate email template %s: %w", path, err)
	}
	return t, nil
}

// LoginCode 渲染登录验证码邮件正文。
func (s *TemplateSet) LoginCode(d LoginCodeData) (string, error) {
	return renderTemplate(s.loginCode, d)
}

// PasswordResetCode 渲染密码重置验证码邮件正文。
func (s *TemplateSet) PasswordResetCode(d PasswordResetCodeData) (string, error) {
	return renderTemplate(s.passwordResetCode, d)
}

// Moderation 渲染新评论/待审核通知邮件正文。
func (s *TemplateSet) Moderation(d ModerationData) (string, error) {
	return renderTemplate(s.moderation, d)
}

// Published 渲染评论发布通知邮件正文。
func (s *TemplateSet) Published(d PublishedData) (string, error) {
	return renderTemplate(s.published, d)
}

// Reply 渲染评论回复通知邮件正文。
func (s *TemplateSet) Reply(d ReplyData) (string, error) {
	return renderTemplate(s.reply, d)
}

// renderTemplate 把数据渲染进单个模板并返回完整 HTML。
func renderTemplate(t *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

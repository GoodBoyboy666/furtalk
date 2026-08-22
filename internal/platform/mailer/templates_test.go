package mailer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTemplate 在临时目录写入一个模板文件，返回其绝对路径。
func writeTemplate(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write template %s: %v", name, err)
	}
	return path
}

// TestLoadTemplatesLoadsAllFive 证明五个模板全部加载成功且可渲染零值数据。
func TestLoadTemplatesLoadsAllFive(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		kind TemplateKind
		body string
	}{
		{KindLoginCode, "{{.Code}}/{{.ExpiresInMinutes}}"},
		{KindPasswordResetCode, "{{.Code}}/{{.ExpiresInMinutes}}"},
		{KindModeration, "{{.AuthorNickname}}/{{.CommentBody}}/{{.AwaitingModeration}}"},
		{KindPublished, "{{.AuthorNickname}}/{{.CommentBody}}"},
		{KindReply, "{{.ReplyAuthorNickname}}/{{.ParentAuthorNickname}}/{{.ReplyBody}}/{{.ParentCommentBody}}/{{.UnsubscribeURL}}"},
	} {
		writeTemplate(t, dir, string(tc.kind)+templateSuffix, tc.body)
	}

	set, err := LoadTemplates(dir)
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	if set == nil {
		t.Fatal("LoadTemplates returned nil set")
	}
}

// TestLoadTemplatesMissingFile 证明缺少任一模板文件时启动失败并指出文件。
func TestLoadTemplatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	specs := map[TemplateKind]string{
		KindLoginCode:         "{{.Code}}",
		KindPasswordResetCode: "{{.Code}}",
		KindModeration:        "{{.AuthorNickname}}",
		KindPublished:         "{{.AuthorNickname}}",
	}
	for kind, body := range specs {
		writeTemplate(t, dir, string(kind)+templateSuffix, body)
	}

	_, err := LoadTemplates(dir)
	if err == nil {
		t.Fatal("LoadTemplates must fail when a file is missing")
	}
	if !strings.Contains(err.Error(), "reply.html") {
		t.Fatalf("error must name the missing file, got: %v", err)
	}
}

// TestLoadTemplatesInvalidSyntax 证明语法错误的模板使启动失败。
func TestLoadTemplatesInvalidSyntax(t *testing.T) {
	dir := t.TempDir()
	specs := map[TemplateKind]string{
		KindLoginCode:         "{{.Code}}",
		KindPasswordResetCode: "{{.Code}}",
		KindModeration:        "{{.AuthorNickname}}",
		KindPublished:         "{{.AuthorNickname}}",
		KindReply:             "{{.ReplyBody}}",
	}
	for kind, body := range specs {
		writeTemplate(t, dir, string(kind)+templateSuffix, body)
	}
	writeTemplate(t, dir, "reply.html", "{{.ReplyBody")

	if _, err := LoadTemplates(dir); err == nil {
		t.Fatal("LoadTemplates must fail on invalid template syntax")
	}
}

// TestLoadTemplatesUnknownField 证明引用不存在字段的模板使启动失败。
func TestLoadTemplatesUnknownField(t *testing.T) {
	dir := t.TempDir()
	specs := map[TemplateKind]string{
		KindLoginCode:         "{{.Code}}",
		KindPasswordResetCode: "{{.Code}}",
		KindModeration:        "{{.AuthorNickname}}",
		KindPublished:         "{{.AuthorNickname}}",
		KindReply:             "{{.ReplyBody}}",
	}
	for kind, body := range specs {
		writeTemplate(t, dir, string(kind)+templateSuffix, body)
	}
	writeTemplate(t, dir, "login_code.html", "{{.Nope}}")

	if _, err := LoadTemplates(dir); err == nil {
		t.Fatal("LoadTemplates must fail when a template references an unknown field")
	}
}

// TestTemplateRenderersEscapeHTML 证明渲染自动转义正文中的 HTML 敏感字符。
func TestTemplateRenderersEscapeHTML(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "moderation.html", "<a href=\"{{.PageURL}}\">{{.PageTitle}}</a><div>{{.CommentBody}}</div>")
	writeTemplate(t, dir, "published.html", "<div>{{.CommentBody}}</div>")
	writeTemplate(t, dir, "reply.html", "<a href=\"{{.UnsubscribeURL}}\">{{.ReplyBody}}</a>")
	writeTemplate(t, dir, "login_code.html", "{{.Code}}")
	writeTemplate(t, dir, "password_reset_code.html", "{{.Code}}")

	set, err := LoadTemplates(dir)
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}

	out, err := set.Moderation(ModerationData{
		CommentBody: "<script>alert(1)</script>",
		PageTitle:   `<img src=x onerror=alert(1)>`,
		PageURL:     "https://example.com/post?utm=1&ref=2",
	})
	if err != nil {
		t.Fatalf("Moderation: %v", err)
	}
	if strings.Contains(out, "<script>") {
		t.Fatalf("body must be escaped, got: %s", out)
	}
	if strings.Contains(out, "<img") {
		t.Fatalf("page title must be escaped, got: %s", out)
	}
	if !strings.Contains(out, "&amp;ref=2") || strings.Contains(out, "&ref=2") {
		t.Fatalf("page url query separator must be escaped as &amp;, got: %s", out)
	}

	reply, err := set.Reply(ReplyData{
		ReplyBody:      "<b>hi</b>",
		UnsubscribeURL: "https://example.com/unsubscribe?token=abc&x=1",
	})
	if err != nil {
		t.Fatalf("Reply: %v", err)
	}
	if strings.Contains(reply, "<b>hi</b>") {
		t.Fatalf("reply body must be escaped, got: %s", reply)
	}
	if strings.Contains(reply, "&x=1") {
		t.Fatalf("unsubscribe URL query separator must be escaped as &amp;, got: %s", reply)
	}
	if !strings.Contains(reply, "&amp;x=1") {
		t.Fatalf("expected escaped &amp; in href, got: %s", reply)
	}
}

// TestLoadTemplatesKeepsSubjectOutOfData 证明 Subject 不作为模板数据字段。
func TestLoadTemplatesKeepsSubjectOutOfData(t *testing.T) {
	dir := t.TempDir()
	for _, kind := range []TemplateKind{KindLoginCode, KindPasswordResetCode, KindModeration, KindPublished, KindReply} {
		writeTemplate(t, dir, string(kind)+templateSuffix, "no subject here")
	}
	if _, err := LoadTemplates(dir); err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
}

// findRepoRoot 向上查找包含 configs/email 的仓库根目录，测试运行目录是包目录。
func findRepoRoot(t *testing.T) (string, error) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "configs", "email")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("configs/email not found above " + dir)
		}
		dir = parent
	}
}

// TestDefaultTemplatesAreSimplifiedChinese 证明仓库默认的五个邮件模板可以加载，
// 使用 zh-CN 语言与 Furtalk 品牌色，且渲染出的中文关键文案存在。
func TestDefaultTemplatesAreSimplifiedChinese(t *testing.T) {
	root, err := findRepoRoot(t)
	if err != nil {
		t.Skipf("repo root not found: %v", err)
	}
	set, err := LoadTemplates(filepath.Join(root, "configs", "email"))
	if err != nil {
		t.Fatalf("LoadTemplates(configs/email): %v", err)
	}
	cases := []struct {
		name   string
		render func() (string, error)
	}{
		{string(KindLoginCode), func() (string, error) { return set.LoginCode(LoginCodeData{Code: "123456", ExpiresInMinutes: 10}) }},
		{string(KindPasswordResetCode), func() (string, error) {
			return set.PasswordResetCode(PasswordResetCodeData{Code: "123456", ExpiresInMinutes: 10})
		}},
		{string(KindModeration), func() (string, error) {
			return set.Moderation(ModerationData{AuthorNickname: "作者", CommentBody: "正文", AwaitingModeration: false})
		}},
		{string(KindPublished), func() (string, error) {
			return set.Published(PublishedData{AuthorNickname: "作者", CommentBody: "正文", UnsubscribeURL: "https://example.com/unsubscribe?token=abc"})
		}},
		{string(KindReply), func() (string, error) {
			return set.Reply(ReplyData{ReplyAuthorNickname: "作者", ParentAuthorNickname: "父作者", ReplyBody: "回复", ParentCommentBody: "父正文", UnsubscribeURL: "https://example.com/unsubscribe?token=abc"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.render()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !strings.Contains(out, `lang="zh-CN"`) {
				t.Fatalf("template must declare lang=zh-CN, got: %s", out)
			}
			if !strings.Contains(out, "#2563eb") {
				t.Fatalf("template must use the Furtalk brand color #2563eb, got: %s", out)
			}
			if !strings.ContainsAny(out, "验证码评论发布回复审核密码") {
				t.Fatalf("template must contain Chinese copy, got: %s", out)
			}
		})
	}
}

// TestDefaultTemplatesRenderPageButton 证明 moderation/reply 模板在评论下方
// 渲染指向页面网址的按钮；无 PageURL 时不渲染按钮；待审核邮件显示“查看”，
// 新评论与回复邮件显示“回复”。
func TestDefaultTemplatesRenderPageButton(t *testing.T) {
	root, err := findRepoRoot(t)
	if err != nil {
		t.Skipf("repo root not found: %v", err)
	}
	set, err := LoadTemplates(filepath.Join(root, "configs", "email"))
	if err != nil {
		t.Fatalf("LoadTemplates(configs/email): %v", err)
	}
	url := "https://example.com/post?utm=1"
	button := "padding:10px 22px;border-radius:8px;"

	modAwaiting, err := set.Moderation(ModerationData{AuthorNickname: "a", CommentBody: "b", AwaitingModeration: true, PageURL: url})
	if err != nil {
		t.Fatalf("Moderation(awaiting): %v", err)
	}
	if !strings.Contains(modAwaiting, "查看") || !strings.Contains(modAwaiting, button) || !strings.Contains(modAwaiting, url) {
		t.Fatalf("awaiting moderation must show a 查看 button, got: %s", modAwaiting)
	}

	modNew, err := set.Moderation(ModerationData{AuthorNickname: "a", CommentBody: "b", AwaitingModeration: false, PageURL: url})
	if err != nil {
		t.Fatalf("Moderation(new): %v", err)
	}
	if !strings.Contains(modNew, "回复") || !strings.Contains(modNew, button) {
		t.Fatalf("new comment must show a 回复 button, got: %s", modNew)
	}

	modNoURL, err := set.Moderation(ModerationData{AuthorNickname: "a", CommentBody: "b", AwaitingModeration: false, PageURL: ""})
	if err != nil {
		t.Fatalf("Moderation(no url): %v", err)
	}
	if strings.Contains(modNoURL, button) {
		t.Fatalf("moderation without PageURL must not render the button, got: %s", modNoURL)
	}

	reply, err := set.Reply(ReplyData{ReplyAuthorNickname: "a", ParentAuthorNickname: "p", ReplyBody: "r", PageURL: url})
	if err != nil {
		t.Fatalf("Reply: %v", err)
	}
	if !strings.Contains(reply, "回复") || !strings.Contains(reply, button) || !strings.Contains(reply, url) {
		t.Fatalf("reply must show a 回复 button, got: %s", reply)
	}

	replyNoURL, err := set.Reply(ReplyData{ReplyAuthorNickname: "a", ParentAuthorNickname: "p", ReplyBody: "r", PageURL: ""})
	if err != nil {
		t.Fatalf("Reply(no url): %v", err)
	}
	if strings.Contains(replyNoURL, button) {
		t.Fatalf("reply without PageURL must not render the button, got: %s", replyNoURL)
	}
}

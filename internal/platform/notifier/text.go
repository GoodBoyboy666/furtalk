package notifier

import (
	"strings"
	"unicode/utf8"
)

// TruncateRunes 按 Unicode 标量安全截断到最多 max 个字符并追加省略号。
// 不会在 rune 中间切断；返回值为 true 表示发生了截断。
func TruncateRunes(s string, max int) (string, bool) {
	if utf8.RuneCountInString(s) <= max {
		return s, false
	}
	if max <= 1 {
		return "…", true
	}
	return string([]rune(s)[:max-1]) + "…", true
}

// truncateBytes 按 UTF-8 字节预算安全截断（Bark / APNs 载荷）。
// 逐 rune 累加字节，绝不切分 UTF-8 序列；返回值为 true 表示发生了截断。
func truncateBytes(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		n := utf8.RuneLen(r)
		if count+n > max {
			break
		}
		b.WriteRune(r)
		count += n
	}
	if b.Len() == 0 {
		return "…", true
	}
	return b.String() + "…", true
}

// truncateUTF16 按 UTF-16 code units 截断（LINE 的 5000 单位限制）。
// 超出 BMP 的字符计 2 个单位；逐 rune 累加，绝不切断字符，并为省略号预留 1 个单位。
func truncateUTF16(s string, max int) (string, bool) {
	if utf16Count(s) <= max {
		return s, false
	}
	budget := max - 1
	if budget <= 0 {
		return "…", true
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		n := utf16Len(r)
		if count+n > budget {
			break
		}
		b.WriteRune(r)
		count += n
	}
	if b.Len() == 0 {
		return "…", true
	}
	return b.String() + "…", true
}

// utf16Count 返回字符串按 UTF-16 code units 计数的长度。
func utf16Count(s string) int {
	count := 0
	for _, r := range s {
		count += utf16Len(r)
	}
	return count
}

// utf16Len 返回单个 rune 的 UTF-16 code unit 数。
func utf16Len(r rune) int {
	if r > 0xFFFF {
		return 2
	}
	return 1
}

// breakMentions 在 @ 后插入零宽空格，防止评论内容或作者昵称触发平台 mention。
// 只应作用于用户可控文本（昵称/正文），不要作用于页面 URL。
func breakMentions(s string) string {
	return strings.ReplaceAll(s, "@", "@\u200b")
}

// escapeDiscordMarkdown 转义 Discord Markdown 控制字符，
// 防止用户可控文本改变消息外观或触发格式注入。
func escapeDiscordMarkdown(s string) string {
	const special = "\\`*_~|<>@#"
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(special, r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// composeText 组装平台纯文本：标题 + 正文，并附加页面 URL。
// 标题与正文打断 @ mention；页面 URL 原样保留，长文本截断时为 URL 预留空间，
// 避免页面链接被截断掉。
func composeText(title, text, pageURL string, max int) string {
	head := breakMentions(title) + "\n\n" + breakMentions(text)
	urlBlock := ""
	if pageURL != "" {
		urlBlock = "\n\n" + pageURL
	}
	urlLen := utf8.RuneCountInString(urlBlock)
	if urlLen >= max {
		urlBlock, _ = TruncateRunes(urlBlock, max)
		return urlBlock
	}
	head, _ = TruncateRunes(head, max-urlLen)
	return head + urlBlock
}

// composeTextUTF16 按 UTF-16 code unit 预算组装文本（LINE），同样为页面 URL 预留空间。
func composeTextUTF16(title, text, pageURL string, max int) string {
	head := breakMentions(title) + "\n\n" + breakMentions(text)
	urlBlock := ""
	if pageURL != "" {
		urlBlock = "\n\n" + pageURL
	}
	urlLen := utf16Count(urlBlock)
	if urlLen >= max {
		urlBlock, _ = truncateUTF16(urlBlock, max)
		return urlBlock
	}
	head, _ = truncateUTF16(head, max-urlLen)
	return head + urlBlock
}

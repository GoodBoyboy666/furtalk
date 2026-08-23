// Package spam 提供垃圾检测的基础协议与固定渠道适配：
// 本地关键词库匹配器、Akismet、阿里云内容安全与腾讯云内容安全。
// 该包与业务无关，不依赖 domain、repository、service 或 Gin。
package spam

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Input 是一次垃圾检测的送检上下文。
// 云渠道适配器只消费 Body；完整上下文仅 Akismet 使用。
type Input struct {
	// BlogURL 是站点 CanonicalURL。
	BlogURL string
	// Permalink 是评论所在页面链接。
	Permalink string
	// CommentType 是评论类型，例如 comment。
	CommentType string
	// Body 是评论 Markdown 原文。
	Body string
	// Nickname 是作者昵称。
	Nickname string
	// Email 是作者邮箱。
	Email string
	// AuthorURL 是作者网址。
	AuthorURL string
	// IP 是原始客户端 IP。
	IP string
	// UserAgent 是原始 UA。
	UserAgent string
}

// Result 是单次检测的结果枚举。
type Result uint8

// 检测结果枚举。
const (
	// ResultPass 表示通过，继续下一渠道。
	ResultPass Result = iota
	// ResultReview 表示可疑，映射为 pending。
	ResultReview
	// ResultBlock 表示垃圾，映射为 spam。
	ResultBlock
)

// Detector 是对单个垃圾检测渠道的检查边界。
type Detector interface {
	// Check 返回渠道判定结果；渠道故障或响应未知时返回非 nil 错误，
	// 调用方应把该错误视为 unknown 并继续后续渠道。
	Check(ctx context.Context, input Input) (Result, error)
}

// 错误 sentinel。
var (
	// ErrUnavailable 在渠道故障、超时或返回未知结果时返回，调用方记 unknown 并继续。
	ErrUnavailable = errors.New("spam: detector unavailable")
	// ErrInvalidFile 在词库文件缺失、不可读、非普通文件、非法 UTF-8 或超出限制时返回。
	ErrInvalidFile = errors.New("spam: invalid keyword file")
)

// ValidateKeywordFile 校验词库文件路径指向服务端可读的普通 UTF-8 文件，
// 并在大小与行数限制内完整解析。供保存配置时的首次加载验证使用。
func ValidateKeywordFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: keyword file is not a regular file", ErrInvalidFile)
	}
	_, err = loadKeywordFile(path, fileSignature{size: info.Size(), mtimeNS: info.ModTime().UnixNano()})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	return nil
}

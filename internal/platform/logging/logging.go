// Package logging 是后端唯一的日志基础设施模块。
// 它封装标准库 log/slog 的构造、公共属性、context 关联与敏感信息过滤；
// 上层始终依赖 *slog.Logger，不引入自有 Logger 接口，也不依赖 Fx。
package logging

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"time"
)

// 日志输出格式的规范值，与配置 logging.format 的合法值保持一致。
const (
	FormatText = "text"
	FormatJSON = "json"
)

// New 构建默认 text 格式的 INFO 阈值 logger，并在 handler 前安装敏感属性过滤。
// 正常运行日志写 stdout；配置或 Fx 图创建前的启动失败由调用方选择 stderr。
func New(w io.Writer) *slog.Logger {
	return NewWithFormat(w, FormatText)
}

// NewWithFormat 按显式格式构建 INFO 阈值的 logger。
// json 使用 slog.NewJSONHandler，text（及空值）使用 slog.NewTextHandler；
// 两者共享同一个敏感属性过滤 handler 与全部字段 helper，不分叉规则。
func NewWithFormat(w io.Writer, format string) *slog.Logger {
	var handler slog.Handler
	switch format {
	case FormatJSON:
		handler = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	default:
		handler = slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	return slog.New(newRedactingHandler(handler))
}

// Discard 返回丢弃全部记录的 logger，供可选依赖为空时的确定性兜底。
// 生产 Fx 图始终注入真实 logger；兜底只服务于测试或可选组件。
func Discard() *slog.Logger {
	return slog.New(discardHandler{})
}

// Normalize 把可选的 nil logger 规范化为 discard logger，替代各包直接调用 slog.Default()。
func Normalize(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return Discard()
	}
	return logger
}

// Error 构造固定的 error 属性，保留错误内容用于诊断。
func Error(err error) slog.Attr {
	return slog.Any("error", err)
}

// RequestID 构造固定的 request_id 属性。
func RequestID(requestID string) slog.Attr {
	return slog.String("request_id", requestID)
}

// ID 构造 *_id 十进制字符串属性；业务 ID 在日志中统一表示为字符串。
func ID(key string, id int64) slog.Attr {
	return slog.String(key, strconv.FormatInt(id, 10))
}

// Duration 构造 duration_ms 属性，毫秒数保持 JSON number。
func Duration(d time.Duration) slog.Attr {
	return slog.Int64("duration_ms", d.Milliseconds())
}

// discardHandler 丢弃全部记录；Enabled 返回 false 使调用方直接跳过。
type discardHandler struct{}

// Enabled 始终为 false，使 slog 跳过记录处理。
func (discardHandler) Enabled(context.Context, slog.Level) bool { return false }

// Handle 不会被执行，仅满足 slog.Handler 接口。
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }

// WithAttrs 返回自身。
func (discardHandler) WithAttrs([]slog.Attr) slog.Handler { return discardHandler{} }

// WithGroup 返回自身。
func (discardHandler) WithGroup(string) slog.Handler { return discardHandler{} }

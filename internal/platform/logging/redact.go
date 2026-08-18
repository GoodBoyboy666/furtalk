package logging

import (
	"context"
	"log/slog"
	"strings"
)

// redactedPlaceholder 是敏感属性被过滤后输出的固定占位符。
const redactedPlaceholder = "[REDACTED]"

// setupTokenValue 标记 bootstrap setup token 的唯一受控放行值。
// 只有 SetupToken 构造的值能通过过滤；普通 setup_token 字符串属性仍会被脱敏。
type setupTokenValue string

// LogValue 把受控放行的 setup token 解析为明文字符串。
func (t setupTokenValue) LogValue() slog.Value {
	return slog.StringValue(string(t))
}

// SetupToken 构造唯一受控放行的 setup_token 属性。
// bootstrap 首次引导在启动时输出一次明文 token 是有意通道；
// 其他调用点构造的 setup_token 属性仍会被统一 handler 脱敏。
func SetupToken(raw string) slog.Attr {
	return slog.Any("setup_token", setupTokenValue(raw))
}

// sensitiveSuffixes 是判定敏感属性名的后缀集合。
var sensitiveSuffixes = []string{"_token", "_password", "_secret"}

// sensitiveExact 是判定敏感属性名的完整键集合。
var sensitiveExact = map[string]struct{}{
	"token":         {},
	"password":      {},
	"passwd":        {},
	"secret":        {},
	"jwt":           {},
	"authorization": {},
	"set-cookie":    {},
	"set_cookie":    {},
	"cookie":        {},
	"api_key":       {},
	"apikey":        {},
}

// redactingHandler 在 JSON handler 前过滤敏感属性。
// 明确的凭据属性名与 *_token/*_password/*_secret 后缀输出固定占位符；
// group 递归处理；error 属性保留用于诊断。
type redactingHandler struct {
	next slog.Handler
}

// newRedactingHandler 把过滤 handler 包在目标 handler 之前。
func newRedactingHandler(next slog.Handler) *redactingHandler {
	return &redactingHandler{next: next}
}

// Enabled 透传给目标 handler。
func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle 过滤记录属性后转发给目标 handler。
func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	filtered := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		filtered = append(filtered, h.redact(a))
		return true
	})
	record := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	record.AddAttrs(filtered...)
	return h.next.Handle(ctx, record)
}

// WithAttrs 过滤后传给目标 handler，扩展属性同样经过脱敏。
func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = h.redact(a)
	}
	return &redactingHandler{next: h.next.WithAttrs(redacted)}
}

// WithGroup 把分组透传给目标 handler。
func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{next: h.next.WithGroup(name)}
}

// redact 对单个属性执行敏感过滤；group 属性递归处理子属性。
func (h *redactingHandler) redact(a slog.Attr) slog.Attr {
	if a.Equal(slog.Attr{}) {
		return a
	}
	if a.Value.Kind() == slog.KindGroup {
		children := a.Value.Group()
		if len(children) == 0 {
			return a
		}
		filtered := make([]slog.Attr, len(children))
		for i, child := range children {
			filtered[i] = h.redact(child)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(filtered...)}
	}
	if isSensitive(a) && !isSetupTokenAllowance(a) {
		a.Value = slog.StringValue(redactedPlaceholder)
	}
	return a
}

// isSensitive 判断属性名是否命中凭据集合或敏感后缀。
func isSensitive(a slog.Attr) bool {
	key := strings.ToLower(a.Key)
	if _, ok := sensitiveExact[key]; ok {
		return true
	}
	for _, suffix := range sensitiveSuffixes {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// isSetupTokenAllowance 判断属性是否为 SetupToken 构造的唯一放行值。
func isSetupTokenAllowance(a slog.Attr) bool {
	if a.Key != "setup_token" {
		return false
	}
	switch a.Value.Kind() {
	case slog.KindAny, slog.KindLogValuer:
		_, ok := a.Value.Any().(setupTokenValue)
		return ok
	default:
		return false
	}
}

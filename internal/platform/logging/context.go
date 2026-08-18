package logging

import (
	"context"
	"log/slog"
)

// contextKey 是 context 中日志属性的内部键。
type contextKey struct{}

// WithAttrs 以不可变副本把属性加入 context.Context。
// 追加基于当前 context 的副本，父 context 不受影响，请求间不串字段。
func WithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	if len(attrs) == 0 {
		return ctx
	}
	existing := AttrsFrom(ctx)
	merged := make([]slog.Attr, 0, len(existing)+len(attrs))
	merged = append(merged, existing...)
	merged = append(merged, attrs...)
	return context.WithValue(ctx, contextKey{}, merged)
}

// AttrsFrom 返回 context 中已保存的日志属性；未保存时返回空切片。
func AttrsFrom(ctx context.Context) []slog.Attr {
	attrs, _ := ctx.Value(contextKey{}).([]slog.Attr)
	return attrs
}

// FromContext 从 context 派生 logger：以 base 为基底，附加上下文属性。
// 上下文无属性时返回 base；base 为空时返回 discard logger。
func FromContext(ctx context.Context, base *slog.Logger) *slog.Logger {
	if base == nil {
		base = Discard()
	}
	attrs := AttrsFrom(ctx)
	if len(attrs) == 0 {
		return base
	}
	args := make([]any, len(attrs))
	for i, a := range attrs {
		args[i] = a
	}
	return base.With(args...)
}

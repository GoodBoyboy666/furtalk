package comment

import (
	"context"
	"time"

	"furtalk/internal/platform/token"
)

// WidgetSignerConfig 是 widget signer 的最小静态配置。
type WidgetSignerConfig struct {
	Issuer   string
	Key      []byte
	Lifetime time.Duration
}

// WidgetSigner 是面向 widget token 的 JWT 签名与验签服务。
type WidgetSigner struct {
	*jwt.Service
}

// NewWidgetSigner 按 feature 自己的配置构建 widget JWT signer。
func NewWidgetSigner(cfg WidgetSignerConfig) *WidgetSigner {
	return &WidgetSigner{jwt.NewService(jwt.Config{
		Issuer:   cfg.Issuer,
		Key:      cfg.Key,
		Lifetime: cfg.Lifetime,
	})}
}

// NewWidgetJWTVerifierFromSigner 在 widget signer 之上构建 widget 凭据验证器。
func NewWidgetJWTVerifierFromSigner(signer *WidgetSigner) *WidgetJWTVerifier {
	return NewWidgetJWTVerifier(signer.Service)
}

// NewSettingsReader 构建从策略读取器投影出 widget 模式与代次的读取器。
func NewSettingsReader(reader SettingsReader) WidgetSettingsReader {
	return widgetSettingsReader{reader: reader}
}

// widgetSettingsReader 把评论策略投影为 widget 中间件所需的模式与凭证代次。
type widgetSettingsReader struct {
	reader SettingsReader
}

// WidgetConfig 返回当前评论模式与凭证代次。
func (a widgetSettingsReader) WidgetConfig(ctx context.Context) (mode string, epoch int64, err error) {
	pol, err := a.reader.CommentPolicy(ctx)
	if err != nil {
		return "", 0, err
	}
	return pol.Mode, pol.Epoch, nil
}

// 编译期断言。
var _ TokenSigner = (*WidgetSigner)(nil)

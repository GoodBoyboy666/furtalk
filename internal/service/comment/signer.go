package comment

import (
	"context"
	"time"

	"furtalk/internal/platform/token"
)

// WidgetSignerConfig widget signer 的最小静态配置。
type WidgetSignerConfig struct {
	Issuer   string
	Key      []byte
	Lifetime time.Duration
}

// WidgetSigner 面向 widget token 的 JWT 签名与验签服务。
type WidgetSigner struct {
	*jwt.Service
}

// NewWidgetSigner 按评论模块配置构建 Widget JWT 签名器。
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

// NewSettingsReader 构建读取 Widget 模式与凭证代次的适配器。
func NewSettingsReader(reader SettingsReader) WidgetSettingsReader {
	return widgetSettingsReader{reader: reader}
}

// widgetSettingsReader 将评论策略转换为 Widget 中间件所需的模式与凭证代次。
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

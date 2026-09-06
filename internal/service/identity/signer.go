package identity

import (
	"time"

	"furtalk/internal/platform/token"
)

// SignerConfig 第一方 signer 所需的最小静态配置。
type SignerConfig struct {
	Issuer   string
	Key      []byte
	Lifetime time.Duration
}

// Signer 面向第一方登录的 JWT 签名与验签服务。
type Signer struct {
	*jwt.Service
}

// NewSigner 从模块自有配置构建第一方 JWT signer。
func NewSigner(cfg SignerConfig) *Signer {
	return &Signer{jwt.NewService(jwt.Config{
		Issuer:   cfg.Issuer,
		Key:      cfg.Key,
		Lifetime: cfg.Lifetime,
	})}
}

// TokenSigner 签发第一方 JWT，由 Signer 实现。
type TokenSigner interface {
	SignFirstParty(userID, sessionVersion int64) (string, error)
	Lifetime() time.Duration
}

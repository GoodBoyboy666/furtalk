package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// appleClientSecretTTL Apple client-secret JWT 的生存期。
// JWT 随每次 token 交换现场生成、短期有效。
const appleClientSecretTTL = 10 * time.Minute

// appleClientSecretAudience Apple client-secret JWT 的固定 audience。
const appleClientSecretAudience = "https://appleid.apple.com"

// parseApplePrivateKey 解析 Apple 的 PKCS#8 DER PEM P-256 私钥（.p8）。
// 私钥必须是 EC 且曲线为 P-256；否则返回错误。该函数同时供配置连通性
// 测试路径验证私钥。
func parseApplePrivateKey(raw string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return nil, fmt.Errorf("oauth: apple private key must be a pem-encoded pkcs8 key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oauth: parse apple private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("oauth: apple private key must be an ec p-256 private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("oauth: apple private key must use the p-256 curve")
	}
	return key, nil
}

// ValidateApplePrivateKey 校验配置的 Apple 私钥可被解析用于生成 client-secret JWT。
// 供管理端连通性测试等外部消费者使用。
func ValidateApplePrivateKey(raw string) error {
	_, err := parseApplePrivateKey(raw)
	return err
}

// clientSecret 为一次 token 交换现场生成短期 ES256 client-secret JWT。
// header 携带 kid=key_id；claims 为 iss=team_id、sub=client_id、
// aud=https://appleid.apple.com、iat=now、exp=now+TTL。
func (p *appleProvider) clientSecret(now time.Time) (string, error) {
	claims := gojwt.MapClaims{
		"iss": p.teamID,
		"sub": p.clientID,
		"aud": appleClientSecretAudience,
		"iat": now.Unix(),
		"exp": now.Add(appleClientSecretTTL).Unix(),
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodES256, claims)
	token.Header["kid"] = p.keyID
	signed, err := token.SignedString(p.privateKey)
	if err != nil {
		return "", fmt.Errorf("oauth: sign apple client secret: %w", err)
	}
	return signed, nil
}

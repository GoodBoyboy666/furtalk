// Package jwt 为评论系统提供通用的 JWT 签名与验签方案。
// 签名算法固定为 HS256，每次解析时强制校验 issuer、audience、subject、token kind 与时间。
// Token 不携带授权角色与状态，授权信息每次请求时从授权缓存读取。
package jwt

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWT 常量：各 token 种类的 audience、kind 与唯一签名算法。
const (
	// AudienceFirstParty 是 first-party 登录 token 的 audience。
	AudienceFirstParty = "furtalk-first-party"
	// AudienceWidgetAuthenticated 是已认证模式 widget token 的 audience。
	AudienceWidgetAuthenticated = "furtalk-widget-authenticated"
	// AudienceUnsubscribe 是通知邮件中退订链接所用签名 token 的 audience。
	AudienceUnsubscribe = "furtalk-unsubscribe"

	// TokenKindFirstParty 是 first-party 登录 token 的 token kind。
	TokenKindFirstParty = "first_party"
	// TokenKindWidgetAuthenticated 是已认证模式 widget token 的 token kind。
	TokenKindWidgetAuthenticated = "widget_authenticated"
	// TokenKindUnsubscribe 是通知退订 token 的 token kind。
	TokenKindUnsubscribe = "unsubscribe"

	// SigningMethod 是唯一接受的签名算法。
	SigningMethod = "HS256"
)

var (
	// ErrInvalidToken 在 token 无法解析，
	// 或未通过固定的 algorithm/issuer/audience/kind/time 声明校验时返回。
	ErrInvalidToken = errors.New("jwt: invalid token")
	// ErrTokenExpired 在 token 已过期或尚未生效时返回。
	ErrTokenExpired = errors.New("jwt: token expired or not yet valid")
)

// Config 携带静态 JWT 策略。Issuer 通常是公开的基础 URL。
type Config struct {
	Issuer   string
	Key      []byte
	Lifetime time.Duration
}

// Claims 是每种 token kind 使用的固定声明集合。
// SiteID 与 CredentialEpoch 仅在 widget token 上设置；
// NotificationKind 仅在退订 token 上设置；
// SessionVersion 仅在第一方 token 上设置，用于撤销检查。
type Claims struct {
	TokenKind        string `json:"token_kind"`
	SiteID           string `json:"site_id,omitempty"`
	CredentialEpoch  string `json:"credential_epoch,omitempty"`
	NotificationKind string `json:"notification_kind,omitempty"`
	SessionVersion   int64  `json:"session_version,omitempty"`
	jwt.RegisteredClaims
}

// UserID 把 subject 解析为十进制 int64 并返回。
// subject 是持久化用户 id 的十进制字符串。
func (c Claims) UserID() (int64, error) {
	id, err := strconv.ParseInt(c.Subject, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: subject %q is not a positive decimal id", ErrInvalidToken, c.Subject)
	}
	return id, nil
}

// Service 是固定策略的 JWT 签名器与验签器。
type Service struct {
	cfg Config
}

// NewService 使用给定的静态策略构建 JWT 服务。
func NewService(cfg Config) *Service {
	return &Service{cfg: cfg}
}

// SignFirstParty 为用户 id 与当前会话代次签发 first-party 登录 token。
// sessionVersion 必须是正整数；签发时写入 claim，供撤销检查与当前版本比较。
func (s *Service) SignFirstParty(userID, sessionVersion int64) (string, error) {
	if sessionVersion <= 0 {
		return "", fmt.Errorf("jwt: first-party session version must be positive, got %d", sessionVersion)
	}
	now := time.Now().UTC()
	claims := Claims{
		TokenKind:      TokenKindFirstParty,
		SessionVersion: sessionVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   strconv.FormatInt(userID, 10),
			Audience:  jwt.ClaimStrings{AudienceFirstParty},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.Lifetime)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	return s.sign(claims)
}

// Lifetime 返回配置的 token 有效期，用于设置 FP Cookie 的 Max-Age，
// 保证不超过 JWT 的过期时间。
func (s *Service) Lifetime() time.Duration {
	return s.cfg.Lifetime
}

// SignWidget 签发绑定到站点与给定 credential epoch 的 widget 凭据。
// Widget 只存在 widget_authenticated 评论凭据；kind 必须为
// TokenKindWidgetAuthenticated。epoch 是十进制字符串形式的 int64。
func (s *Service) SignWidget(userID, siteID int64, kind, epoch string) (string, error) {
	if kind != TokenKindWidgetAuthenticated {
		return "", fmt.Errorf("jwt: unsupported widget token kind %q", kind)
	}
	audience := AudienceWidgetAuthenticated
	now := time.Now().UTC()
	claims := Claims{
		TokenKind:       kind,
		SiteID:          strconv.FormatInt(siteID, 10),
		CredentialEpoch: epoch,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   strconv.FormatInt(userID, 10),
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.Lifetime)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	return s.sign(claims)
}

// sign 使用固定的 HS256 算法序列化并签名 claims。
func (s *Service) sign(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := token.SignedString(s.cfg.Key)
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}
	return raw, nil
}

// SignUnsubscribe 为通知退订链接签发短期有效的签名 token。
// 该 token 只证明用户有权退订某个通知 kind，不能用于启用通知。
func (s *Service) SignUnsubscribe(userID int64, kind string, lifetime time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		TokenKind:        TokenKindUnsubscribe,
		NotificationKind: kind,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   strconv.FormatInt(userID, 10),
			Audience:  jwt.ClaimStrings{AudienceUnsubscribe},
			ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	return s.sign(claims)
}

// ParseUnsubscribe 验证退订 token，返回用户 id 与 token 授权禁用的通知 kind。
// 伪造、过期或 audience 不符的 token 一律拒绝，不检查用户是否存在。
func (s *Service) ParseUnsubscribe(raw string) (int64, string, error) {
	claims, err := s.Parse(raw, AudienceUnsubscribe, TokenKindUnsubscribe)
	if err != nil {
		return 0, "", err
	}
	if claims.NotificationKind == "" {
		return 0, "", fmt.Errorf("%w: missing notification kind", ErrInvalidToken)
	}
	userID, err := claims.UserID()
	if err != nil {
		return 0, "", err
	}
	return userID, claims.NotificationKind, nil
}

// Parse 按固定策略以及期望的 audience 与 token kind 验证 token。
// algorithm、issuer、audience、kind 不符，缺少 subject/jti，或 token 过期时一律拒绝。
func (s *Service) Parse(raw string, wantAudience, wantKind string) (*Claims, error) {
	claims := &Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{SigningMethod}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithAudience(wantAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	_, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		return s.cfg.Key, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if claims.Subject == "" || claims.ID == "" {
		return nil, fmt.Errorf("%w: missing subject or jti", ErrInvalidToken)
	}
	if claims.TokenKind != wantKind {
		return nil, fmt.Errorf("%w: token kind %q does not match %q", ErrInvalidToken, claims.TokenKind, wantKind)
	}
	if _, err := claims.UserID(); err != nil {
		return nil, err
	}
	return claims, nil
}

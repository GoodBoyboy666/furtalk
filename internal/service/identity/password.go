package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/value"

	"golang.org/x/crypto/argon2"
)

// Argon2id 密码哈希派生参数。
const (
	argon2Memory  = 64 * 1024
	argon2Time    = 3
	argon2Threads = 2
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

var errBadHash = errors.New("identity: malformed password hash envelope")

// setPassword 派生 Argon2id 哈希并原子更新密码状态与会话代次，返回新代次。
// 时间列精度为微秒（precision:6），统一截断以保持存储值一致。
func (s *Service) setPassword(ctx context.Context, userID int64, password string) (int64, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return 0, err
	}
	return s.users.SetPassword(ctx, userID, hash, s.now().UTC().Truncate(time.Microsecond))
}

// LoginWithPassword 校验 CAPTCHA 后核对邮箱与密码组合，签发 FP Cookie。
func (s *Service) LoginWithPassword(ctx context.Context, rawEmail, password, captchaToken string) (*Session, error) {
	_, normalized, err := value.NormalizeEmail(rawEmail)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if err := s.checkCaptcha(ctx, PasswordLoginAction, captchaToken); err != nil {
		return nil, err
	}
	user, err := s.users.FindByEmailNormalized(ctx, normalized)
	if errors.Is(err, domain.ErrNotFound) {
		_, _ = hashPassword(password)
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	hash, err := s.users.PasswordHash(ctx, user.ID)
	if errors.Is(err, domain.ErrNotFound) {
		_, _ = hashPassword(password)
		return nil, domain.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !verifyPassword(hash, password) {
		return nil, domain.ErrInvalidCredentials
	}
	return s.completeLogin(ctx, user)
}

// hashPassword 派生内嵌参数的 Argon2id 哈希格式。
func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("identity: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// verifyPassword 用常数时间比较校验密码与 Argon2id 哈希格式。
func verifyPassword(encoded, password string) bool {
	params, err := parseEnvelope(encoded)
	if err != nil {
		return false
	}
	derived := argon2.IDKey([]byte(password), params.salt, params.time, params.memory, params.threads, params.keyLen)
	return subtle.ConstantTimeCompare(derived, params.hash) == 1
}

type envelopeParams struct {
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
	salt    []byte
	hash    []byte
}

func parseEnvelope(encoded string) (*envelopeParams, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, errBadHash
	}
	if version != argon2.Version {
		return nil, errBadHash
	}
	var memory, timeCost, threads int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return nil, errBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, errBadHash
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, errBadHash
	}
	return &envelopeParams{
		memory:  uint32(memory),
		time:    uint32(timeCost),
		threads: uint8(threads),
		keyLen:  uint32(len(hash)),
		salt:    salt,
		hash:    hash,
	}, nil
}

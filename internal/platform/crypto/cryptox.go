// Package cryptox 提供保护静态存储的提供方密钥的低层加密方案：
// AES-256-GCM 信封，格式为
//
//	envelope = key_version(1 byte) || nonce(12 bytes) || ciphertext
//
// 外加随机字节辅助函数。该包与业务无关，不承载评论系统的策略。
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// 信封格式的固定长度与 AES-256 的最小密钥长度。
const (
	envelopeKeyVersionLength = 1
	gcmNonceLength           = 12
	gcmOverheadLength        = 16
	minimumKeyLength         = 32
)

var (
	// ErrBadEnvelope 在信封无法解析，或嵌入的 key version 与当前主密钥版本不匹配时返回。
	ErrBadEnvelope = errors.New("cryptox: invalid secret envelope")
	// ErrKeyLength 在密钥长度不足 32 字节时返回。
	ErrKeyLength = errors.New("cryptox: key must be at least 32 bytes")
)

// RandomBytes 返回 n 个密码学安全的随机字节。
func RandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("cryptox: generate random bytes: %w", err)
	}
	return buf, nil
}

// RandomToken 返回 n 个随机字节的 base64url 编码（无填充）字符串。
func RandomToken(n int) (string, error) {
	raw, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// SHA256Hex 返回 raw 的 SHA-256 摘要的十六进制编码。
func SHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Encrypt 使用新的随机 nonce 以 AES-256-GCM 密封明文，并返回首字节携带给定 key version 的信封。
// 密钥必须至少 32 字节。
func Encrypt(key []byte, keyVersion byte, plaintext []byte) ([]byte, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptox: new gcm: %w", err)
	}
	nonce := make([]byte, gcmNonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cryptox: generate nonce: %w", err)
	}
	envelope := make([]byte, 0, envelopeKeyVersionLength+gcmNonceLength+len(plaintext)+gcmOverheadLength)
	envelope = append(envelope, keyVersion)
	envelope = append(envelope, nonce...)
	envelope = aead.Seal(envelope, nonce, plaintext, nil)
	return envelope, nil
}

// Decrypt 打开信封并返回明文。
// 结构性或认证失败，以及嵌入的 key version 与提供值不匹配时都安全失败；
// 轮换后的密钥不会静默解密旧密钥写入的记录。
func Decrypt(key []byte, keyVersion byte, envelope []byte) ([]byte, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	if len(envelope) < envelopeKeyVersionLength+gcmNonceLength+gcmOverheadLength {
		return nil, ErrBadEnvelope
	}
	if envelope[0] != keyVersion {
		return nil, ErrBadEnvelope
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptox: new gcm: %w", err)
	}
	nonce := envelope[envelopeKeyVersionLength : envelopeKeyVersionLength+gcmNonceLength]
	ciphertext := envelope[envelopeKeyVersionLength+gcmNonceLength:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrBadEnvelope
	}
	return plaintext, nil
}

func newBlock(key []byte) (cipher.Block, error) {
	if len(key) < minimumKeyLength {
		return nil, ErrKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptox: new aes cipher: %w", err)
	}
	return block, nil
}

package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

// scopedSubjectVersion 是 ScopedSubject 输出格式的版本前缀。
// 该标记是稳定的机器标识，变更编码时必须整体迁移，不允许静默混用两种格式。
const scopedSubjectVersion = "ft1:"

// ScopedSubject 返回 (issuer, rawSubject) 二元组的确定性、版本化、抗碰撞编码。
func ScopedSubject(issuer, rawSubject string) string {
	h := sha256.New()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(issuer)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(issuer))
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(rawSubject)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(rawSubject))
	return scopedSubjectVersion + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

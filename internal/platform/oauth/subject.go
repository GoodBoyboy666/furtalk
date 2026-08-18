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
// 自托管 GitLab/Gitea 的数字 sub 只在单个实例内稳定：把同一固定 key 重新配置到
// 另一实例时，新的数字 sub 绝不能与旧绑定碰撞。编码先对两部分做长度前缀
// （8 字节大端 uint64），再对拼接字节做版本化 SHA-256，输出以 ft1: 开头，
// 因此 ("ab", "c") 与 ("a", "bc") 即使字符串拼接相同也产生不同的结果。
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

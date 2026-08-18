package oauth

import (
	"strings"
	"testing"
)

// TestScopedSubjectDeterminism 验证相同 (issuer, subject) 元组产生相同结果。
func TestScopedSubjectDeterminism(t *testing.T) {
	first := ScopedSubject("https://gitlab.example.com", "123")
	second := ScopedSubject("https://gitlab.example.com", "123")
	if first != second {
		t.Fatalf("determinism: %q != %q", first, second)
	}
}

// TestScopedSubjectFormat 验证输出携带稳定的 ft1: 前缀且长度为定值。
// SHA-256 摘要为 32 字节，base64url 无填充编码长度为 43。
func TestScopedSubjectFormat(t *testing.T) {
	got := ScopedSubject("https://gitlab.example.com", "123")
	if !strings.HasPrefix(got, scopedSubjectVersion) {
		t.Fatalf("prefix = %q, want %q", got[:min(len(got), len(scopedSubjectVersion))], scopedSubjectVersion)
	}
	if len(got) != len(scopedSubjectVersion)+43 {
		t.Fatalf("length = %d, want %d", len(got), len(scopedSubjectVersion)+43)
	}
}

// TestScopedSubjectCollisionResistance 验证不同元组产生不同结果：
// 同一 issuer 的不同 subject、不同 issuer 的同一 subject 与空 issuer 均不碰撞。
func TestScopedSubjectCollisionResistance(t *testing.T) {
	cases := []struct {
		issuer, subject string
	}{
		{"https://a.example", "1"},
		{"https://a.example", "2"},
		{"https://b.example", "1"},
		{"", "1"},
		{"https://a.example", ""},
	}
	seen := make(map[string]string, len(cases))
	for _, c := range cases {
		got := ScopedSubject(c.issuer, c.subject)
		if prev, ok := seen[got]; ok {
			t.Fatalf("collision: %q already produced by %s", got, prev)
		}
		seen[got] = c.issuer + " / " + c.subject
	}
}

// TestScopedSubjectNoRawConcatenation 验证长度前缀编码使裸字符串拼接碰撞也不相同：
// ("ab", "c") 与 ("a", "bc") 拼接后相同，但编码结果必须不同。
func TestScopedSubjectNoRawConcatenation(t *testing.T) {
	if ScopedSubject("ab", "c") == ScopedSubject("a", "bc") {
		t.Fatal("length-prefix encoding must distinguish (ab,c) from (a,bc)")
	}
}

package spam

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keywords.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

// TestLocalMatcherMatches 验证正文命中、昵称开关与大小写/Unicode 不敏感匹配。
func TestLocalMatcherMatches(t *testing.T) {
	path := writeFile(t, "广告\n免费领取\nLOAN\n")
	matcher := NewLocal(LocalConfig{FilePath: path, CheckNickname: true}, nil)
	ctx := context.Background()

	cases := []struct {
		name     string
		body     string
		nickname string
		want     Result
	}{
		{name: "body exact", body: "这里有广告", want: ResultBlock},
		{name: "body no hit", body: "你好世界", want: ResultPass},
		{name: "body case insensitive", body: "get a loan now", want: ResultBlock},
		{name: "nickname hit", body: "正常内容", nickname: "免费领取", want: ResultBlock},
		{name: "nickname no hit off", body: "正常内容", nickname: "普通昵称", want: ResultPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := matcher.Check(ctx, Input{Body: tc.body, Nickname: tc.nickname})
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if got != tc.want {
				t.Fatalf("result = %v, want %v", got, tc.want)
			}
		})
	}

	// 关闭昵称检测：昵称命中不影响结果。
	matcherNickOff := NewLocal(LocalConfig{FilePath: path, CheckNickname: false}, nil)
	got, err := matcherNickOff.Check(ctx, Input{Body: "正常内容", Nickname: "广告"})
	if err != nil {
		t.Fatalf("check nickname off: %v", err)
	}
	if got != ResultPass {
		t.Fatalf("nickname off result = %v, want pass", got)
	}
}

// TestLocalMatcherUnicodeFold 验证 Unicode 兼容规范化与大小写折叠匹配。
func TestLocalMatcherUnicodeFold(t *testing.T) {
	// 全角字符与大小写变体都应命中。
	path := writeFile(t, "ｆｒｅｅ\n")
	matcher := NewLocal(LocalConfig{FilePath: path, CheckNickname: false}, nil)
	got, err := matcher.Check(context.Background(), Input{Body: "get free stuff"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if got != ResultBlock {
		t.Fatalf("fullwidth result = %v, want block", got)
	}
}

// TestLocalMatcherHotReload 验证文件变化触发重载，且失败重载保留最近成功快照。
func TestLocalMatcherHotReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keywords.txt")
	if err := os.WriteFile(path, []byte("广告\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	matcher := NewLocal(LocalConfig{FilePath: path, CheckNickname: false}, nil)
	ctx := context.Background()

	if got, _ := matcher.Check(ctx, Input{Body: "有广告"}); got != ResultBlock {
		t.Fatalf("initial hit = %v, want block", got)
	}

	// 更新词库并确保 mtime/size 变化。
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte("广告\n贷款\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := matcher.Check(ctx, Input{Body: "有贷款"}); got != ResultBlock {
		t.Fatalf("reloaded hit = %v, want block", got)
	}

	// 删除文件：保留最近成功快照，仍可命中。
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := matcher.Check(ctx, Input{Body: "有贷款"}); err != nil || got != ResultBlock {
		t.Fatalf("after remove result = %v err = %v, want block/nil", got, err)
	}
}

// TestLocalMatcherNeverLoaded 验证从未成功加载且文件缺失时按 unknown 降级（返回错误）。
func TestLocalMatcherNeverLoaded(t *testing.T) {
	matcher := NewLocal(LocalConfig{FilePath: "/no/such/file.txt", CheckNickname: false}, nil)
	_, err := matcher.Check(context.Background(), Input{Body: "x"})
	if err == nil {
		t.Fatal("check on missing file = nil error, want error")
	}
}

// TestLocalMatcherEmptyFile 验证空词库返回 pass。
func TestLocalMatcherEmptyFile(t *testing.T) {
	path := writeFile(t, "\n  \n")
	matcher := NewLocal(LocalConfig{FilePath: path, CheckNickname: false}, nil)
	got, err := matcher.Check(context.Background(), Input{Body: "广告"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if got != ResultPass {
		t.Fatalf("empty file result = %v, want pass", got)
	}
}

// TestValidateKeywordFile 验证文件校验：普通可读文件通过，缺失/非法 UTF-8 拒绝。
func TestValidateKeywordFile(t *testing.T) {
	path := writeFile(t, "广告\n")
	if err := ValidateKeywordFile(path); err != nil {
		t.Fatalf("valid file error = %v, want nil", err)
	}
	if err := ValidateKeywordFile("/no/such/file"); err == nil {
		t.Fatal("missing file error = nil, want error")
	}
	if err := ValidateKeywordFile(t.TempDir()); err == nil {
		t.Fatal("directory error = nil, want error")
	}
}

// TestParseKeywordLinesDedup 验证去空行、修剪、去重与 CRLF。
func TestParseKeywordLinesDedup(t *testing.T) {
	lines, err := parseKeywordLines([]byte(" 广告  \r\n广告\r\n\n  \n贷款\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("lines = %v, want 2 unique", lines)
	}
	joined := strings.Join(lines, ",")
	if !strings.Contains(joined, "广告") || !strings.Contains(joined, "贷款") {
		t.Fatalf("lines mismatch: %v", lines)
	}
}

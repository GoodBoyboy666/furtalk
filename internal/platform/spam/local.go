package spam

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	"furtalk/internal/platform/logging"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// 词库文件与单行的大小限制。
const (
	maxKeywordFileSize = 64 << 20 // 64 MiB
	maxKeywordLineLen  = 4000     // 与评论正文最大长度一致
)

// LocalConfig 是本地词库检测器的配置。
type LocalConfig struct {
	// FilePath 是词库文件的绝对路径。
	FilePath string
	// CheckNickname 开启时昵称也参与匹配；关闭时只检测正文。
	CheckNickname bool
}

// LocalMatcher 是按文件快照热重载的本地关键词检测器。
// 每次 Check 只比较修改时间与文件大小，变化时才重新解析并原子替换。
type LocalMatcher struct {
	cfg     LocalConfig
	log     *slog.Logger
	mu      sync.RWMutex
	current *snapshot
}

// fileSignature 是词库文件的稳定性签名。
type fileSignature struct {
	size    int64
	mtimeNS int64
}

// snapshot 是一次成功加载的词库快照。
type snapshot struct {
	path    string
	size    int64
	mtimeNS int64
	matcher *acMachine
}

// NewLocal 构建本地词库检测器。
func NewLocal(cfg LocalConfig, logger *slog.Logger) *LocalMatcher {
	return &LocalMatcher{cfg: cfg, log: logging.Normalize(logger)}
}

// Check 检测正文（开启昵称检测时还包括昵称）是否命中词库。
// 无任何成功快照且文件不可读时返回错误，调用方按 unknown 降级。
func (m *LocalMatcher) Check(ctx context.Context, input Input) (Result, error) {
	snap, err := m.reloadIfChanged()
	if err != nil {
		return ResultPass, err
	}
	if snap == nil || snap.matcher == nil || snap.matcher.patternCount == 0 {
		return ResultPass, nil
	}
	if snap.matcher.contains([]rune(normalizeKeyword(input.Body))) {
		return ResultBlock, nil
	}
	if m.cfg.CheckNickname && snap.matcher.contains([]rune(normalizeKeyword(input.Nickname))) {
		return ResultBlock, nil
	}
	return ResultPass, nil
}

// reloadIfChanged 按文件签名决定是否重建词库快照。
// 热重载失败时继续使用最近一次成功快照；从未成功加载时返回错误。
func (m *LocalMatcher) reloadIfChanged() (*snapshot, error) {
	info, err := os.Stat(m.cfg.FilePath)
	if err != nil {
		m.mu.RLock()
		snap := m.current
		m.mu.RUnlock()
		if snap != nil {
			m.log.Warn("spam: stat keyword file failed, keep last good snapshot", "error", err)
			return snap, nil
		}
		return nil, fmt.Errorf("%w: stat keyword file: %v", ErrUnavailable, err)
	}
	sig := fileSignature{size: info.Size(), mtimeNS: info.ModTime().UnixNano()}
	m.mu.RLock()
	current := m.current
	m.mu.RUnlock()
	if current != nil && current.path == m.cfg.FilePath && current.size == sig.size && current.mtimeNS == sig.mtimeNS {
		return current, nil
	}
	patterns, err := loadKeywordFile(m.cfg.FilePath, sig)
	if err != nil {
		m.mu.RLock()
		old := m.current
		m.mu.RUnlock()
		if old != nil {
			m.log.Warn("spam: reload keyword file failed, keep last good snapshot", "error", err)
			return old, nil
		}
		return nil, fmt.Errorf("%w: reload keyword file: %v", ErrUnavailable, err)
	}
	next := &snapshot{path: m.cfg.FilePath, size: sig.size, mtimeNS: sig.mtimeNS, matcher: buildAC(patterns)}
	m.mu.Lock()
	m.current = next
	m.mu.Unlock()
	return next, nil
}

// loadKeywordFile 在大小与单行限制内读取并解析词库文件。
// 读取前后再次核对签名，避免把写到一半的文件发布为新快照。
func loadKeywordFile(path string, before fileSignature) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("keyword file is not a regular file")
	}
	if info.Size() > maxKeywordFileSize {
		return nil, fmt.Errorf("keyword file exceeds %d bytes", maxKeywordFileSize)
	}
	content, err := io.ReadAll(io.LimitReader(f, maxKeywordFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxKeywordFileSize {
		return nil, fmt.Errorf("keyword file exceeds %d bytes", maxKeywordFileSize)
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if after.Size() != before.size || after.ModTime().UnixNano() != before.mtimeNS {
		return nil, fmt.Errorf("keyword file changed while reading")
	}
	if !utf8.Valid(content) {
		return nil, fmt.Errorf("keyword file is not valid utf-8")
	}
	return parseKeywordLines(content)
}

// parseKeywordLines 按行解析词库：忽略空行、修剪首尾空白、NFKC 加大小写折叠后去重。
func parseKeywordLines(content []byte) ([]string, error) {
	seen := make(map[string]struct{})
	out := make([]string, 0, 16)
	for _, raw := range bytes.Split(content, []byte{'\n'}) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		if len(line) > maxKeywordLineLen {
			return nil, fmt.Errorf("keyword line exceeds %d bytes", maxKeywordLineLen)
		}
		key := normalizeKeyword(line)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out, nil
}

// normalizeKeyword 用 NFKC 兼容规范化加 Unicode 大小写折叠归一化关键词或候选文本。
func normalizeKeyword(raw string) string {
	return foldCaser.String(norm.NFKC.String(raw))
}

// foldCaser 是复用的大小写折叠转换器。
var foldCaser = cases.Fold()

// acMachine 是 rune 级的 Aho-Corasick 多模式自动机。
// 命中检测为候选文本长度的线性扫描，不为每个关键词逐一 Contains。
type acMachine struct {
	root         *acNode
	patternCount int
}

// acNode 是自动机的一个节点。
type acNode struct {
	next     map[rune]*acNode
	fail     *acNode
	terminal bool
}

// buildAC 由已归一化的模式构建自动机。
func buildAC(patterns []string) *acMachine {
	root := &acNode{next: make(map[rune]*acNode)}
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		node := root
		for _, r := range pattern {
			child, ok := node.next[r]
			if !ok {
				child = &acNode{next: make(map[rune]*acNode)}
				node.next[r] = child
			}
			node = child
		}
		node.terminal = true
	}
	queue := make([]*acNode, 0, 16)
	for _, child := range root.next {
		child.fail = root
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for r, child := range current.next {
			fail := current.fail
			for fail != nil {
				if next, ok := fail.next[r]; ok {
					child.fail = next
					break
				}
				fail = fail.fail
			}
			if child.fail == nil {
				child.fail = root
			}
			if child.fail.terminal {
				child.terminal = true
			}
			queue = append(queue, child)
		}
	}
	return &acMachine{root: root, patternCount: len(patterns)}
}

// contains 报告候选文本是否命中任一模式。
func (m *acMachine) contains(text []rune) bool {
	node := m.root
	for _, r := range text {
		for node != m.root && node.next[r] == nil {
			node = node.fail
		}
		if next, ok := node.next[r]; ok {
			node = next
		} else {
			node = m.root
		}
		if node.terminal {
			return true
		}
	}
	return false
}

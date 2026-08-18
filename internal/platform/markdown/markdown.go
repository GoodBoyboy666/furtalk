// Package markdown 验证 Markdown 正文，解析为 goldmark AST 并拒绝原始 HTML 节点。
package markdown

import (
	"errors"
	"html"
	"net/url"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// ErrRawHTML 在正文包含原始内联 HTML 或 HTML 块时返回。
var ErrRawHTML = errors.New("markdown: raw HTML is not allowed")

// ErrUnsafeDestination 在链接或图片 destination 使用了不安全的 URL 形式时返回。
var ErrUnsafeDestination = errors.New("markdown: unsafe link destination")

var md = goldmark.New()

// Validate 将 body 解析为 goldmark AST，不含原始 HTML 节点时返回 nil。
// 不做任何渲染。
func Validate(body string) error {
	doc := md.Parser().Parse(text.NewReader([]byte(body)))
	err := ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n.Kind() {
		case ast.KindRawHTML, ast.KindHTMLBlock:
			return ast.WalkStop, ErrRawHTML
		case ast.KindLink, ast.KindImage:
			if err := validateDestination(destination(n)); err != nil {
				return ast.WalkStop, err
			}
			return ast.WalkContinue, nil
		default:
			return ast.WalkContinue, nil
		}
	})
	if err != nil {
		return err
	}
	return nil
}

func destination(n ast.Node) []byte {
	switch node := n.(type) {
	case *ast.Link:
		return node.Destination
	case *ast.Image:
		return node.Destination
	default:
		return nil
	}
}

func validateDestination(raw []byte) error {
	destination := html.UnescapeString(string(raw))
	for _, char := range destination {
		if char <= ' ' || char == '\u007f' || char == '\\' {
			return ErrUnsafeDestination
		}
	}
	if strings.HasPrefix(destination, "//") {
		return ErrUnsafeDestination
	}

	parsed, err := url.Parse(destination)
	if err != nil {
		return ErrUnsafeDestination
	}
	switch strings.ToLower(parsed.Scheme) {
	case "", "http", "https", "mailto":
		return nil
	default:
		return ErrUnsafeDestination
	}
}

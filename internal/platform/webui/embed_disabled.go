//go:build !embed

// Package webui 提供编译期可选的 Web 控制台静态资源。
package webui

import (
	"errors"
	"io/fs"
)

// ErrUnavailable 表示当前二进制没有编译 Web 控制台资源。
var ErrUnavailable = errors.New("web UI is not compiled in; rebuild with -tags embed")

// FS 在未启用 embed 构建标签时返回明确错误。
func FS() (fs.FS, error) {
	return nil, ErrUnavailable
}

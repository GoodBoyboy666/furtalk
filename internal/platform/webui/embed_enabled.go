//go:build embed

// Package webui 提供编译期可选的 Web 控制台静态资源。
package webui

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
)

// ErrUnavailable 表示当前二进制没有编译 Web 控制台资源。
var ErrUnavailable = errors.New("web UI is not compiled in; rebuild with -tags embed")

// embeddedDist 是只读的 Web 构建产物；该目录由 scripts/stage-web.sh 生成。
//
//go:embed dist
var embeddedDist embed.FS

// FS 返回内嵌的 Web 资源文件系统。
func FS() (fs.FS, error) {
	dist, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		return nil, fmt.Errorf("web UI resource root: %w", err)
	}
	info, err := fs.Stat(dist, "index.html")
	if err != nil {
		return nil, fmt.Errorf("web UI bundle is missing index.html: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("web UI bundle index.html is not a regular file")
	}
	return dist, nil
}

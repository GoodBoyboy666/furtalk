package router

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
)

// RegisterWeb 注册 HTTP 路由。
func RegisterWeb(engine *gin.Engine, assets fs.FS) error {
	if engine == nil {
		return errors.New("router: web engine is nil")
	}
	if assets == nil {
		return errors.New("router: web assets are nil")
	}
	info, err := fs.Stat(assets, "index.html")
	if err != nil {
		return fmt.Errorf("router: web assets do not contain index.html: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("router: web assets index.html is not a regular file")
	}
	fileServer := http.FileServer(http.FS(assets))
	engine.NoRoute(func(c *gin.Context) {
		serveWeb(c, assets, fileServer)
	})
	return nil
}

// serveWeb 处理 Web 静态资源与 SPA 回退请求。
func serveWeb(c *gin.Context, assets fs.FS, fileServer http.Handler) {
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		c.Status(http.StatusNotFound)
		return
	}

	requestPath := c.Request.URL.Path
	if isReservedWebPath(requestPath) {
		c.Status(http.StatusNotFound)
		return
	}

	assetPath, valid := cleanWebPath(requestPath)
	if !valid {
		c.Status(http.StatusNotFound)
		return
	}
	if isReservedWebPath("/" + assetPath) {
		c.Status(http.StatusNotFound)
		return
	}

	if info, err := fs.Stat(assets, assetPath); err == nil && info.Mode().IsRegular() {
		serveWebFile(c, fileServer, assetPath)
		return
	}

	if path.Ext(assetPath) != "" {
		c.Status(http.StatusNotFound)
		return
	}
	serveWebFile(c, fileServer, "index.html")
}

// isReservedWebPath 判断请求路径是否属于保留 Web 路径。
func isReservedWebPath(requestPath string) bool {
	return requestPath == "/api" || strings.HasPrefix(requestPath, "/api/") ||
		requestPath == "/health" || strings.HasPrefix(requestPath, "/health/")
}

// cleanWebPath 规范化 Web 请求路径并判断其可用性。
func cleanWebPath(requestPath string) (string, bool) {
	if requestPath == "" || requestPath == "/" {
		return "index.html", true
	}
	if strings.ContainsRune(requestPath, '\\') || strings.IndexFunc(requestPath, unicode.IsControl) >= 0 {
		return "", false
	}

	name := strings.TrimPrefix(requestPath, "/")
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return "", false
		}
	}
	cleaned := path.Clean(name)
	if cleaned == "." || !fs.ValidPath(cleaned) {
		return "", false
	}
	return cleaned, true
}

// serveWebFile 通过静态文件处理器返回 Web 文件。
func serveWebFile(c *gin.Context, fileServer http.Handler, name string) {
	request := c.Request.Clone(c.Request.Context())
	request.URL.Path = "/" + name
	// FileServer 会把以 /index.html 结尾的路径重定向到父目录；父目录直接提供页面内容。
	if strings.HasSuffix(name, "/index.html") || name == "index.html" {
		request.URL.Path = strings.TrimSuffix(request.URL.Path, "index.html")
	}
	request.URL.RawPath = ""
	fileServer.ServeHTTP(c.Writer, request)
}

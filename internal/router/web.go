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

// RegisterWeb 将 Web 静态资源与 SPA history fallback 挂载到已有 Gin engine。
// 已注册的 API 与健康路由由 Gin 优先处理；未命中的保留前缀不会回退到首页。
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

func isReservedWebPath(requestPath string) bool {
	return requestPath == "/api" || strings.HasPrefix(requestPath, "/api/") ||
		requestPath == "/health" || strings.HasPrefix(requestPath, "/health/")
}

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

func serveWebFile(c *gin.Context, fileServer http.Handler, name string) {
	request := c.Request.Clone(c.Request.Context())
	request.URL.Path = "/" + name
	// FileServer 会把以 /index.html 结尾的路径重定向到父目录，这里直接按父目录提供内容。
	if strings.HasSuffix(name, "/index.html") || name == "index.html" {
		request.URL.Path = strings.TrimSuffix(request.URL.Path, "index.html")
	}
	request.URL.RawPath = ""
	fileServer.ServeHTTP(c.Writer, request)
}

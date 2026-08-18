package router

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"furtalk/internal/platform/config"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/ratelimit"
	"github.com/gin-gonic/gin"
)

func TestRegisterWebServesStaticAndSPARequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	assets := fstestMapFS()
	engine := newWebTestRouter(t, assets)

	tests := []struct {
		name       string
		method     string
		path       string
		status     int
		body       string
		bodyAbsent bool
		notSPA     bool
	}{
		{name: "home", method: http.MethodGet, path: "/", status: http.StatusOK, body: "<html>home</html>"},
		{name: "index file", method: http.MethodGet, path: "/index.html", status: http.StatusOK, body: "<html>home</html>"},
		{name: "nested index file", method: http.MethodGet, path: "/nested/index.html", status: http.StatusOK, body: "<html>nested</html>"},
		{name: "home head", method: http.MethodHead, path: "/", status: http.StatusOK, bodyAbsent: true},
		{name: "static asset", method: http.MethodGet, path: "/assets/app.js", status: http.StatusOK, body: "console.log('ok')"},
		{name: "static asset head", method: http.MethodHead, path: "/assets/app.js", status: http.StatusOK, bodyAbsent: true},
		{name: "frontend route", method: http.MethodGet, path: "/settings/profile", status: http.StatusOK, body: "<html>home</html>"},
		{name: "frontend route head", method: http.MethodHead, path: "/settings/profile", status: http.StatusOK, bodyAbsent: true},
		{name: "missing asset", method: http.MethodGet, path: "/assets/missing.js", status: http.StatusNotFound, notSPA: true},
		{name: "post frontend route", method: http.MethodPost, path: "/settings/profile", status: http.StatusNotFound, notSPA: true},
		{name: "options frontend route", method: http.MethodOptions, path: "/settings/profile", status: http.StatusNotFound, notSPA: true},
		{name: "reserved api root", method: http.MethodGet, path: "/api", status: http.StatusNotFound, notSPA: true},
		{name: "unknown api", method: http.MethodGet, path: "/api/unknown", status: http.StatusNotFound, notSPA: true},
		{name: "normalized reserved api", method: http.MethodGet, path: "/./api", status: http.StatusNotFound, notSPA: true},
		{name: "path traversal", method: http.MethodGet, path: "/../settings/profile", status: http.StatusNotFound, notSPA: true},
		{name: "encoded path traversal", method: http.MethodGet, path: "/%2e%2e/settings/profile", status: http.StatusNotFound, notSPA: true},
		{name: "encoded backslash", method: http.MethodGet, path: "/%5csettings/profile", status: http.StatusNotFound, notSPA: true},
		{name: "encoded control character", method: http.MethodGet, path: "/%09settings/profile", status: http.StatusNotFound, notSPA: true},
		{name: "unicode control character", method: http.MethodGet, path: "/%C2%85settings/profile", status: http.StatusNotFound, notSPA: true},
		{name: "reserved health root", method: http.MethodGet, path: "/health", status: http.StatusNotFound, notSPA: true},
		{name: "unknown health", method: http.MethodGet, path: "/health/unknown", status: http.StatusNotFound, notSPA: true},
		{name: "normalized reserved health", method: http.MethodGet, path: "/health/./unknown", status: http.StatusNotFound, notSPA: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, nil)
			engine.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
			if test.notSPA && strings.Contains(recorder.Body.String(), "<html>home</html>") {
				t.Fatalf("body unexpectedly contains SPA index: %q", recorder.Body.String())
			}
			if test.notSPA {
				return
			}
			if test.bodyAbsent {
				if recorder.Body.Len() != 0 {
					t.Fatalf("body = %q, want empty", recorder.Body.String())
				}
				return
			}
			if got := recorder.Body.String(); got != test.body {
				t.Fatalf("body = %q, want %q", got, test.body)
			}
		})
	}
}

func TestRegisterWebPreservesRegisteredRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	assets := fstestMapFS()
	translator, err := httpx.NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(
		func() bool { return true },
		config.HTTPConfig{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		ratelimit.New(100, 100),
		translator,
		[]gin.HandlerFunc{func(c *gin.Context) { c.Next() }},
		[]Register{func(api *gin.RouterGroup) {
			api.GET("/web-probe", func(c *gin.Context) { c.String(http.StatusTeapot, "api") })
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterWeb(engine, assets); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/web-probe", nil))
	if recorder.Code != http.StatusTeapot || recorder.Body.String() != "api" {
		t.Fatalf("registered API response = %d/%q, want 418/\"api\"", recorder.Code, recorder.Body.String())
	}
}

func TestRegisterWebRejectsMissingIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	if err := RegisterWeb(engine, fstest.MapFS{"assets/app.js": &fstest.MapFile{Data: []byte("js")}}); err == nil {
		t.Fatal("RegisterWeb() error = nil, want missing index rejection")
	}
	if err := RegisterWeb(engine, fstest.MapFS{"index.html": &fstest.MapFile{Mode: fs.ModeDir}}); err == nil {
		t.Fatal("RegisterWeb() error = nil, want non-file index rejection")
	}
}

func fstestMapFS() fs.FS {
	return fstest.MapFS{
		"index.html":        &fstest.MapFile{Data: []byte("<html>home</html>")},
		"assets/app.js":     &fstest.MapFile{Data: []byte("console.log('ok')")},
		"assets/app.css":    &fstest.MapFile{Data: []byte("body{}")},
		"assets/icon.svg":   &fstest.MapFile{Data: []byte("<svg></svg>")},
		"nested/index.html": &fstest.MapFile{Data: []byte("<html>nested</html>")},
		"routes/README.txt": &fstest.MapFile{Data: []byte("not a route")},
	}
}

func newWebTestRouter(t *testing.T, assets fs.FS) *gin.Engine {
	t.Helper()
	translator, err := httpx.NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(
		func() bool { return true },
		config.HTTPConfig{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		ratelimit.New(100, 100),
		translator,
		[]gin.HandlerFunc{func(c *gin.Context) { c.Next() }},
		[]Register{func(api *gin.RouterGroup) {
			api.GET("/web-probe", func(c *gin.Context) { c.String(http.StatusTeapot, "api") })
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterWeb(engine, assets); err != nil {
		t.Fatal(err)
	}
	return engine
}

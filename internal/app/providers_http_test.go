package app

import (
	"testing"
	"time"

	"furtalk/internal/platform/config"
	"github.com/gin-gonic/gin"
)

func TestProvideHTTPServerProjectsResourceLimits(t *testing.T) {
	t.Parallel()

	engine := gin.New()
	cfg := config.HTTPConfig{
		Address:           "127.0.0.1:9090",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       75 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	server := provideHTTPServer(cfg, engine)
	if server.Addr != cfg.Address || server.Handler != engine {
		t.Fatalf("server address/handler = %q/%T, want %q/engine", server.Addr, server.Handler, cfg.Address)
	}
	if server.ReadHeaderTimeout != cfg.ReadHeaderTimeout || server.ReadTimeout != cfg.ReadTimeout ||
		server.WriteTimeout != cfg.WriteTimeout || server.IdleTimeout != cfg.IdleTimeout ||
		server.MaxHeaderBytes != cfg.MaxHeaderBytes {
		t.Fatalf("server limits = %+v, want HTTP config %+v", server, cfg)
	}
}

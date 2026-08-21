//go:build !embed

package app

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"furtalk/internal/platform/config"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/ratelimit"
	"furtalk/internal/platform/webui"
	"furtalk/internal/router"
	"furtalk/internal/service/identity"
	"github.com/gin-gonic/gin"
)

func TestProvideRouterRejectsWebWithoutEmbedResources(t *testing.T) {
	translator, err := httpx.NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	_, err = provideRouter(
		newReadiness(),
		config.HTTPConfig{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		ratelimit.New(10, 10),
		translator,
		[]gin.HandlerFunc{func(c *gin.Context) { c.Next() }},
		[]router.Register{func(*gin.RouterGroup) {}},
		(*identity.Service)(nil),
		webRuntimeOptions{Enabled: true},
	)
	if !errors.Is(err, webui.ErrUnavailable) {
		t.Fatalf("provideRouter() error = %v, want webui.ErrUnavailable", err)
	}
}

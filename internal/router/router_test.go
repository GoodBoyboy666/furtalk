package router

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"furtalk/internal/platform/config"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/ratelimit"
	"github.com/gin-gonic/gin"
)

// TestRouterRegistersFrozenContract 验证冻结的路由表。
func TestRouterRegistersFrozenContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	translator, err := httpx.NewTranslator(httpx.ProtocolErrorMappings())
	if err != nil {
		t.Fatal(err)
	}
	registers := []Register{
		func(api *gin.RouterGroup) {
			api.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		},
	}
	engine, err := New(
		func() bool { return false },
		config.HTTPConfig{BodyLimit: 1 << 20, RateLimitRate: 100, RateLimitBurst: 100},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		ratelimit.New(100, 100),
		translator,
		[]gin.HandlerFunc{func(c *gin.Context) { c.Next() }},
		registers,
	)
	if err != nil {
		t.Fatal(err)
	}

	got := make([]string, 0, len(engine.Routes()))
	for _, route := range engine.Routes() {
		got = append(got, route.Method+" "+route.Path)
	}
	sort.Strings(got)
	want := []string{
		"GET /api/v1/probe",
		"GET /health/live",
		"GET /health/ready",
	}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("route count = %d, want %d\ngot: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("route[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRouterRejectsEmptyRegisters 验证空注册函数列表被拒绝。
func TestRouterRejectsEmptyRegisters(t *testing.T) {
	translator, err := httpx.NewTranslator()
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(
		func() bool { return false }, config.HTTPConfig{}, slog.Default(), ratelimit.New(1, 1), translator,
		[]gin.HandlerFunc{func(c *gin.Context) { c.Next() }}, nil,
	)
	if err == nil {
		t.Fatal("New() error = nil for empty registers, want rejection")
	}
}

// TestReadinessEndpointUsesSuppliedState 验证 readiness 状态由组合根控制。
func TestReadinessEndpointUsesSuppliedState(t *testing.T) {
	ready := false
	translator, err := httpx.NewTranslator(httpx.ProtocolErrorMappings())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(
		func() bool { return ready },
		config.HTTPConfig{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		ratelimit.New(100, 100),
		translator,
		[]gin.HandlerFunc{func(c *gin.Context) { c.Next() }},
		[]Register{func(api *gin.RouterGroup) { api.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) }) }},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		ready  bool
		status int
	}{
		{name: "not ready", ready: false, status: http.StatusServiceUnavailable},
		{name: "ready", ready: true, status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			ready = test.ready
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

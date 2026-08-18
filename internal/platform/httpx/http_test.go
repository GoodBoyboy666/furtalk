package httpx

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"furtalk/internal/platform/logging"
	"github.com/gin-gonic/gin"
)

// TestRequestIDPropagatesToContext 验证请求 ID 同时写入 Gin 上下文与标准 context。
func TestRequestIDPropagatesToContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestID())
	r.GET("/probe", func(c *gin.Context) {
		found := false
		for _, a := range logging.AttrsFrom(c.Request.Context()) {
			if a.Key == "request_id" && a.Value.String() != "" {
				found = true
			}
		}
		if !found {
			t.Fatal("request_id missing from request context")
		}
		if c.GetString(RequestIDKey) == "" {
			t.Fatal("request_id missing from gin context")
		}
		c.Status(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe", nil))
	if recorder.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID response header missing")
	}
}

// TestAccessLogDerivesContextAttrs 验证 AccessLog 从当前请求 context 派生关联字段，
// 能看到后续中间件追加的 user_id，且不泄露 query/header/body。
func TestAccessLogDerivesContextAttrs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)
	r := gin.New()
	r.Use(RequestID())
	r.Use(AccessLog(logger))
	// 模拟后续鉴权中间件追加业务 ID。
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(logging.WithAttrs(c.Request.Context(), logging.ID("user_id", 42)))
		c.Next()
	})
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe?x=secret-query", nil))

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode access log: %v\nraw: %s", err, buf.String())
	}
	if record["method"] != "GET" || record["path"] != "/probe" || record["status"] != float64(http.StatusNoContent) {
		t.Fatalf("access log method/path/status = %v/%v/%v", record["method"], record["path"], record["status"])
	}
	requestID, _ := record["request_id"].(string)
	if requestID == "" {
		t.Fatal("access log must include request_id")
	}
	if record["user_id"] != "42" {
		t.Fatalf("access log user_id = %v, want 42", record["user_id"])
	}
	if _, ok := record["duration_ms"].(float64); !ok {
		t.Fatalf("duration_ms = %T, want JSON number", record["duration_ms"])
	}
	if strings.Contains(buf.String(), "secret-query") {
		t.Fatal("access log leaks query string")
	}
}

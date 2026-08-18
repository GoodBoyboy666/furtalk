package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// decodeBodyRequest 构造带指定 Content-Type 与 body 的请求并经 DecodeBody 解码。
func decodeBodyRequest(t *testing.T, contentType, body string) error {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var got error
	router.POST("/echo", func(c *gin.Context) {
		var target struct {
			Value string `json:"value"`
		}
		got = DecodeBody(c, &target)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	router.ServeHTTP(rec, req)
	return got
}

// TestDecodeBodyAcceptsJSON 验证合法 application/json（含参数）通过。
func TestDecodeBodyAcceptsJSON(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		contentType string
	}{
		{name: "plain", contentType: "application/json"},
		{name: "charset parameter", contentType: "application/json; charset=utf-8"},
		{name: "uppercase media type", contentType: "Application/JSON"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := decodeBodyRequest(t, tt.contentType, `{"value":"ok"}`); err != nil {
				t.Fatalf("DecodeBody err = %v, want nil", err)
			}
		})
	}
}

// TestDecodeBodyRejectsNonJSON 验证缺失或非 JSON Content-Type 返回 415 语义错误。
func TestDecodeBodyRejectsNonJSON(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		contentType string
	}{
		{name: "missing", contentType: ""},
		{name: "text plain", contentType: "text/plain"},
		{name: "form", contentType: "application/x-www-form-urlencoded"},
		{name: "malformed", contentType: "application/json; charset"},
		{name: "wrong json-ish", contentType: "text/json"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := decodeBodyRequest(t, tt.contentType, `{"value":"ok"}`); err != ErrUnsupportedMediaType {
				t.Fatalf("DecodeBody err = %v, want ErrUnsupportedMediaType", err)
			}
		})
	}
}

// TestDecodeBodyOrdering 验证 Content-Type 校验先于 body 校验：
// 非 JSON Content-Type 即使 body 空或畸形也返回 415。
func TestDecodeBodyOrdering(t *testing.T) {
	t.Parallel()
	if err := decodeBodyRequest(t, "text/plain", ""); err != ErrUnsupportedMediaType {
		t.Fatalf("DecodeBody(text/plain, empty) err = %v, want ErrUnsupportedMediaType", err)
	}
}

// TestDecodeBodyJSONStrictnessPreserved 验证合法 Content-Type 下原有 JSON
// 严格解码语义保持不变：空 body、畸形 JSON、多 JSON 值与未知字段。
func TestDecodeBodyJSONStrictnessPreserved(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want error
	}{
		{name: "empty body", body: "", want: ErrMissingBody},
		{name: "malformed", body: `{`, want: ErrMalformedBody},
		{name: "multiple values", body: `{} {}`, want: ErrMultipleObjects},
		{name: "unknown field", body: `{"unknown":1}`, want: ErrMalformedBody},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := decodeBodyRequest(t, "application/json", tt.body); err != tt.want {
				t.Fatalf("DecodeErr = %v, want %v", err, tt.want)
			}
		})
	}
}

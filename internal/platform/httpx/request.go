package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	// ErrMissingBody 请求体为空。
	ErrMissingBody = errors.New("httpx: request body is missing")
	// ErrMalformedBody 请求体不是合法 JSON。
	ErrMalformedBody = errors.New("httpx: request body is malformed")
	// ErrMultipleObjects 请求体包含多个 JSON 值。
	ErrMultipleObjects = errors.New("httpx: request body has multiple values")
	// ErrInvalidID 路径/查询参数不是正整数 id。
	ErrInvalidID = errors.New("httpx: invalid id")
	// ErrUnsupportedMediaType Content-Type 不是 application/json。
	ErrUnsupportedMediaType = errors.New("httpx: unsupported media type")
)

// ProtocolErrorMappings 返回请求解析层错误的 HTTP 映射组。
func ProtocolErrorMappings() []Mapping {
	return []Mapping{
		{Target: ErrMissingBody, Status: http.StatusBadRequest, Code: "invalid_request_body", Message: "请求体不能为空"},
		{Target: ErrMalformedBody, Status: http.StatusBadRequest, Code: "invalid_request_body", Message: "请求体格式错误"},
		{Target: ErrMultipleObjects, Status: http.StatusBadRequest, Code: "invalid_request_body", Message: "请求体必须包含单个 JSON 对象"},
		{Target: ErrInvalidID, Status: http.StatusBadRequest, Code: "invalid_id", Message: "标识符无效"},
		{Target: ErrUnsupportedMediaType, Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Content-Type 必须为 application/json"},
	}
}

// DecodeBody 严格解码单个 JSON 对象到 into，拒绝未知字段与尾随内容。
// 仅接受 application/json（含合法参数，如 application/json; charset=utf-8）；
// 缺失、格式错误或其它 media type 返回 ErrUnsupportedMediaType。
// 空请求体返回 ErrMissingBody，格式错误返回 ErrMalformedBody，
// 多个 JSON 值返回 ErrMultipleObjects。
func DecodeBody(c *gin.Context, into any) error {
	if err := requireJSONContentType(c); err != nil {
		return err
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		if errors.Is(err, io.EOF) {
			return ErrMissingBody
		}
		return ErrMalformedBody
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ErrMultipleObjects
	}
	return nil
}

// requireJSONContentType 校验请求 Content-Type 为 application/json。
// 兼容合法参数（如 charset），缺失或其它 media type 返回 ErrUnsupportedMediaType。
func requireJSONContentType(c *gin.Context) error {
	raw := c.GetHeader("Content-Type")
	if raw == "" {
		return ErrUnsupportedMediaType
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return ErrUnsupportedMediaType
	}
	return nil
}

// ParseIDParam 解析路由参数 name 中的十进制正整数 id。
func ParseIDParam(c *gin.Context, name string) (int64, error) {
	return ParseDecimalID(c.Param(name))
}

// ParseDecimalID 把十进制字符串解析为正整数 id，非法输入返回 ErrInvalidID。
func ParseDecimalID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, ErrInvalidID
	}
	return id, nil
}

// ParseOptionalID 解析可选的十进制 id。
// 空字符串或 nil 返回 nil，否则按 ParseDecimalID 解析。
func ParseOptionalID(raw *string) (*int64, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, nil
	}
	id, err := ParseDecimalID(*raw)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// ParseOptionalQueryID 解析可选的查询参数 id，参数缺失时返回 nil。
func ParseOptionalQueryID(c *gin.Context, name string) (*int64, error) {
	raw := c.Query(name)
	if raw == "" {
		return nil, nil
	}
	return ParseOptionalID(&raw)
}

// ParseOptionalTime 解析可选的 RFC3339 时间，空字符串返回 nil。
func ParseOptionalTime(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, ErrInvalidID
	}
	return &parsed, nil
}

// ParseOptionalQueryBool 解析可选的布尔查询参数，参数缺失时返回 nil。
func ParseOptionalQueryBool(c *gin.Context, name string) (*bool, error) {
	raw := c.Query(name)
	if raw == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, ErrInvalidID
	}
	return &parsed, nil
}

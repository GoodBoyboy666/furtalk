// Package httpx 提供与业务无关的 HTTP 协议基础设施。
package httpx

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
)

// ErrorResponse 是错误响应的 JSON 信封，包含单个 error 对象。
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody 描述一个语义错误：机器可读的 code、人类可读的 message、
// 关联的 request_id 以及可选的 details。
type ErrorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id"`
	Details   map[string]any `json:"details"`
}

// Mapping 描述一个语义错误在 HTTP 边界上的映射：
// 目标错误、响应状态码、错误码与展示消息。
type Mapping struct {
	Target  error
	Status  int
	Code    string
	Message string
}

// Translator 是不可变、确定性的语义错误翻译表。
type Translator struct {
	mappings []Mapping
}

// NewTranslator 合并若干错误映射组并校验合法性：
// 目标错误必须非空且可比较，状态码必须落在 4xx/5xx，
// code 与 message 非空，且目标错误不能重复。
func NewTranslator(groups ...[]Mapping) (*Translator, error) {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	mappings := make([]Mapping, 0, total)
	seen := make(map[error]struct{}, total)
	for _, group := range groups {
		for _, mapping := range group {
			if mapping.Target == nil {
				return nil, errors.New("httpx: mapping target is nil")
			}
			if !reflect.TypeOf(mapping.Target).Comparable() {
				return nil, fmt.Errorf("httpx: mapping target %T is not comparable", mapping.Target)
			}
			if mapping.Status < 400 || mapping.Status > 599 {
				return nil, fmt.Errorf("httpx: invalid mapping status %d", mapping.Status)
			}
			if mapping.Code == "" || mapping.Message == "" {
				return nil, errors.New("httpx: mapping code and message are required")
			}
			if _, exists := seen[mapping.Target]; exists {
				return nil, fmt.Errorf("httpx: duplicate mapping target %v", mapping.Target)
			}
			seen[mapping.Target] = struct{}{}
			mappings = append(mappings, mapping)
		}
	}
	return &Translator{mappings: mappings}, nil
}

// Translate 在映射表中查找能匹配 err 的错误。
// 入参为 nil 或未找到匹配时返回空映射与 false。
func (t *Translator) Translate(err error) (Mapping, bool) {
	if t == nil || err == nil {
		return Mapping{}, false
	}
	for _, mapping := range t.mappings {
		if errors.Is(err, mapping.Target) {
			return mapping, true
		}
	}
	return Mapping{}, false
}

const translatorContextKey = "httpx.error_translator"

// WriteError 使用上下文中的翻译器把 err 转为响应。
// 未匹配到映射或未挂载翻译器时，回退为 500 内部错误。
func WriteError(c *gin.Context, err error) {
	translator, _ := c.Get(translatorContextKey)
	if typed, ok := translator.(*Translator); ok {
		if mapping, found := typed.Translate(err); found {
			c.JSON(mapping.Status, Response(c, mapping.Code, mapping.Message))
			return
		}
	}
	_ = c.Error(err)
	c.JSON(http.StatusInternalServerError, Response(c, "internal_error", "服务器内部错误"))
}

// Abort 以给定状态码与错误信息中止请求并写入响应。
func Abort(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, Response(c, code, message))
}

// Response 构造携带当前请求 ID 的错误响应体。
func Response(c *gin.Context, code, message string) ErrorResponse {
	return ErrorResponse{Error: ErrorBody{
		Code: code, Message: message, RequestID: c.GetString(RequestIDKey), Details: map[string]any{},
	}}
}

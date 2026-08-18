// Package handler 是 HTTP 层：请求解析、身份提取、DTO 组装与错误→HTTP 映射。
// 按业务分文件，同属一个大包。不触碰 repository 与 GORM。
package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

// writeError 把业务错误统一映射为 HTTP 响应。
func writeError(c *gin.Context, err error) {
	httpx.WriteError(c, err)
}

func errorResponse(c *gin.Context, code, message string) httpx.ErrorResponse {
	return httpx.Response(c, code, message)
}

// requirePrincipal 返回已认证主体，缺失时写入 401 并终止请求。
func requirePrincipal(c *gin.Context) (domain.Principal, bool) {
	principal, ok := middleware.CurrentPrincipal(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, errorResponse(c, "unauthorized", "authentication required"))
		c.Abort()
		return domain.Principal{}, false
	}
	return principal, true
}

// currentUserID 返回已认证主体的 id，缺失时写入 401 并终止请求。
func currentUserID(c *gin.Context) (int64, bool) {
	principal, ok := requirePrincipal(c)
	if !ok {
		return 0, false
	}
	return principal.UserID, true
}

// rawMessage 把已解码的 JSON 值转回 json.RawMessage。
func rawMessage(value any) json.RawMessage {
	if value == nil {
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return data
}

// clientIPFromContext 从中间件设置的客户端 IP 键读取原始 IP。
func clientIPFromContext(c *gin.Context) net.IP {
	raw := c.GetString(httpx.ClientIPKey)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return net.ParseIP(raw)
}

// formatOptionalID 把可选业务 id 格式化为十进制字符串。
func formatOptionalID(id *int64) *string {
	if id == nil {
		return nil
	}
	value := strconv.FormatInt(*id, 10)
	return &value
}

// actingUserID 返回已认证主体的 id，不存在时返回 0（管理端路由始终在 RequireAdmin 之后）。
func actingUserID(c *gin.Context) int64 {
	if principal, ok := middleware.CurrentPrincipal(c); ok {
		return principal.UserID
	}
	return 0
}

// parsePage 解析页码查询参数：缺省为第 1 页；非正整数页码返回参数错误。
// 边界校验在本层完成，offset 的推导与溢出保护由领域层 OffsetForPage 负责。
func parsePage(c *gin.Context) (int, error) {
	raw := c.Query("page")
	if raw == "" {
		return 1, nil
	}
	page, err := strconv.Atoi(raw)
	if err != nil || page < 1 {
		return 0, httpx.ErrInvalidID
	}
	return page, nil
}

package handler

import (
	"net/http"

	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/bootstrap"
	"furtalk/internal/service/notification"
	"github.com/gin-gonic/gin"
)

// RegisterBootstrap 挂载引导子路由。
func RegisterBootstrap(api *gin.RouterGroup, service *bootstrap.Service) {
	group := api.Group("/bootstrap")
	group.GET("/status", bootstrapStatus(service))
	group.POST("/admin", bootstrapAdmin(service))
}

// RegisterNotification 挂载退订子路由。
func RegisterNotification(api *gin.RouterGroup, service *notification.Service) {
	api.POST("/notification-unsubscriptions", notificationUnsubscribe(service))
}

// @Summary 查询系统是否完成初始化
// @Tags bootstrap
// @Produce json
// @Success 200 {object} BootstrapStatusResponse "初始化状态"
// @Router /api/v1/bootstrap/status [get]
func bootstrapStatus(service *bootstrap.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		required, err := service.Status(c.Request.Context())
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, BootstrapStatusResponse{Required: required})
	}
}

// @Summary 创建首位管理员
// @Tags bootstrap
// @Accept json
// @Param body body BootstrapAdminRequest true "初始化令牌与管理账号"
// @Success 204 "初始化完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 409 {object} httpx.ErrorResponse "邮箱已被注册"
// @Failure 410 {object} httpx.ErrorResponse "初始化已不可用"
// @Router /api/v1/bootstrap/admin [post]
func bootstrapAdmin(service *bootstrap.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req BootstrapAdminRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		input := bootstrap.AdminInput{
			SetupToken: req.SetupToken,
			Email:      req.Email,
			Nickname:   req.Nickname,
			Password:   req.Password,
		}
		if err := service.CreateAdmin(c.Request.Context(), input); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 退订通知邮件
// @Tags notification
// @Accept json
// @Param body body UnsubscribeRequest true "邮件中的签名退订 token"
// @Success 204 "退订完成"
// @Failure 400 {object} httpx.ErrorResponse "退订令牌无效"
// @Router /api/v1/notification-unsubscriptions [post]
func notificationUnsubscribe(service *notification.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req UnsubscribeRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if err := service.Unsubscribe(c.Request.Context(), req.Token); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

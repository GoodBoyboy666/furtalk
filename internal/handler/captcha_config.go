package handler

import (
	"net/http"

	"furtalk/internal/service/setting"
	"github.com/gin-gonic/gin"
)

// RegisterCaptchaConfig 注册 HTTP 路由。
func RegisterCaptchaConfig(api *gin.RouterGroup, service *setting.CaptchaConfigService) {
	api.GET("/captcha/config", captchaConfig(service))
}

// captchaConfig 返回按 action 划分的公共 CAPTCHA 配置。
// @Summary 获取按 action 划分的公共 CAPTCHA 配置
// @Tags captcha
// @Produce json
// @Param action query string true "CAPTCHA 业务 action（如 password_login、comment）"
// @Success 200 {object} CaptchaConfigResponse "公共 CAPTCHA 配置（不含机密）"
// @Failure 422 "action 缺失或超长"
// @Failure 503 "验证码服务暂不可用"
// @Router /api/v1/captcha/config [get]
func captchaConfig(service *setting.CaptchaConfigService) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		cfg, err := service.PublicConfig(c.Request.Context(), c.Query("action"))
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toCaptchaConfigResponse(cfg))
	}
}

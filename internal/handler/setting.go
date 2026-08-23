package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/setting"
	"github.com/gin-gonic/gin"
)

// RegisterAdminSettings 挂载设置与提供商管理子路由。
func RegisterAdminSettings(admin *gin.RouterGroup, settingsService *setting.Service, providers *setting.ProviderService) {
	admin.GET("/settings", adminGetSettings(settingsService))
	admin.PATCH("/settings", adminPatchSettings(settingsService))

	admin.GET("/providers", adminListProviders(providers))
	admin.PUT("/providers/:provider_key", adminUpsertProvider(providers))
	admin.POST("/providers/:provider_key/test", adminTestProvider(providers))
	admin.DELETE("/providers/:provider_key", adminDeleteProvider(providers))
}

// RegisterAdminSMTP 挂载 SMTP 测试路由。
func RegisterAdminSMTP(admin *gin.RouterGroup, service *setting.SMTPProbe) {
	admin.POST("/smtp/test", adminSMTPTest(service))
}

// @Summary 读取系统设置
// @Tags admin-settings
// @Produce json
// @Success 200 {object} SettingsResponse "公开设置项列表"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Router /api/v1/admin/settings [get]
func adminGetSettings(service *setting.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		items, err := service.PublicItems(c.Request.Context())
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, SettingsResponse{Settings: items})
	}
}

// @Summary 更新系统设置
// @Tags admin-settings
// @Accept json
// @Produce json
// @Param body body SettingsPatchRequest true "需要修改的设置项"
// @Success 200 {object} SettingsResponse "更新后的完整设置列表"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/settings [patch]
func adminPatchSettings(service *setting.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SettingsPatchRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		updatedBy := actingUserID(c)
		items, err := service.Patch(c.Request.Context(), req.Settings, updatedBy)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, SettingsResponse{Settings: items})
	}
}

// @Summary 列出提供商配置
// @Tags admin-providers
// @Produce json
// @Success 200 {object} ProvidersResponse "提供商列表（不含机密；CAPTCHA 项无 enabled，OAuth/OIDC 与 Spam 项携带 enabled）"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Router /api/v1/admin/providers [get]
func adminListProviders(service *setting.ProviderService) gin.HandlerFunc {
	return func(c *gin.Context) {
		metas, err := service.List(c.Request.Context())
		if err != nil {
			writeError(c, err)
			return
		}
		out := make([]ProviderMetadata, 0, len(metas))
		for _, m := range metas {
			public := map[string]any{}
			if len(m.PublicConfig) > 0 {
				if err := json.Unmarshal(m.PublicConfig, &public); err != nil {
					writeError(c, err)
					return
				}
			}
			md := ProviderMetadata{
				ProviderKey:  m.ProviderKey,
				Kind:         string(m.Kind),
				Configured:   m.Configured,
				PublicConfig: public,
			}
			if m.Kind != domain.ProviderKindCaptcha {
				enabled := m.Enabled
				md.Enabled = &enabled
			}
			out = append(out, md)
		}
		c.JSON(http.StatusOK, ProvidersResponse{Providers: out})
	}
}

// @Summary 新增或更新提供商
// @Tags admin-providers
// @Accept json
// @Param provider_key path string true "提供商 key"
// @Param body body ProviderUpsertRequest true "提供商配置（CAPTCHA 不允许携带 enabled；Spam 必须携带 enabled）"
// @Success 204 "保存完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 500 {object} httpx.ErrorResponse "提供商密钥数据损坏"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/providers/{provider_key} [put]
func adminUpsertProvider(service *setting.ProviderService) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.Param("provider_key")
		var req ProviderUpsertRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		kind := domain.ProviderKind(req.Kind)
		config, err := json.Marshal(req.Config)
		if err != nil {
			writeError(c, err)
			return
		}
		switch kind {
		case domain.ProviderKindCaptcha:
			if req.Enabled != nil {
				writeError(c, fmt.Errorf("%w: captcha provider must not include enabled", domain.ErrValidation))
				return
			}
			err = service.UpsertCaptcha(c.Request.Context(), key, config)
		case domain.ProviderKindOAuth, domain.ProviderKindOIDC:
			enabled := false
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			err = service.UpsertAuth(c.Request.Context(), key, kind, enabled, config)
		case domain.ProviderKindSpam:
			if req.Enabled == nil {
				writeError(c, fmt.Errorf("%w: spam provider requires enabled", domain.ErrValidation))
				return
			}
			err = service.UpsertSpam(c.Request.Context(), key, *req.Enabled, config)
		default:
			err = fmt.Errorf("%w: unknown provider kind %q", domain.ErrValidation, kind)
		}
		if err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 删除提供商配置
// @Tags admin-providers
// @Param provider_key path string true "提供商 key"
// @Success 204 "删除完成"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "提供商不存在"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/providers/{provider_key} [delete]
func adminDeleteProvider(service *setting.ProviderService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := service.Delete(c.Request.Context(), c.Param("provider_key")); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 测试提供商连通性
// @Tags admin-providers
// @Produce json
// @Param provider_key path string true "提供商 key"
// @Success 200 {object} map[string]string "status=ok"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "提供商不存在"
// @Failure 503 {object} httpx.ErrorResponse "服务暂不可用"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/providers/{provider_key}/test [post]
func adminTestProvider(service *setting.ProviderService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := service.Test(c.Request.Context(), c.Param("provider_key")); err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

// @Summary 测试 SMTP 投递配置
// @Tags smtp
// @Produce json
// @Success 200 {object} map[string]string "status=ok"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 503 {object} httpx.ErrorResponse "投递失败"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/smtp/test [post]
func adminSMTPTest(service *setting.SMTPProbe) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := service.Test(c.Request.Context()); err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

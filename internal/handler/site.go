package handler

import (
	"net/http"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/site"
	"github.com/gin-gonic/gin"
)

// RegisterAdminSites 挂载 /api/v1/admin/sites 资源。
func RegisterAdminSites(admin *gin.RouterGroup, service *site.Service) {
	group := admin.Group("/sites")
	group.GET("", adminSitesList(service))
	group.POST("", adminSitesCreate(service))
	group.GET("/:site_id", adminSitesGet(service))
	group.PATCH("/:site_id", adminSitesUpdate(service))
	group.DELETE("/:site_id", adminSitesDelete(service))
	group.POST("/:site_id/origins", adminSitesAddOrigin(service))
	group.PATCH("/:site_id/origins/:origin_id", adminSitesUpdateOrigin(service))
	group.DELETE("/:site_id/origins/:origin_id", adminSitesRemoveOrigin(service))
}

// @Summary 列出站点
// @Tags admin-sites
// @Produce json
// @Success 200 {object} SiteListResponse "站点列表"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Router /api/v1/admin/sites [get]
func adminSitesList(service *site.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := service.List(c.Request.Context())
		if err != nil {
			writeError(c, err)
			return
		}
		out := make([]SiteResponse, 0, len(rows))
		for _, row := range rows {
			out = append(out, toSiteResponse(row))
		}
		c.JSON(http.StatusOK, SiteListResponse{Sites: out})
	}
}

// @Summary 创建站点
// @Tags admin-sites
// @Accept json
// @Produce json
// @Param body body SiteRequest true "站点名称与规范 URL"
// @Success 201 {object} SiteResponse "创建的站点"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 409 {object} httpx.ErrorResponse "站点冲突"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/sites [post]
func adminSitesCreate(service *site.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SiteRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		s, err := service.Create(c.Request.Context(), req.Name, req.CanonicalURL)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusCreated, toSiteResponse(*s))
	}
}

// @Summary 获取站点详情
// @Tags admin-sites
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Success 200 {object} SiteResponse "站点详情"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "站点不存在"
// @Router /api/v1/admin/sites/{site_id} [get]
func adminSitesGet(service *site.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		s, err := service.Get(c.Request.Context(), id)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toSiteResponse(*s))
	}
}

// @Summary 更新站点
// @Tags admin-sites
// @Accept json
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param body body SiteUpdateRequest true "可更新的字段"
// @Success 200 {object} SiteResponse "更新后的站点"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "站点不存在"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/sites/{site_id} [patch]
func adminSitesUpdate(service *site.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req SiteUpdateRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		patch := site.SiteUpdate{Name: req.Name, CanonicalURL: req.CanonicalURL}
		if req.Status != nil {
			status := domain.SiteStatus(*req.Status)
			patch.Status = &status
		}
		s, err := service.Update(c.Request.Context(), id, patch)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toSiteResponse(*s))
	}
}

// @Summary 删除站点
// @Tags admin-sites
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param confirm query boolean false "删除需要显式确认"
// @Success 204 "删除完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "站点不存在"
// @Failure 409 {object} httpx.ErrorResponse "资源状态冲突"
// @Failure 422 {object} httpx.ErrorResponse "破坏性操作需要显式确认"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/sites/{site_id} [delete]
func adminSitesDelete(service *site.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		if err := service.Delete(c.Request.Context(), id, c.Query("confirm") == "true"); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 添加站点允许的 origin
// @Tags admin-sites
// @Accept json
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param body body OriginRequest true "精确 origin"
// @Success 201 {object} OriginResponse "创建的 origin"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "站点不存在"
// @Failure 409 {object} httpx.ErrorResponse "资源状态冲突"
// @Failure 422 {object} httpx.ErrorResponse "origin 格式非法"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/sites/{site_id}/origins [post]
func adminSitesAddOrigin(service *site.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req OriginRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		origin, err := service.AddOrigin(c.Request.Context(), siteID, req.Origin)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusCreated, toOriginResponse(*origin))
	}
}

// @Summary 更新站点允许的 origin
// @Tags admin-sites
// @Accept json
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param origin_id path integer true "origin ID（十进制字符串）"
// @Param body body OriginRequest true "精确 origin"
// @Success 200 {object} OriginResponse "更新后的 origin"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "站点或 origin 不存在"
// @Failure 409 {object} httpx.ErrorResponse "资源状态冲突"
// @Failure 422 {object} httpx.ErrorResponse "origin 格式非法"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/sites/{site_id}/origins/{origin_id} [patch]
func adminSitesUpdateOrigin(service *site.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		originID, err := httpx.ParseIDParam(c, "origin_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req OriginRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		origin, err := service.UpdateOrigin(c.Request.Context(), siteID, originID, req.Origin)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toOriginResponse(*origin))
	}
}

// @Summary 移除站点允许的 origin
// @Tags admin-sites
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param origin_id path integer true "origin ID（十进制字符串）"
// @Success 204 "移除完成"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "站点或 origin 不存在"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/sites/{site_id}/origins/{origin_id} [delete]
func adminSitesRemoveOrigin(service *site.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		originID, err := httpx.ParseIDParam(c, "origin_id")
		if err != nil {
			writeError(c, err)
			return
		}
		if err := service.RemoveOrigin(c.Request.Context(), siteID, originID); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

package handler

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/comment"
	"github.com/gin-gonic/gin"
)

// RegisterWidget 挂载全部 widget 端点。
func RegisterWidget(api *gin.RouterGroup, service *comment.Service, verifier comment.WidgetCredentialVerifier, settings comment.WidgetSettingsReader, authz middleware.PrincipalStore, origins httpx.OriginsProvider) {
	widget := api.Group("/widget")
	widgetCredential := middleware.WidgetPrincipalResolution(verifier, settings, authz)
	widgetOptionalCredential := middleware.WidgetOptionalResolution(verifier, settings, authz)
	widget.GET("/sites/:site_id/runtime-config", httpx.CORSForSiteParam("site_id", origins), widgetRuntimeConfig(service))
	widget.OPTIONS("/sites/:site_id/runtime-config", httpx.CORSForSiteParam("site_id", origins))
	widget.GET("/sites/:site_id/comments", httpx.CORSForSiteParam("site_id", origins), widgetOptionalCredential, widgetListComments(service))
	widget.OPTIONS("/sites/:site_id/comments", httpx.CORSForSiteParam("site_id", origins))
	widget.GET("/sites/:site_id/latest-comments", httpx.CORSForSiteParam("site_id", origins), widgetListLatestComments(service))
	widget.OPTIONS("/sites/:site_id/latest-comments", httpx.CORSForSiteParam("site_id", origins))

	widget.POST(
		"/sites/:site_id/comments",
		httpx.CORSForSiteParam("site_id", origins),
		widgetOptionalCredential,
		httpx.RequireAllowedOrigin(origins, httpx.SiteIDFromParam("site_id")),
		widgetCreateComment(service),
	)
	widget.DELETE("/comments/:comment_id", httpx.CORSForCredentialContext(), widgetCredential, httpx.RequireAllowedOrigin(origins, middleware.SiteIDFromCredential), widgetDeleteComment(service))
	widget.OPTIONS("/comments/:comment_id", httpx.CORSForCredentialContext())
	widget.PUT(
		"/sites/:site_id/comments/:comment_id/like",
		httpx.CORSForSiteParam("site_id", origins),
		widgetCredential,
		httpx.RequireAllowedOrigin(origins, httpx.SiteIDFromParam("site_id")),
		widgetLikeComment(service),
	)
	widget.DELETE(
		"/sites/:site_id/comments/:comment_id/like",
		httpx.CORSForSiteParam("site_id", origins),
		widgetCredential,
		httpx.RequireAllowedOrigin(origins, httpx.SiteIDFromParam("site_id")),
		widgetUnlikeComment(service),
	)
	widget.OPTIONS("/sites/:site_id/comments/:comment_id/like", httpx.CORSForSiteParam("site_id", origins))

	widget.POST("/comment-authorizations/exchange", httpx.CORSForCredentialContext(), widgetExchange(service))
	widget.OPTIONS("/comment-authorizations/exchange", httpx.CORSForCredentialContext())
	widget.GET("/session", httpx.CORSForCredentialContext(), widgetSession(service))
	widget.DELETE("/session", httpx.CORSForCredentialContext(), widgetClear(service))
	widget.OPTIONS("/session", httpx.CORSForCredentialContext())
}

// RegisterFirstPartyCommentAuthorization 挂载第一方评论授权签发端点。
func RegisterFirstPartyCommentAuthorization(api *gin.RouterGroup, service *comment.Service, userGate middleware.UserGate, csrf ...gin.HandlerFunc) {
	issueGroup := api.Group("/comment-authorizations")
	issueGroup.Use(append([]gin.HandlerFunc{middleware.RequireUser(userGate)}, csrf...)...)
	issueGroup.GET("/context", firstPartyAuthorizationContext(service))
	issueGroup.POST("", firstPartyIssueAuthorization(service))
}

// RegisterFirstParty 挂载第一方评论端点。
func RegisterFirstParty(api *gin.RouterGroup, service *comment.Service, userGate middleware.UserGate, csrf ...gin.HandlerFunc) {
	middlewares := append([]gin.HandlerFunc{middleware.RequireUser(userGate)}, csrf...)
	commentGroup := api.Group("/comments", middlewares...)
	commentGroup.POST("/:comment_id/replies", firstPartyCreateReply(service))
	commentGroup.DELETE("/:comment_id", firstPartyDelete(service))
}

// RegisterMeComments 挂载本人评论读取端点（RequireUser 门禁）。
func RegisterMeComments(api *gin.RouterGroup, service *comment.Service, userGate middleware.UserGate, csrf ...gin.HandlerFunc) {
	middlewares := append([]gin.HandlerFunc{middleware.RequireUser(userGate)}, csrf...)
	me := api.Group("/me", middlewares...)
	me.GET("/comments", meCommentsList(service))
	me.GET("/comments/sites", meCommentsSites(service))
	me.GET("/comments/:comment_id", meCommentsGet(service))
}

// @Summary 分页列出本人评论
// @Tags me
// @Produce json
// @Param site_id query integer false "站点 ID（十进制字符串）"
// @Param status query string false "pending | published | spam"
// @Param page query integer false "页码（从 1 开始，默认 1）"
// @Param limit query integer false "每页数量（默认 25）"
// @Success 200 {object} MeCommentListResponse "本人评论一页与匹配总数"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Router /api/v1/me/comments [get]
func meCommentsList(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := requirePrincipal(c)
		if !ok {
			return
		}
		var siteID *int64
		if parsed, err := httpx.ParseOptionalQueryID(c, "site_id"); err != nil {
			writeError(c, err)
			return
		} else {
			siteID = parsed
		}
		var status *domain.CommentStatus
		if raw := c.Query("status"); raw != "" {
			s := domain.CommentStatus(raw)
			if !validOwnerCommentStatus(s) {
				writeError(c, httpx.ErrInvalidID)
				return
			}
			status = &s
		}
		page, err := parsePage(c)
		if err != nil {
			writeError(c, err)
			return
		}
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
		result, err := service.ListByOwner(c.Request.Context(), principal.UserID, siteID, status, page, limit)
		if err != nil {
			writeError(c, err)
			return
		}
		resp := MeCommentListResponse{
			Comments:       make([]MeCommentResponse, 0, len(result.Comments)),
			Total:          result.Total,
			UserDeleteMode: result.UserDeleteMode,
		}
		for _, view := range result.Comments {
			resp.Comments = append(resp.Comments, toMeCommentResponse(view))
		}
		c.JSON(http.StatusOK, resp)
	}
}

// @Summary 列出本人评论的站点选项
// @Tags me
// @Produce json
// @Success 200 {object} MeCommentSitesResponse "本人发表过评论的站点"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Router /api/v1/me/comments/sites [get]
func meCommentsSites(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := requirePrincipal(c)
		if !ok {
			return
		}
		sites, err := service.ListOwnerSites(c.Request.Context(), principal.UserID)
		if err != nil {
			writeError(c, err)
			return
		}
		resp := MeCommentSitesResponse{Sites: make([]MeCommentSiteResponse, 0, len(sites))}
		for _, s := range sites {
			resp.Sites = append(resp.Sites, MeCommentSiteResponse{
				ID:   strconv.FormatInt(s.ID, 10),
				Name: s.Name,
			})
		}
		c.JSON(http.StatusOK, resp)
	}
}

// @Summary 获取本人单条评论详情
// @Tags me
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} MeCommentDetailResponse "本人评论详情"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在或不属于当前用户"
// @Router /api/v1/me/comments/{comment_id} [get]
func meCommentsGet(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := requirePrincipal(c)
		if !ok {
			return
		}
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		detail, err := service.GetByOwner(c.Request.Context(), principal.UserID, commentID)
		if err != nil {
			writeError(c, err)
			return
		}
		resp := toMeCommentDetailResponse(*detail)
		c.JSON(http.StatusOK, resp)
	}
}

// RegisterAdminComments 挂载管理端评论端点。
func RegisterAdminComments(admin *gin.RouterGroup, service *comment.Service) {
	admin.GET("/comments", adminCommentsList(service))
	admin.GET("/comments/:comment_id", adminCommentsGet(service))
	admin.PATCH("/comments/:comment_id", adminCommentsPatch(service))
	admin.POST("/comments/:comment_id/pending", adminCommentsPending(service))
	admin.POST("/comments/:comment_id/publish", adminCommentsPublish(service))
	admin.POST("/comments/:comment_id/spam", adminCommentsSpam(service))
	admin.DELETE("/comments/:comment_id", adminCommentsDelete(service))
	admin.POST("/comments/:comment_id/restore", adminCommentsRestore(service))
}

// RegisterAdminThreads 挂载管理端线程（评论区开关）端点。
func RegisterAdminThreads(admin *gin.RouterGroup, service *comment.Service) {
	group := admin.Group("/sites/:site_id/threads")
	group.GET("", adminThreadsList(service))
	group.PATCH("/:thread_id", adminThreadsPatch(service))
	group.DELETE("/:thread_id", adminThreadsDelete(service))
}

// @Summary 按站点列出线程
// @Tags admin-threads
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param comments_enabled query boolean false "按评论开关过滤"
// @Param q query string false "搜索 page_key/page_title/page_url"
// @Param sort query string false "排序方向：asc（最早优先）或 desc（最新优先，默认）"
// @Param page query integer false "页码（从 1 开始，默认 1）"
// @Param limit query integer false "每页数量（默认 25）"
// @Success 200 {object} AdminThreadListResponse "一页线程与匹配总数"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Router /api/v1/admin/sites/{site_id}/threads [get]
func adminThreadsList(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var enabled *bool
		if enabled, err = httpx.ParseOptionalQueryBool(c, "comments_enabled"); err != nil {
			writeError(c, err)
			return
		}
		sort, err := domain.NormalizeAdminSort(c.Query("sort"))
		if err != nil {
			writeError(c, err)
			return
		}
		page, err := parsePage(c)
		if err != nil {
			writeError(c, err)
			return
		}
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
		result, err := service.AdminListThreads(c.Request.Context(), siteID, enabled, c.Query("q"), page, sort, limit)
		if err != nil {
			writeError(c, err)
			return
		}
		resp := AdminThreadListResponse{
			Threads: make([]AdminThreadResponse, 0, len(result.Threads)),
			Total:   result.Total,
		}
		for _, view := range result.Threads {
			resp.Threads = append(resp.Threads, toAdminThreadResponse(view))
		}
		c.JSON(http.StatusOK, resp)
	}
}

// @Summary 更新线程元数据（page_key / page_title / comments_enabled）
// @Tags admin-threads
// @Accept json
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param thread_id path integer true "线程 ID（十进制字符串）"
// @Param body body AdminThreadUpdateRequest true "新的线程元数据（至少一个字段）"
// @Success 200 {object} AdminThreadResponse "更新后的线程视图"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "线程不存在或不属于该站点"
// @Failure 409 {object} httpx.ErrorResponse "page_key 在站点内重复"
// @Failure 422 {object} httpx.ErrorResponse "缺少任何更新字段或字段校验失败"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/sites/{site_id}/threads/{thread_id} [patch]
func adminThreadsPatch(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		threadID, err := httpx.ParseIDParam(c, "thread_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req AdminThreadUpdateRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		if req.PageKey == nil && !req.PageTitle.Set && !req.PageURL.Set && req.CommentsEnabled == nil {
			c.JSON(http.StatusUnprocessableEntity, errorResponse(c, "invalid_input", "至少提供一个更新字段"))
			return
		}
		view, err := service.AdminUpdateThread(c.Request.Context(), siteID, threadID, comment.AdminThreadUpdateInput{
			PageKey:         req.PageKey,
			PageTitle:       comment.OptionalNullableString{Set: req.PageTitle.Set, Value: req.PageTitle.Value},
			PageURL:         comment.OptionalNullableString{Set: req.PageURL.Set, Value: req.PageURL.Value},
			CommentsEnabled: req.CommentsEnabled,
		})
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminThreadResponse(*view))
	}
}

// @Summary 硬删除线程及其全部评论
// @Tags admin-threads
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param thread_id path integer true "线程 ID（十进制字符串）"
// @Param confirm query boolean true "破坏性操作需要显式确认"
// @Success 204 "删除成功"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Failure 404 {object} httpx.ErrorResponse "线程不存在或不属于该站点"
// @Failure 422 {object} httpx.ErrorResponse "破坏性操作需要显式确认"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/sites/{site_id}/threads/{thread_id} [delete]
func adminThreadsDelete(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		threadID, err := httpx.ParseIDParam(c, "thread_id")
		if err != nil {
			writeError(c, err)
			return
		}
		confirm := c.Query("confirm") == "true"
		if err := service.AdminDeleteThread(c.Request.Context(), siteID, threadID, confirm); err != nil {
			writeError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// @Summary 获取 widget 运行时配置
// @Tags widget
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Success 200 {object} RuntimeConfigResponse "运行时配置"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 403 {object} httpx.ErrorResponse "站点已停用"
// @Failure 404 {object} httpx.ErrorResponse "站点不存在"
// @Router /api/v1/widget/sites/{site_id}/runtime-config [get]
func widgetRuntimeConfig(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		rc, err := service.RuntimeConfig(c.Request.Context(), siteID)
		if err != nil {
			writeError(c, err)
			return
		}
		// no-store：管理员修改 emoji_catalog_url 后，新初始化的 Widget
		// 不能命中浏览器/中间代理的旧缓存。
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, toRuntimeConfigResponse(rc))
	}
}

// @Summary 列出 widget 线程评论
// @Tags widget
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param page_key query string true "页面标识（必填）"
// @Param sort query string false "排序：asc（按 (created_at,id) 升序）、desc（按 (created_at,id) 降序）或 hot（按 (like_count,created_at,id) 降序）"
// @Param cursor query string false "不透明的排序游标（与 sort 对应，hot 游标只能用于 hot）"
// @Param limit query integer false "每页数量（默认 50）"
// @Success 200 {object} ThreadCommentsResponse "评论列表"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 403 {object} httpx.ErrorResponse "站点已停用"
// @Failure 404 {object} httpx.ErrorResponse "线程不存在"
// @Router /api/v1/widget/sites/{site_id}/comments [get]
func widgetListComments(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		var viewerID *int64
		if cred, ok := middleware.WidgetCredentialOf(c); ok {
			viewerID = comment.ViewerState(cred)
		}
		view, err := service.ListPublic(c.Request.Context(), siteID, c.Query("page_key"), c.Query("cursor"), c.Query("sort"), limit, viewerID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toThreadCommentsResponse(view))
	}
}

// @Summary 点赞一条已发布的评论
// @Tags widget
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} LikeResponse "权威的点赞计数与状态（重复点赞幂等成功）"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "缺少 widget 凭证"
// @Failure 403 {object} httpx.ErrorResponse "凭证不再适用、站点不匹配或 origin 不被允许"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在或未发布"
// @Router /api/v1/widget/sites/{site_id}/comments/{comment_id}/like [put]
func widgetLikeComment(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		cred, ok := middleware.WidgetCredentialOf(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, errorResponse(c, "unauthorized", "widget credential required"))
			return
		}
		result, err := service.LikeComment(c.Request.Context(), siteID, commentID, cred.UserID())
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toLikeResponse(result))
	}
}

// @Summary 取消点赞一条已发布的评论
// @Tags widget
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} LikeResponse "权威的点赞计数与状态（重复取消幂等成功，计数不为负）"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "缺少 widget 凭证"
// @Failure 403 {object} httpx.ErrorResponse "凭证不再适用、站点不匹配或 origin 不被允许"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在或未发布"
// @Router /api/v1/widget/sites/{site_id}/comments/{comment_id}/like [delete]
func widgetUnlikeComment(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		cred, ok := middleware.WidgetCredentialOf(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, errorResponse(c, "unauthorized", "widget credential required"))
			return
		}
		result, err := service.UnlikeComment(c.Request.Context(), siteID, commentID, cred.UserID())
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toLikeResponse(result))
	}
}

// @Summary 列出站点最新公开评论
// @Tags widget
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param limit query integer false "返回数量（默认 25，最大 25）"
// @Success 200 {object} LatestCommentListResponse "最新评论列表"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 403 {object} httpx.ErrorResponse "站点已停用"
// @Failure 404 {object} httpx.ErrorResponse "站点不存在"
// @Router /api/v1/widget/sites/{site_id}/latest-comments [get]
func widgetListLatestComments(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
		views, err := service.ListLatestPublic(c.Request.Context(), siteID, limit)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toLatestCommentListResponse(views))
	}
}

// @Summary 创建 widget 评论
// @Tags widget
// @Accept json
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param body body CreateCommentRequest true "评论内容与署名资料"
// @Success 201 {object} CommentResponse "创建的评论"
// @Success 200 {object} WidgetAuthorizationRequiredResponse "提交邮箱对应管理员，需要先经第一方显式授权"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "缺少 widget 凭证或凭证无效"
// @Failure 403 {object} httpx.ErrorResponse "origin 不被允许或验证码失败"
// @Failure 404 {object} httpx.ErrorResponse "站点或父评论不存在"
// @Failure 409 {object} httpx.ErrorResponse "父评论已删除或跨线程回复"
// @Failure 422 {object} httpx.ErrorResponse "需要验证码或回复深度超限"
// @Failure 503 {object} httpx.ErrorResponse "验证码服务暂不可用"
// @Router /api/v1/widget/sites/{site_id}/comments [post]
func widgetCreateComment(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req CreateCommentRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		parentID, err := httpx.ParseOptionalID(req.ParentID)
		if err != nil {
			writeError(c, err)
			return
		}
		var cred comment.WidgetCredential
		if c, ok := middleware.WidgetCredentialOf(c); ok {
			cred = c
		}
		input := comment.CreateInput{
			SiteID:       siteID,
			PageKey:      req.PageKey,
			PageURL:      req.PageURL,
			PageTitle:    req.PageTitle,
			ParentID:     parentID,
			BodyMarkdown: req.BodyMarkdown,
			IP:           clientIPFromContext(c),
			UA:           c.GetHeader("User-Agent"),
			CaptchaToken: req.CaptchaToken,
			Origin:       httpx.ValidRequestOrigin(c),
			Email:        req.Email,
			Nickname:     req.Nickname,
			WebsiteURL: comment.WebsiteOperation{
				Set:   req.WebsiteURL.Set,
				Value: req.WebsiteURL.Value,
			},
			Credential: cred,
		}
		view, err := service.Create(c.Request.Context(), input)
		if err != nil {
			if errors.Is(err, domain.ErrAuthorizationRequired) {
				c.JSON(http.StatusOK, WidgetAuthorizationRequiredResponse{NeedAuthCode: true})
				return
			}
			writeError(c, err)
			return
		}
		c.JSON(http.StatusCreated, toCommentResponse(*view))
	}
}

// @Summary 删除自己的 widget 评论
// @Tags widget
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} CommentDeleteResponse "删除结果"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "缺少 widget 凭证"
// @Failure 403 {object} httpx.ErrorResponse "origin 不被允许"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Router /api/v1/widget/comments/{comment_id} [delete]
func widgetDeleteComment(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		cred, ok := middleware.WidgetCredentialOf(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, errorResponse(c, "unauthorized", "widget credential required"))
			return
		}
		siteID := cred.SiteID()
		result, err := service.DeleteByOwner(c.Request.Context(), cred.UserID(), commentID, &siteID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toCommentDeleteResponse(*result))
	}
}

// @Summary 为第一方页面签发一次性授权码
// @Tags first-party
// @Accept json
// @Produce json
// @Param body body AuthorizationIssueRequest true "站点与授权范围"
// @Success 201 {object} AuthorizationIssueResponse "一次性授权码"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 403 {object} httpx.ErrorResponse "CSRF token 无效"
// @Failure 404 {object} httpx.ErrorResponse "站点不存在"
// @Failure 422 {object} httpx.ErrorResponse "origin 格式无效"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/comment-authorizations [post]
func firstPartyIssueAuthorization(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		principal, ok := requirePrincipal(c)
		if !ok {
			return
		}
		var req AuthorizationIssueRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		siteID, err := httpx.ParseDecimalID(req.SiteID)
		if err != nil {
			writeError(c, err)
			return
		}
		origin, ok := httpx.CanonicalOrigin(req.Origin)
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, errorResponse(c, "invalid_input", "origin must be an exact https origin"))
			return
		}
		result, err := service.IssueAuthorization(c.Request.Context(), comment.IssueInput{
			SiteID:    siteID,
			Origin:    origin,
			RequestID: req.RequestID,
			UserID:    principal.UserID,
			Role:      principal.Role,
		})
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusCreated, AuthorizationIssueResponse{
			Code:      result.Code,
			RequestID: result.RequestID,
			ExpiresAt: result.ExpiresAt,
		})
	}
}

// @Summary 获取授权上下文（只读）
// @Tags first-party
// @Produce json
// @Param site_id query integer true "站点 ID（十进制字符串）"
// @Param origin query string true "嵌入方精确 Origin"
// @Success 200 {object} AuthorizationContextResponse "授权上下文"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 403 {object} httpx.ErrorResponse "站点不可用或 origin 不被允许"
// @Router /api/v1/comment-authorizations/context [get]
func firstPartyAuthorizationContext(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		principal, ok := requirePrincipal(c)
		if !ok {
			return
		}
		siteID, err := httpx.ParseOptionalQueryID(c, "site_id")
		if err != nil || siteID == nil {
			writeError(c, httpx.ErrInvalidID)
			return
		}
		origin, ok := httpx.CanonicalOrigin(c.Query("origin"))
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, errorResponse(c, "invalid_input", "origin must be an exact https origin"))
			return
		}
		view, err := service.AuthorizationContext(c.Request.Context(), *siteID, principal.Role, origin)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, AuthorizationContextResponse{
			SiteID:   strconv.FormatInt(view.SiteID, 10),
			SiteName: view.SiteName,
			Origin:   view.Origin,
		})
	}
}

// @Summary 用授权码交换 widget 会话凭证
// @Tags widget
// @Accept json
// @Param body body AuthorizationExchangeRequest true "授权码"
// @Success 204 "已写入 widget 会话 Cookie"
// @Failure 400 {object} httpx.ErrorResponse "授权码无效"
// @Failure 403 {object} httpx.ErrorResponse "origin 不被允许"
// @Router /api/v1/widget/comment-authorizations/exchange [post]
func widgetExchange(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req AuthorizationExchangeRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		requestOrigin := httpx.ValidRequestOrigin(c)
		result, err := service.ExchangeAuthorization(c.Request.Context(), req.Code, requestOrigin)
		if err != nil {
			writeError(c, err)
			return
		}
		setWidgetCookie(c, result)
		c.Status(http.StatusNoContent)
	}
}

// @Summary 探测当前 widget 会话
// @Tags widget
// @Produce json
// @Success 200 {object} WidgetSessionResponse "会话状态"
// @Router /api/v1/widget/session [get]
func widgetSession(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		raw, _ := c.Cookie(middleware.WidgetCookieName)
		requestOrigin := httpx.ValidRequestOrigin(c)
		result := service.Probe(c.Request.Context(), raw, requestOrigin)
		c.JSON(http.StatusOK, toWidgetSessionResponse(*result))
	}
}

// @Summary 清除当前 widget 会话
// @Tags widget
// @Success 204 "已清除会话 Cookie"
// @Router /api/v1/widget/session [delete]
func widgetClear(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		middleware.ClearWidgetCookie(c)
		c.Status(http.StatusNoContent)
	}
}

// @Summary 第一方回复评论
// @Tags first-party
// @Accept json
// @Produce json
// @Param comment_id path integer true "父评论 ID（十进制字符串）"
// @Param body body ReplyRequest true "回复正文（可附带 CAPTCHA token）"
// @Success 201 {object} CommentResponse "创建的回复"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 403 {object} httpx.ErrorResponse "验证码验证失败"
// @Failure 404 {object} httpx.ErrorResponse "父评论不存在"
// @Failure 409 {object} httpx.ErrorResponse "父评论已删除或跨线程回复"
// @Failure 422 {object} httpx.ErrorResponse "回复深度超过限制或缺少验证码"
// @Failure 503 {object} httpx.ErrorResponse "验证码服务暂不可用"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/comments/{comment_id}/replies [post]
func firstPartyCreateReply(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := requirePrincipal(c)
		if !ok {
			return
		}
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req ReplyRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		view, err := service.CreateReplyFirstParty(
			c.Request.Context(),
			principal.UserID,
			principal.Role,
			commentID,
			req.Body,
			req.CaptchaToken,
			clientIPFromContext(c),
			c.GetHeader("User-Agent"),
		)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusCreated, toCommentResponse(*view))
	}
}

// @Summary 第一方删除自己的评论
// @Tags first-party
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} CommentDeleteResponse "删除结果"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/comments/{comment_id} [delete]
func firstPartyDelete(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := requirePrincipal(c)
		if !ok {
			return
		}
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		result, err := service.DeleteByOwner(c.Request.Context(), principal.UserID, commentID, nil)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toCommentDeleteResponse(*result))
	}
}

// @Summary 使用过滤器与页码分页列出评论
// @Tags admin-comments
// @Produce json
// @Param site_id query integer false "站点 ID（十进制字符串）"
// @Param thread_id query integer false "线程 ID（十进制字符串）"
// @Param status query string false "pending | published | spam | deleted"
// @Param user_id query integer false "作者用户 ID（十进制字符串）"
// @Param q query string false "正文/作者邮箱/昵称搜索关键字"
// @Param since query string false "RFC3339 时间下限"
// @Param until query string false "RFC3339 时间上限"
// @Param sort query string false "排序方向：asc（最早优先）或 desc（最新优先，默认）"
// @Param page query integer false "页码（从 1 开始，默认 1）"
// @Param limit query integer false "每页数量（默认 25）"
// @Success 200 {object} AdminCommentListResponse "一页评论与匹配总数"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 403 {object} httpx.ErrorResponse "权限不足"
// @Router /api/v1/admin/comments [get]
func adminCommentsList(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		filter, err := parseAdminCommentFilter(c)
		if err != nil {
			writeError(c, err)
			return
		}
		page, err := parsePage(c)
		if err != nil {
			writeError(c, err)
			return
		}
		result, err := service.AdminList(c.Request.Context(), filter, page)
		if err != nil {
			writeError(c, err)
			return
		}
		resp := AdminCommentListResponse{
			Comments: make([]AdminCommentResponse, 0, len(result.Comments)),
			Total:    result.Total,
		}
		for _, view := range result.Comments {
			resp.Comments = append(resp.Comments, toAdminCommentResponse(view))
		}
		c.JSON(http.StatusOK, resp)
	}
}

// @Summary 获取单条评论的管理视图
// @Tags admin-comments
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} AdminCommentResponse "管理视图"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Router /api/v1/admin/comments/{comment_id} [get]
func adminCommentsGet(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		view, err := service.AdminGet(c.Request.Context(), commentID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminCommentResponse(*view))
	}
}

// @Summary 编辑评论的 Markdown 正文
// @Tags admin-comments
// @Accept json
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Param body body AdminCommentUpdateRequest true "新的正文"
// @Success 200 {object} AdminCommentResponse "更新后的管理视图"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/comments/{comment_id} [patch]
func adminCommentsPatch(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		var req AdminCommentUpdateRequest
		if err := httpx.DecodeBody(c, &req); err != nil {
			writeError(c, err)
			return
		}
		view, err := service.AdminEditBody(c.Request.Context(), commentID, req.Body)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminCommentResponse(*view))
	}
}

// @Summary 把评论移入待审核
// @Tags admin-comments
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} AdminCommentResponse "移动后的管理视图"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Failure 409 {object} httpx.ErrorResponse "评论状态冲突"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/comments/{comment_id}/pending [post]
func adminCommentsPending(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		view, err := service.AdminPending(c.Request.Context(), commentID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminCommentResponse(*view))
	}
}

// @Summary 发布待审评论
// @Tags admin-comments
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} AdminCommentResponse "发布后的管理视图"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Failure 409 {object} httpx.ErrorResponse "评论状态冲突"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/comments/{comment_id}/publish [post]
func adminCommentsPublish(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		view, err := service.AdminPublish(c.Request.Context(), commentID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminCommentResponse(*view))
	}
}

// @Summary 将评论标记为垃圾评论
// @Tags admin-comments
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} AdminCommentResponse "标记后的管理视图"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Failure 409 {object} httpx.ErrorResponse "评论状态冲突"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/comments/{comment_id}/spam [post]
func adminCommentsSpam(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		view, err := service.AdminMarkSpam(c.Request.Context(), commentID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminCommentResponse(*view))
	}
}

// @Summary 删除评论（软删除或硬删除）
// @Tags admin-comments
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Param hard query boolean false "是否物理删除"
// @Param confirm query boolean false "硬删除需要显式确认"
// @Success 200 {object} CommentDeleteResponse "删除结果"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Failure 409 {object} httpx.ErrorResponse "评论状态冲突"
// @Failure 422 {object} httpx.ErrorResponse "破坏性操作需要显式确认"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/comments/{comment_id} [delete]
func adminCommentsDelete(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		hard := c.Query("hard") == "true"
		confirm := c.Query("confirm") == "true"
		result, err := service.AdminDelete(c.Request.Context(), commentID, hard, confirm)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toCommentDeleteResponse(*result))
	}
}

// @Summary 恢复已删除的评论
// @Tags admin-comments
// @Produce json
// @Param comment_id path integer true "评论 ID（十进制字符串）"
// @Success 200 {object} AdminCommentResponse "恢复后的管理视图"
// @Failure 400 {object} httpx.ErrorResponse "请求参数无效"
// @Failure 401 {object} httpx.ErrorResponse "需要管理员登录"
// @Failure 404 {object} httpx.ErrorResponse "评论不存在"
// @Failure 409 {object} httpx.ErrorResponse "评论状态冲突"
// @Param X-CSRF-Token header string true "CSRF token"
// @Router /api/v1/admin/comments/{comment_id}/restore [post]
func adminCommentsRestore(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		commentID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		view, err := service.AdminRestore(c.Request.Context(), commentID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toAdminCommentResponse(*view))
	}
}

// parseAdminCommentFilter 解析管理员评论列表的过滤参数。
func parseAdminCommentFilter(c *gin.Context) (domain.AdminFilter, error) {
	filter := domain.AdminFilter{}
	var err error
	if filter.SiteID, err = httpx.ParseOptionalQueryID(c, "site_id"); err != nil {
		return filter, err
	}
	if filter.ThreadID, err = httpx.ParseOptionalQueryID(c, "thread_id"); err != nil {
		return filter, err
	}
	if filter.UserID, err = httpx.ParseOptionalQueryID(c, "user_id"); err != nil {
		return filter, err
	}
	if raw := c.Query("status"); raw != "" {
		status := domain.CommentStatus(raw)
		if !validCommentStatus(status) {
			return filter, httpx.ErrInvalidID
		}
		filter.Status = &status
	}
	filter.Q = c.Query("q")
	if filter.Since, err = httpx.ParseOptionalTime(c.Query("since")); err != nil {
		return filter, err
	}
	if filter.Until, err = httpx.ParseOptionalTime(c.Query("until")); err != nil {
		return filter, err
	}
	sort, err := domain.NormalizeAdminSort(c.Query("sort"))
	if err != nil {
		return filter, err
	}
	filter.Sort = sort
	if raw := c.Query("limit"); raw != "" {
		limit, parseErr := strconv.Atoi(raw)
		if parseErr != nil || limit <= 0 {
			return filter, httpx.ErrInvalidID
		}
		filter.Limit = limit
	}
	return filter, nil
}

// validCommentStatus 报告状态字符串是否为合法的审核状态。
func validCommentStatus(status domain.CommentStatus) bool {
	switch status {
	case domain.CommentStatusPending, domain.CommentStatusPublished, domain.CommentStatusSpam, domain.CommentStatusDeleted:
		return true
	default:
		return false
	}
}

// validOwnerCommentStatus 报告状态字符串是否为普通用户侧可见的审核状态。
// 软删除（deleted）对普通用户不可见，视为无效筛选参数。
func validOwnerCommentStatus(status domain.CommentStatus) bool {
	switch status {
	case domain.CommentStatusPending, domain.CommentStatusPublished, domain.CommentStatusSpam:
		return true
	default:
		return false
	}
}

// setWidgetCookie 以按 JWT 过期时间推导出的 Max-Age 写入 CHIPS Cookie。
func setWidgetCookie(c *gin.Context, result *comment.SessionResult) {
	maxAge := time.Until(result.ExpiresAt)
	middleware.SetWidgetCookie(c, result.Token, maxAge)
}

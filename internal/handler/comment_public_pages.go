package handler

import (
	"net/http"
	"strconv"

	"furtalk/internal/middleware"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/comment"

	"github.com/gin-gonic/gin"
)

// widgetListRootComments 处理 Widget 根评论分页请求。
// @Summary 分页列出 widget 线程的可见根评论
// @Description 仅返回根评论及 has_replies；先按置顶分组，再按根自身的时间或点赞数排序，游标绑定站点、线程和排序。
// @Tags widget
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param page_key query string true "页面标识（必填）"
// @Param sort query string false "排序：asc、desc 或 hot；缺省使用实例设置"
// @Param cursor query string false "根评论专用游标，必须匹配站点、线程和 sort"
// @Param limit query integer false "每页根评论数量（默认 50，最大 100）"
// @Success 200 {object} ThreadRootCommentsResponse "根评论分页"
// @Failure 400 {object} httpx.ErrorResponse "路径参数无效"
// @Failure 403 {object} httpx.ErrorResponse "站点已停用"
// @Failure 404 {object} httpx.ErrorResponse "站点不存在"
// @Failure 422 {object} httpx.ErrorResponse "页面标识、排序或游标无效"
// @Router /api/v1/widget/sites/{site_id}/root-comments [get]
func widgetListRootComments(service *comment.Service) gin.HandlerFunc {
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
		view, err := service.ListPublicRoots(c.Request.Context(), siteID, c.Query("page_key"), c.Query("cursor"), c.Query("sort"), limit, viewerID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toThreadRootCommentsResponse(view))
	}
}

// widgetListReplies 处理 Widget 可见根下的回复分页请求。
// @Summary 分页列出 widget 可见根评论的全部可见回复
// @Description 按 created_at、id 升序返回所有深度的回复，保留可见关系和原始深度；游标绑定站点、线程和根评论。
// @Tags widget
// @Produce json
// @Param site_id path integer true "站点 ID（十进制字符串）"
// @Param comment_id path integer true "可见根评论 ID（十进制字符串）"
// @Param page_key query string true "页面标识（必填，根评论须属于该线程）"
// @Param cursor query string false "回复专用游标，必须匹配站点、线程和根评论"
// @Param limit query integer false "每页回复数量（默认 50，最大 100）"
// @Success 200 {object} CommentRepliesResponse "回复分页；可见根无回复或游标耗尽时返回空数组"
// @Failure 400 {object} httpx.ErrorResponse "路径参数无效"
// @Failure 403 {object} httpx.ErrorResponse "站点已停用"
// @Failure 404 {object} httpx.ErrorResponse "站点、线程或可见根不存在"
// @Failure 422 {object} httpx.ErrorResponse "页面标识或游标无效"
// @Router /api/v1/widget/sites/{site_id}/comments/{comment_id}/replies [get]
func widgetListReplies(service *comment.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		siteID, err := httpx.ParseIDParam(c, "site_id")
		if err != nil {
			writeError(c, err)
			return
		}
		rootID, err := httpx.ParseIDParam(c, "comment_id")
		if err != nil {
			writeError(c, err)
			return
		}
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		var viewerID *int64
		if cred, ok := middleware.WidgetCredentialOf(c); ok {
			viewerID = comment.ViewerState(cred)
		}
		view, err := service.ListPublicReplies(c.Request.Context(), siteID, rootID, c.Query("page_key"), c.Query("cursor"), limit, viewerID)
		if err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, toCommentRepliesResponse(view))
	}
}

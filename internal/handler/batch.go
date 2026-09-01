package handler

import (
	"errors"
	"strconv"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"

	"github.com/gin-gonic/gin"
)

// AdminBatchRequest 三个管理员资源批量命令共用的请求体。
type AdminBatchRequest struct {
	IDs     []string `json:"ids"`
	Action  string   `json:"action"`
	Confirm bool     `json:"confirm"`
}

// AdminBatchResponse 三个管理员资源批量命令共用的成功响应。
type AdminBatchResponse struct {
	Action         string `json:"action"`
	RequestedCount int    `json:"requested_count"`
	ChangedCount   int    `json:"changed_count"`
	UnchangedCount int    `json:"unchanged_count"`
}

// parseBatchIDs 校验十进制业务 ID、数量上限与唯一性。
// ID 在 HTTP 边界保持字符串，解析后才进入服务层和事务。
func parseBatchIDs(raw []string) ([]int64, error) {
	if len(raw) < 1 || len(raw) > 100 {
		return nil, httpx.ErrInvalidID
	}
	ids := make([]int64, 0, len(raw))
	seen := make(map[int64]struct{}, len(raw))
	for _, value := range raw {
		id, err := httpx.ParseDecimalID(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[id]; exists {
			return nil, httpx.ErrInvalidID
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}

func toAdminBatchResponse(result domain.BatchResult) AdminBatchResponse {
	return AdminBatchResponse{
		Action:         result.Action,
		RequestedCount: result.RequestedCount,
		ChangedCount:   result.ChangedCount,
		UnchangedCount: result.UnchangedCount,
	}
}

// writeBatchError 保留统一错误翻译，同时在业务失败时安全地投影 failed_id。
func writeBatchError(c *gin.Context, err error) {
	details := map[string]any(nil)
	var resourceErr *domain.ResourceError
	if errors.As(err, &resourceErr) && resourceErr != nil && resourceErr.ResourceID > 0 {
		details = map[string]any{"failed_id": strconv.FormatInt(resourceErr.ResourceID, 10)}
	}
	httpx.WriteErrorWithDetails(c, err, details)
}

func decodeCommentBatchRequest(c *gin.Context) (comment.AdminBatchInput, error) {
	var req AdminBatchRequest
	if err := httpx.DecodeBody(c, &req); err != nil {
		return comment.AdminBatchInput{}, err
	}
	ids, err := parseBatchIDs(req.IDs)
	if err != nil {
		return comment.AdminBatchInput{}, err
	}
	if !comment.ValidAdminBatchAction(req.Action) {
		return comment.AdminBatchInput{}, domain.ErrValidation
	}
	return comment.AdminBatchInput{IDs: ids, Action: comment.AdminBatchAction(req.Action), Confirm: req.Confirm}, nil
}

func decodeThreadBatchRequest(c *gin.Context) (comment.AdminThreadBatchInput, error) {
	var req AdminBatchRequest
	if err := httpx.DecodeBody(c, &req); err != nil {
		return comment.AdminThreadBatchInput{}, err
	}
	ids, err := parseBatchIDs(req.IDs)
	if err != nil {
		return comment.AdminThreadBatchInput{}, err
	}
	if !comment.ValidAdminThreadBatchAction(req.Action) {
		return comment.AdminThreadBatchInput{}, domain.ErrValidation
	}
	return comment.AdminThreadBatchInput{
		IDs: ids, Action: comment.AdminThreadBatchAction(req.Action), Confirm: req.Confirm,
	}, nil
}

func decodeUserBatchRequest(c *gin.Context) (identity.AdminUserBatchInput, error) {
	var req AdminBatchRequest
	if err := httpx.DecodeBody(c, &req); err != nil {
		return identity.AdminUserBatchInput{}, err
	}
	ids, err := parseBatchIDs(req.IDs)
	if err != nil {
		return identity.AdminUserBatchInput{}, err
	}
	if !identity.ValidAdminUserBatchAction(req.Action) {
		return identity.AdminUserBatchInput{}, domain.ErrValidation
	}
	return identity.AdminUserBatchInput{
		IDs: ids, Action: identity.AdminUserBatchAction(req.Action), Confirm: req.Confirm,
	}, nil
}

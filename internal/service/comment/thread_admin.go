package comment

import (
	"context"
	"fmt"
	"strings"

	"furtalk/internal/domain"
)

// AdminListThreads 按站点作用域列出线程，支持开启状态、文本过滤与页码分页，并返回匹配总数。
func (s *Service) AdminListThreads(ctx context.Context, siteID int64, commentsEnabled *bool, q string, page int, sort domain.CommentSort, limit int) (*AdminThreadListResult, error) {
	limit = normalizeLimit(limit)
	if sort == "" {
		sort = domain.CommentSortDesc
	}
	filter := domain.AdminThreadFilter{
		SiteID:          &siteID,
		CommentsEnabled: commentsEnabled,
		Q:               q,
		Sort:            sort,
		Offset:          domain.OffsetForPage(page, limit),
		Limit:           limit,
	}
	rows, err := s.threads.ListAdmin(ctx, filter)
	if err != nil {
		return nil, err
	}
	total, err := s.threads.CountAdmin(ctx, filter)
	if err != nil {
		return nil, err
	}
	result := &AdminThreadListResult{Threads: make([]AdminThreadView, 0, len(rows)), Total: total}
	for _, r := range rows {
		result.Threads = append(result.Threads, toAdminThreadView(r))
	}
	return result, nil
}

// AdminThreadUpdateInput 携带线程 PATCH 的独立可选操作；至少一个字段非空。
// PageTitle 使用三态：Set=false 保持现状，Set=true 且 Value=nil 或空白清空，
// Set=true 且非空值覆盖。
type AdminThreadUpdateInput struct {
	PageKey         *string
	PageTitle       OptionalNullableString
	CommentsEnabled *bool
}

// AdminUpdateThread 按站点作用域更新线程元数据并返回更新后的完整管理视图。
// 至少一个字段必须提供；跨站点的 thread_id 视为不存在。
func (s *Service) AdminUpdateThread(ctx context.Context, siteID, threadID int64, input AdminThreadUpdateInput) (*AdminThreadView, error) {
	if input.PageKey == nil && !input.PageTitle.Set && input.CommentsEnabled == nil {
		return nil, fmt.Errorf("%w: at least one thread field is required", domain.ErrValidation)
	}
	patch := domain.ThreadPatch{CommentsEnabled: input.CommentsEnabled}
	if input.PageKey != nil {
		key := strings.TrimSpace(*input.PageKey)
		if key == "" {
			return nil, fmt.Errorf("%w: page_key is required", domain.ErrValidation)
		}
		if len(key) > maxPageKeyLength {
			return nil, fmt.Errorf("%w: page_key must not exceed %d characters", domain.ErrValidation, maxPageKeyLength)
		}
		patch.PageKey = &key
	}
	if input.PageTitle.Set {
		title := ""
		if input.PageTitle.Value != nil {
			title = strings.TrimSpace(*input.PageTitle.Value)
		}
		if title == "" {
			patch.ClearPageTitle = true
		} else {
			if len(title) > maxPageTitleLength {
				return nil, fmt.Errorf("%w: page_title must not exceed %d characters", domain.ErrValidation, maxPageTitleLength)
			}
			patch.PageTitle = &title
		}
	}
	thread, err := s.threads.UpdateThread(ctx, siteID, threadID, patch)
	if err != nil {
		return nil, err
	}
	return s.adminThreadView(ctx, siteID, thread)
}

// AdminDeleteThread 按站点作用域硬删除一条 thread 及其下全部评论。
// 破坏性操作必须显式确认；跨站点的 thread_id 视为不存在。
func (s *Service) AdminDeleteThread(ctx context.Context, siteID, threadID int64, confirm bool) error {
	if !confirm {
		return domain.ErrConfirmationRequired
	}
	if err := s.threads.DeleteThread(ctx, siteID, threadID); err != nil {
		return err
	}
	return nil
}

// adminThreadView 组装带站点名的管理线程视图。
func (s *Service) adminThreadView(ctx context.Context, siteID int64, thread *domain.Thread) (*AdminThreadView, error) {
	site, err := s.sites.Get(ctx, siteID)
	if err != nil {
		return nil, err
	}
	return &AdminThreadView{
		ID:              thread.ID,
		SiteID:          thread.SiteID,
		SiteName:        site.Name,
		PageKey:         thread.PageKey,
		PageURL:         thread.PageURL,
		PageTitle:       thread.PageTitle,
		CommentsEnabled: thread.CommentsEnabled,
		CreatedAt:       thread.CreatedAt,
		UpdatedAt:       thread.UpdatedAt,
	}, nil
}

// toAdminThreadView 把仓储行转换为管理线程视图。
func toAdminThreadView(row domain.AdminThread) AdminThreadView {
	return AdminThreadView{
		ID:              row.ID,
		SiteID:          row.SiteID,
		SiteName:        row.SiteName,
		PageKey:         row.PageKey,
		PageURL:         row.PageURL,
		PageTitle:       row.PageTitle,
		CommentsEnabled: row.CommentsEnabled,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
	}
}

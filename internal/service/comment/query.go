package comment

import (
	"context"
	"errors"
	"fmt"

	"furtalk/internal/domain"
	pkgcaptcha "furtalk/internal/platform/captcha"
	"furtalk/internal/platform/value"
)

// ListPublic 返回线程的扁平评论列表，带稳定的游标分页。
// 缺省排序使用实例策略的 comment_sort；显式 sort 只影响本次浏览。
// hot 使用 (like_count, created_at, id) 降序；其游标带版本标记，只能用于 hot。
// viewerID 非空时各评论携带该查看者是否点赞的观众状态，否则恒为 false。
// 缺失的页面返回 ID=0、默认开启的合成空线程。
func (s *Service) ListPublic(ctx context.Context, siteID int64, pageKey, cursorRaw, sortRaw string, limit int, viewerID *int64) (*ThreadView, error) {
	if err := s.validateSiteActive(ctx, siteID); err != nil {
		return nil, err
	}
	if err := validatePageKey(pageKey); err != nil {
		return nil, err
	}
	limit = normalizeLimit(limit)
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	sort, err := normalizeSort(sortRaw, pol.CommentSort)
	if err != nil {
		return nil, err
	}
	cursor, err := decodeCursor(cursorRaw, sort)
	if err != nil {
		return nil, err
	}
	thread, err := s.threads.GetBySiteAndKey(ctx, siteID, pageKey)
	if errors.Is(err, domain.ErrNotFound) {
		return &ThreadView{
			ID:              0,
			SiteID:          siteID,
			PageKey:         pageKey,
			CommentsEnabled: true,
			Comments:        []CommentView{},
		}, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.comments.ListPublic(ctx, siteID, thread.ID, sort, cursor, limit+1, viewerID)
	if err != nil {
		return nil, err
	}
	view := &ThreadView{
		ID: thread.ID, SiteID: siteID, PageKey: pageKey,
		PageURL: thread.PageURL, PageTitle: thread.PageTitle,
		CommentsEnabled: thread.CommentsEnabled,
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	for i := range rows {
		view.Comments = append(view.Comments, toCommentViewWithReply(&rows[i].Comment, rows[i].AuthorNickname, rows[i].AuthorWebsite, rows[i].AuthorRole,
			value.GravatarURL(rows[i].AuthorEmailNormalized, pol.GravatarBaseURL), rows[i].ReplyToNickname, rows[i].LikeCount, rows[i].LikedByMe))
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		var next string
		if sort == domain.CommentSortHot {
			next = encodeHotCursor(last.IsPinned, last.LikeCount, last.CreatedAt, last.ID)
		} else {
			next = encodeCursor(last.IsPinned, last.CreatedAt, last.ID)
		}
		view.NextCursor = &next
	}
	return view, nil
}

// ListLatestPublic 返回站点最新发布的评论列表（最多 25 条）。
// 仅返回 published 评论，关联所属线程的页面元数据及作者当前公开资料。
func (s *Service) ListLatestPublic(ctx context.Context, siteID int64, limit int) ([]LatestCommentView, error) {
	if err := s.validateSiteActive(ctx, siteID); err != nil {
		return nil, err
	}
	limit = normalizeLatestLimit(limit)
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.comments.ListLatestPublic(ctx, siteID, limit)
	if err != nil {
		return nil, err
	}
	views := make([]LatestCommentView, 0, len(rows))
	for i := range rows {
		views = append(views, LatestCommentView{
			ID:              rows[i].ID,
			SiteID:          rows[i].SiteID,
			ThreadID:        rows[i].ThreadID,
			PageKey:         rows[i].PageKey,
			PageURL:         rows[i].PageURL,
			PageTitle:       rows[i].PageTitle,
			UserID:          rows[i].UserID,
			BodyMarkdown:    rows[i].BodyMarkdown,
			Status:          rows[i].Status,
			AuthorNickname:  rows[i].AuthorNickname,
			AuthorWebsite:   rows[i].AuthorWebsite,
			AuthorRole:      rows[i].AuthorRole,
			AuthorAvatarURL: value.GravatarURL(rows[i].AuthorEmailNormalized, pol.GravatarBaseURL),
			ReplyToUserID:   rows[i].ReplyToUserID,
			ReplyToNickname: rows[i].ReplyToNickname,
			CreatedAt:       rows[i].CreatedAt,
			PublishedAt:     rows[i].PublishedAt,
		})
	}
	return views, nil
}

// normalizeSort 解析公开 sort 参数并校验：空值回落到实例策略默认排序，
// 显式值必须是 asc/desc/hot，非法值返回验证错误。
func normalizeSort(raw, defaultSort string) (domain.CommentSort, error) {
	if raw == "" {
		if !domain.ValidPublicCommentSort(defaultSort) {
			return "", fmt.Errorf("%w: configured comment sort %q is invalid", domain.ErrValidation, defaultSort)
		}
		return domain.CommentSort(defaultSort), nil
	}
	if !domain.ValidPublicCommentSort(raw) {
		return "", fmt.Errorf("%w: comment sort must be asc, desc or hot", domain.ErrValidation)
	}
	return domain.CommentSort(raw), nil
}

// RuntimeConfig 构建公共 widget 运行时配置。
func (s *Service) RuntimeConfig(ctx context.Context, siteID int64) (*RuntimeConfig, error) {
	site, err := s.sites.Get(ctx, siteID)
	if err != nil {
		return nil, err
	}
	if site.Status != domain.SiteStatusActive {
		return nil, domain.ErrSiteInactive
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	rc := &RuntimeConfig{
		SiteID:          siteID,
		Name:            site.Name,
		CommentMode:     pol.Mode,
		Moderation:      pol.Moderation,
		UserDeleteMode:  pol.UserDeleteMode,
		MaxReplyDepth:   pol.MaxReplyDepth,
		CommentSort:     pol.CommentSort,
		EmojiCatalogURL: pol.EmojiCatalogURL,
	}
	provider, err := s.providers.SelectedCaptcha(ctx)
	if err != nil && !errors.Is(err, domain.ErrNotFound) && !errors.Is(err, domain.ErrProviderNotFound) {
		return nil, err
	}
	rc.Captcha = buildRuntimeCaptcha(pol.CaptchaPolicy, provider)
	return rc, nil
}

// buildRuntimeCaptcha 为 comment action 构造公共渲染投影。
// 策略开启但 provider 未配置/损坏时仍标记 required=true，
// 写端点重新读取实时策略并以 503 失败关闭。
func buildRuntimeCaptcha(policy map[string]bool, provider *CaptchaConfig) *RuntimeCaptcha {
	build := func(action string) *CaptchaProjection {
		if !policy[action] {
			return &CaptchaProjection{Required: false}
		}
		projection := &CaptchaProjection{Required: true}
		if provider != nil {
			projection.Provider = provider.Provider
			projection.SiteKey = provider.SiteKey
			projection.APIEndpoint = pkgcaptcha.WidgetAPIURL(pkgcaptcha.Config{
				Provider: provider.Provider,
				SiteKey:  provider.SiteKey,
				Endpoint: provider.Endpoint,
			})
		}
		return projection
	}
	return &RuntimeCaptcha{
		Comment: build(CommentAction),
	}
}

// avatarBaseURL 读取当前 Gravatar BaseURL策略。
func (s *Service) avatarBaseURL(ctx context.Context) (string, error) {
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return "", err
	}
	return pol.GravatarBaseURL, nil
}

package handler

import (
	"strconv"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"furtalk/internal/service/setting"
)

// 响应 DTO 与映射。字段名与历史 HTTP 契约完全一致。

// NotificationPreferencesResponse 是通知偏好的响应体。
type NotificationPreferencesResponse struct {
	ReplyEnabled      bool `json:"reply_enabled"`
	ModerationEnabled bool `json:"moderation_enabled"`
}

// MeResponse 是当前用户资料的响应体。
type MeResponse struct {
	ID                      string                          `json:"id"`
	Email                   string                          `json:"email"`
	Nickname                string                          `json:"nickname"`
	WebsiteURL              *string                         `json:"website_url"`
	AvatarURL               string                          `json:"avatar_url"`
	Role                    string                          `json:"role"`
	Status                  string                          `json:"status"`
	EmailVerified           bool                            `json:"email_verified"`
	HasPassword             bool                            `json:"has_password"`
	NotificationPreferences NotificationPreferencesResponse `json:"notification_preferences"`
	CreatedAt               time.Time                       `json:"created_at"`
	UpdatedAt               time.Time                       `json:"updated_at"`
}

func toMeResponse(p identity.Profile) MeResponse {
	return MeResponse{
		ID:            strconv.FormatInt(p.ID, 10),
		Email:         p.Email,
		Nickname:      p.Nickname,
		WebsiteURL:    p.WebsiteURL,
		AvatarURL:     p.AvatarURL,
		Role:          string(p.Role),
		Status:        string(p.Status),
		EmailVerified: p.EmailVerified,
		HasPassword:   p.HasPassword,
		NotificationPreferences: NotificationPreferencesResponse{
			ReplyEnabled:      p.Preferences.ReplyEnabled,
			ModerationEnabled: p.Preferences.ModerationEnabled,
		},
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

// PasskeyRegistrationOptionsResponse 是 passkey 注册选项的响应体。
type PasskeyRegistrationOptionsResponse struct {
	Challenge string `json:"challenge"`
	Options   any    `json:"options"`
}

// PasskeyLoginOptionsResponse 是 passkey 登录选项的响应体。
type PasskeyLoginOptionsResponse struct {
	Challenge string `json:"challenge"`
	Options   any    `json:"options"`
}

// AuthProviderMetadata 是公开 OAuth/OIDC 提供商的元数据。
type AuthProviderMetadata struct {
	Key  string `json:"key"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// AuthProvidersResponse 是公开提供商列表响应。
type AuthProvidersResponse struct {
	Providers []AuthProviderMetadata `json:"providers"`
}

// OAuthStartResponse 是 OAuth 开始端点返回的授权 URL。
type OAuthStartResponse struct {
	AuthURL string `json:"auth_url"`
}

// OAuthCompleteRequest 是 OAuth 登录完成端点的请求。
// handoff 与 (state, code, error) 互斥，二者只能提交其一。
type OAuthCompleteRequest struct {
	State   string `json:"state"`
	Code    string `json:"code"`
	Error   string `json:"error"`
	Handoff string `json:"handoff"`
}

// OAuthCompleteResponse 是 OAuth 登录完成端点的成功响应，
// redirect 是已净化的站内回跳地址。
type OAuthCompleteResponse struct {
	Redirect string `json:"redirect"`
}

// IdentityMetadata 是登录方式的元数据。
type IdentityMetadata struct {
	Kind       string     `json:"kind"`
	ID         string     `json:"id,omitempty"`
	Name       string     `json:"name,omitempty"`
	Provider   string     `json:"provider,omitempty"`
	CreatedAt  time.Time  `json:"created_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// IdentitiesResponse 是登录方式列表响应。
type IdentitiesResponse struct {
	Identities []IdentityMetadata `json:"identities"`
}

// AdminUserResponse 是管理端用户资料响应体。
type AdminUserResponse struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Nickname      string     `json:"nickname"`
	WebsiteURL    *string    `json:"website_url"`
	AvatarURL     string     `json:"avatar_url"`
	Role          string     `json:"role"`
	Status        string     `json:"status"`
	EmailVerified bool       `json:"email_verified"`
	HasPassword   bool       `json:"has_password"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at"`
}

// AdminUserListResponse 是管理端用户列表响应，携带按搜索条件统计的真实总数。
type AdminUserListResponse struct {
	Users []AdminUserResponse `json:"users"`
	Total int64               `json:"total"`
}

func toAdminUserResponse(p identity.Profile) AdminUserResponse {
	return AdminUserResponse{
		ID:            strconv.FormatInt(p.ID, 10),
		Email:         p.Email,
		Nickname:      p.Nickname,
		WebsiteURL:    p.WebsiteURL,
		AvatarURL:     p.AvatarURL,
		Role:          string(p.Role),
		Status:        string(p.Status),
		EmailVerified: p.EmailVerified,
		HasPassword:   p.HasPassword,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
		DeletedAt:     p.DeletedAt,
	}
}

// RuntimeConfigResponse 是公开的 widget 运行时配置数据。
type RuntimeConfigResponse struct {
	SiteID         string `json:"site_id"`
	Name           string `json:"name"`
	CommentMode    string `json:"comment_mode"`
	Moderation     string `json:"moderation"`
	UserDeleteMode string `json:"user_delete_mode"`
	MaxReplyDepth  int    `json:"max_reply_depth"`
	CommentSort    string `json:"comment_sort"`
	// EmojiCatalogURL 是可选的 widget 远程表情目录地址；未配置时字段缺省。
	EmojiCatalogURL string                  `json:"emoji_catalog_url,omitempty"`
	Captcha         *RuntimeCaptchaResponse `json:"captcha"`
}

// CaptchaActionResponse 是单个 action 的公共 CAPTCHA 渲染投影。
// APIEndpoint 仅 CAP 返回，已解析为官方 widget 端点。
type CaptchaActionResponse struct {
	Required    bool   `json:"required"`
	Provider    string `json:"provider,omitempty"`
	SiteKey     string `json:"site_key,omitempty"`
	APIEndpoint string `json:"api_endpoint,omitempty"`
}

// RuntimeCaptchaResponse 是 widget 运行时配置中的按 action CAPTCHA 投影。
type RuntimeCaptchaResponse struct {
	Comment *CaptchaActionResponse `json:"comment,omitempty"`
}

// CommentResponse 是公开的评论视图。
type CommentResponse struct {
	ID             string  `json:"id"`
	SiteID         string  `json:"site_id"`
	ThreadID       string  `json:"thread_id"`
	UserID         string  `json:"user_id"`
	ParentID       *string `json:"parent_id"`
	RootID         *string `json:"root_id"`
	Depth          int     `json:"depth"`
	Body           string  `json:"body"`
	Status         string  `json:"status"`
	IsPinned       bool    `json:"is_pinned"`
	AuthorNickname string  `json:"author_nickname"`
	AuthorWebsite  *string `json:"author_website"`
	AuthorRole     string  `json:"author_role"`
	AvatarURL      string  `json:"avatar_url"`
	// ReplyToUserID 是被回复作者的 id；根评论为 nil，被回复者注销后也为 nil。
	ReplyToUserID *string `json:"reply_to_user_id"`
	// ReplyToNickname 是被回复作者的当前昵称；缺失或已注销时为 nil。
	ReplyToNickname *string    `json:"reply_to_nickname"`
	CreatedAt       time.Time  `json:"created_at"`
	PublishedAt     *time.Time `json:"published_at"`
	// LikeCount 是公开的 Like 计数，始终存在。
	LikeCount int64 `json:"like_count"`
	// LikedByMe 只反映已验证查看者是否点赞；匿名读取恒为 false。
	LikedByMe bool `json:"liked_by_me"`
}

// LikeResponse 是 Like 添加/移除的权威结果。
type LikeResponse struct {
	CommentID string `json:"comment_id"`
	LikeCount int64  `json:"like_count"`
	Liked     bool   `json:"liked"`
}

// CommentPinResponse 是 Widget 置顶变更返回的权威结果。
type CommentPinResponse struct {
	CommentID string `json:"comment_id"`
	IsPinned  bool   `json:"is_pinned"`
}

// ThreadMetaResponse 是线程元数据。
type ThreadMetaResponse struct {
	ID              string  `json:"id"`
	SiteID          string  `json:"site_id"`
	PageKey         string  `json:"page_key"`
	PageURL         *string `json:"page_url"`
	PageTitle       *string `json:"page_title"`
	CommentsEnabled bool    `json:"comments_enabled"`
}

// ThreadCommentsResponse 是一个线程的评论列表。
type ThreadCommentsResponse struct {
	Thread     ThreadMetaResponse `json:"thread"`
	Comments   []CommentResponse  `json:"comments"`
	NextCursor *string            `json:"next_cursor"`
}

// LatestCommentResponse 是站点公开最新评论视图。
type LatestCommentResponse struct {
	ID              string     `json:"id"`
	SiteID          string     `json:"site_id"`
	ThreadID        string     `json:"thread_id"`
	PageKey         string     `json:"page_key"`
	PageURL         *string    `json:"page_url"`
	PageTitle       *string    `json:"page_title"`
	UserID          string     `json:"user_id"`
	Body            string     `json:"body"`
	Status          string     `json:"status"`
	AuthorNickname  string     `json:"author_nickname"`
	AuthorWebsite   *string    `json:"author_website"`
	AuthorRole      string     `json:"author_role"`
	AvatarURL       string     `json:"avatar_url"`
	ReplyToUserID   *string    `json:"reply_to_user_id"`
	ReplyToNickname *string    `json:"reply_to_nickname"`
	CreatedAt       time.Time  `json:"created_at"`
	PublishedAt     *time.Time `json:"published_at"`
}

// LatestCommentListResponse 是站点公开最新评论列表。
type LatestCommentListResponse struct {
	Comments []LatestCommentResponse `json:"comments"`
}

// MeCommentResponse 是本人评论的展示视图，不含邮箱/IP/UA 等管理字段。
type MeCommentResponse struct {
	ID             string  `json:"id"`
	SiteID         string  `json:"site_id"`
	SiteName       string  `json:"site_name"`
	ThreadID       string  `json:"thread_id"`
	PageKey        string  `json:"page_key"`
	PageURL        *string `json:"page_url"`
	PageTitle      *string `json:"page_title"`
	UserID         string  `json:"user_id"`
	ParentID       *string `json:"parent_id"`
	RootID         *string `json:"root_id"`
	Depth          int     `json:"depth"`
	Body           string  `json:"body"`
	Status         string  `json:"status"`
	AuthorNickname string  `json:"author_nickname"`
	AuthorWebsite  *string `json:"author_website"`
	AvatarURL      string  `json:"avatar_url"`
	// ReplyToUserID 是被回复作者的 id；根评论为 nil，被回复者注销后也为 nil。
	ReplyToUserID *string `json:"reply_to_user_id"`
	// ReplyToNickname 是被回复作者的当前昵称；缺失或已注销时为 nil。
	ReplyToNickname *string    `json:"reply_to_nickname"`
	CreatedAt       time.Time  `json:"created_at"`
	PublishedAt     *time.Time `json:"published_at"`
	DeletedAt       *time.Time `json:"deleted_at"`
}

// MeCommentListResponse 是本人评论的一页、匹配总数与当前删除策略。
type MeCommentListResponse struct {
	Comments       []MeCommentResponse `json:"comments"`
	Total          int64               `json:"total"`
	UserDeleteMode string              `json:"user_delete_mode"`
}

// MeCommentDetailResponse 是本人评论详情与当前删除策略。
type MeCommentDetailResponse struct {
	MeCommentResponse
	UserDeleteMode string `json:"user_delete_mode"`
}

// MeCommentSiteResponse 是本人评论的站点选项。
type MeCommentSiteResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MeCommentSitesResponse 是本人评论站点选项列表。
type MeCommentSitesResponse struct {
	Sites []MeCommentSiteResponse `json:"sites"`
}

// CommentDeleteResponse 是删除操作结果。
type CommentDeleteResponse struct {
	DeletedRootID string `json:"deleted_root_id"`
	Hard          bool   `json:"hard"`
}

// AuthorizationIssueResponse 是一次性授权码响应。
type AuthorizationIssueResponse struct {
	Code      string    `json:"code"`
	RequestID string    `json:"request_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthorizationContextResponse 是授权页展示所需的只读上下文。
type AuthorizationContextResponse struct {
	SiteID   string `json:"site_id"`
	SiteName string `json:"site_name"`
	Origin   string `json:"origin"`
}

// WidgetAuthorizationRequiredResponse 是评论创建需要显式授权的受控响应。
type WidgetAuthorizationRequiredResponse struct {
	NeedAuthCode bool `json:"need_auth_code"`
}

// WidgetSessionResponse 是不敏感的 session 探测结果。
type WidgetSessionResponse struct {
	Valid          bool       `json:"valid"`
	CredentialMode string     `json:"credential_mode,omitempty"`
	UserID         string     `json:"user_id,omitempty"`
	SiteID         string     `json:"site_id,omitempty"`
	Role           string     `json:"role,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

// AdminCommentResponse 是仅管理员可见的视图。
type AdminCommentResponse struct {
	ID             string  `json:"id"`
	SiteID         string  `json:"site_id"`
	ThreadID       string  `json:"thread_id"`
	UserID         string  `json:"user_id"`
	ParentID       *string `json:"parent_id"`
	RootID         *string `json:"root_id"`
	Depth          int     `json:"depth"`
	Body           string  `json:"body"`
	Status         string  `json:"status"`
	IsPinned       bool    `json:"is_pinned"`
	AuthorEmail    string  `json:"author_email"`
	AuthorNickname string  `json:"author_nickname"`
	AuthorWebsite  *string `json:"author_website"`
	AvatarURL      string  `json:"avatar_url"`
	// ReplyToUserID 是被回复作者的 id；根评论为 nil，被回复者注销后也为 nil。
	ReplyToUserID *string `json:"reply_to_user_id"`
	// ReplyToNickname 是被回复作者的当前昵称；缺失或已注销时为 nil。
	ReplyToNickname *string    `json:"reply_to_nickname"`
	IPMode          string     `json:"ip_mode"`
	IPValue         *string    `json:"ip_value"`
	UAMode          string     `json:"ua_mode"`
	UARaw           *string    `json:"ua_raw,omitempty"`
	UABrowser       *string    `json:"ua_browser"`
	UAOS            *string    `json:"ua_os"`
	UADevice        *string    `json:"ua_device"`
	CreatedAt       time.Time  `json:"created_at"`
	PublishedAt     *time.Time `json:"published_at"`
	DeletedAt       *time.Time `json:"deleted_at"`
}

// AdminCommentListResponse 是管理员评论的一页数据与匹配总数。
type AdminCommentListResponse struct {
	Comments []AdminCommentResponse `json:"comments"`
	Total    int64                  `json:"total"`
}

// AdminCommentTrendPointResponse 是一个按本地日历日统计的趋势点。
type AdminCommentTrendPointResponse struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// AdminCommentTrendResponse 是管理员概览的评论趋势响应。
type AdminCommentTrendResponse struct {
	Days     int                              `json:"days"`
	Timezone string                           `json:"timezone"`
	Points   []AdminCommentTrendPointResponse `json:"points"`
}

// AdminThreadResponse 是管理端线程视图。
type AdminThreadResponse struct {
	ID              string    `json:"id"`
	SiteID          string    `json:"site_id"`
	SiteName        string    `json:"site_name"`
	PageKey         string    `json:"page_key"`
	PageURL         *string   `json:"page_url"`
	PageTitle       *string   `json:"page_title"`
	CommentsEnabled bool      `json:"comments_enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AdminThreadListResponse 是管理端线程的一页数据与匹配总数。
type AdminThreadListResponse struct {
	Threads []AdminThreadResponse `json:"threads"`
	Total   int64                 `json:"total"`
}

func toRuntimeConfigResponse(rc *comment.RuntimeConfig) RuntimeConfigResponse {
	resp := RuntimeConfigResponse{
		SiteID:          strconv.FormatInt(rc.SiteID, 10),
		Name:            rc.Name,
		CommentMode:     rc.CommentMode,
		Moderation:      rc.Moderation,
		UserDeleteMode:  rc.UserDeleteMode,
		MaxReplyDepth:   rc.MaxReplyDepth,
		CommentSort:     rc.CommentSort,
		EmojiCatalogURL: rc.EmojiCatalogURL,
	}
	if rc.Captcha != nil {
		resp.Captcha = &RuntimeCaptchaResponse{}
		if rc.Captcha.Comment != nil {
			resp.Captcha.Comment = toCaptchaActionResponse(*rc.Captcha.Comment)
		}
	}
	return resp
}

func toCaptchaActionResponse(projection comment.CaptchaProjection) *CaptchaActionResponse {
	return &CaptchaActionResponse{
		Required:    projection.Required,
		Provider:    projection.Provider,
		SiteKey:     projection.SiteKey,
		APIEndpoint: projection.APIEndpoint,
	}
}

func toThreadCommentsResponse(view *comment.ThreadView) ThreadCommentsResponse {
	resp := ThreadCommentsResponse{
		Thread: ThreadMetaResponse{
			ID:              strconv.FormatInt(view.ID, 10),
			SiteID:          strconv.FormatInt(view.SiteID, 10),
			PageKey:         view.PageKey,
			PageURL:         view.PageURL,
			PageTitle:       view.PageTitle,
			CommentsEnabled: view.CommentsEnabled,
		},
		Comments:   make([]CommentResponse, 0, len(view.Comments)),
		NextCursor: view.NextCursor,
	}
	for _, c := range view.Comments {
		resp.Comments = append(resp.Comments, toCommentResponse(c))
	}
	return resp
}

func toCommentResponse(view comment.CommentView) CommentResponse {
	return CommentResponse{
		ID:              strconv.FormatInt(view.ID, 10),
		SiteID:          strconv.FormatInt(view.SiteID, 10),
		ThreadID:        strconv.FormatInt(view.ThreadID, 10),
		UserID:          strconv.FormatInt(view.UserID, 10),
		ParentID:        formatOptionalID(view.ParentID),
		RootID:          formatOptionalID(view.RootID),
		Depth:           view.Depth,
		Body:            view.BodyMarkdown,
		Status:          string(view.Status),
		IsPinned:        view.IsPinned,
		AuthorNickname:  view.AuthorNickname,
		AuthorWebsite:   view.AuthorWebsite,
		AuthorRole:      string(view.AuthorRole),
		AvatarURL:       view.AuthorAvatarURL,
		ReplyToUserID:   formatOptionalID(view.ReplyToUserID),
		ReplyToNickname: view.ReplyToNickname,
		CreatedAt:       view.CreatedAt,
		PublishedAt:     view.PublishedAt,
		LikeCount:       view.LikeCount,
		LikedByMe:       view.LikedByMe,
	}
}

func toLikeResponse(result *comment.LikeResult) LikeResponse {
	return LikeResponse{
		CommentID: strconv.FormatInt(result.CommentID, 10),
		LikeCount: result.LikeCount,
		Liked:     result.Liked,
	}
}

func toLatestCommentListResponse(views []comment.LatestCommentView) LatestCommentListResponse {
	comments := make([]LatestCommentResponse, 0, len(views))
	for _, v := range views {
		comments = append(comments, toLatestCommentResponse(v))
	}
	return LatestCommentListResponse{Comments: comments}
}

func toLatestCommentResponse(view comment.LatestCommentView) LatestCommentResponse {
	return LatestCommentResponse{
		ID:              strconv.FormatInt(view.ID, 10),
		SiteID:          strconv.FormatInt(view.SiteID, 10),
		ThreadID:        strconv.FormatInt(view.ThreadID, 10),
		PageKey:         view.PageKey,
		PageURL:         view.PageURL,
		PageTitle:       view.PageTitle,
		UserID:          strconv.FormatInt(view.UserID, 10),
		Body:            view.BodyMarkdown,
		Status:          string(view.Status),
		AuthorNickname:  view.AuthorNickname,
		AuthorWebsite:   view.AuthorWebsite,
		AuthorRole:      string(view.AuthorRole),
		AvatarURL:       view.AuthorAvatarURL,
		ReplyToUserID:   formatOptionalID(view.ReplyToUserID),
		ReplyToNickname: view.ReplyToNickname,
		CreatedAt:       view.CreatedAt,
		PublishedAt:     view.PublishedAt,
	}
}

func toMeCommentResponse(view comment.OwnerCommentView) MeCommentResponse {
	return MeCommentResponse{
		ID:              strconv.FormatInt(view.ID, 10),
		SiteID:          strconv.FormatInt(view.SiteID, 10),
		SiteName:        view.SiteName,
		ThreadID:        strconv.FormatInt(view.ThreadID, 10),
		PageKey:         view.PageKey,
		PageURL:         view.PageURL,
		PageTitle:       view.PageTitle,
		UserID:          strconv.FormatInt(view.UserID, 10),
		ParentID:        formatOptionalID(view.ParentID),
		RootID:          formatOptionalID(view.RootID),
		Depth:           view.Depth,
		Body:            view.BodyMarkdown,
		Status:          string(view.Status),
		AuthorNickname:  view.AuthorNickname,
		AuthorWebsite:   view.AuthorWebsite,
		AvatarURL:       view.AuthorAvatarURL,
		ReplyToUserID:   formatOptionalID(view.ReplyToUserID),
		ReplyToNickname: view.ReplyToNickname,
		CreatedAt:       view.CreatedAt,
		PublishedAt:     view.PublishedAt,
		DeletedAt:       view.DeletedAt,
	}
}

func toMeCommentDetailResponse(detail comment.OwnerCommentDetail) MeCommentDetailResponse {
	return MeCommentDetailResponse{
		MeCommentResponse: toMeCommentResponse(detail.View),
		UserDeleteMode:    detail.UserDeleteMode,
	}
}

func toCommentDeleteResponse(result comment.DeleteResult) CommentDeleteResponse {
	return CommentDeleteResponse{
		DeletedRootID: strconv.FormatInt(result.DeletedRootID, 10),
		Hard:          result.Hard,
	}
}

func toWidgetSessionResponse(result comment.ProbeResult) WidgetSessionResponse {
	if !result.Valid {
		return WidgetSessionResponse{Valid: false}
	}
	expiresAt := result.ExpiresAt
	return WidgetSessionResponse{
		Valid:          true,
		CredentialMode: result.CredentialMode,
		UserID:         strconv.FormatInt(result.UserID, 10),
		SiteID:         strconv.FormatInt(result.SiteID, 10),
		Role:           string(result.Role),
		ExpiresAt:      &expiresAt,
	}
}

func toAdminCommentResponse(view comment.AdminCommentView) AdminCommentResponse {
	base := toCommentResponse(view.CommentView)
	return AdminCommentResponse{
		ID:              base.ID,
		SiteID:          base.SiteID,
		ThreadID:        base.ThreadID,
		UserID:          base.UserID,
		ParentID:        base.ParentID,
		RootID:          base.RootID,
		Depth:           base.Depth,
		Body:            base.Body,
		Status:          base.Status,
		IsPinned:        base.IsPinned,
		AuthorEmail:     view.Email,
		AuthorNickname:  base.AuthorNickname,
		AuthorWebsite:   base.AuthorWebsite,
		AvatarURL:       base.AvatarURL,
		ReplyToUserID:   base.ReplyToUserID,
		ReplyToNickname: base.ReplyToNickname,
		IPMode:          string(view.IPMode),
		IPValue:         view.IPValue,
		UAMode:          string(view.UAMode),
		UARaw:           view.UARaw,
		UABrowser:       view.UABrowser,
		UAOS:            view.UAOS,
		UADevice:        view.UADevice,
		CreatedAt:       base.CreatedAt,
		PublishedAt:     base.PublishedAt,
		DeletedAt:       view.DeletedAt,
	}
}

func toAdminCommentTrendResponse(trend domain.CommentTrend) AdminCommentTrendResponse {
	points := make([]AdminCommentTrendPointResponse, 0, len(trend.Points))
	for _, point := range trend.Points {
		points = append(points, AdminCommentTrendPointResponse{
			Date:  point.Date,
			Count: point.Count,
		})
	}
	return AdminCommentTrendResponse{
		Days:     trend.Days,
		Timezone: trend.Timezone,
		Points:   points,
	}
}

func toAdminThreadResponse(view comment.AdminThreadView) AdminThreadResponse {
	return AdminThreadResponse{
		ID:              strconv.FormatInt(view.ID, 10),
		SiteID:          strconv.FormatInt(view.SiteID, 10),
		SiteName:        view.SiteName,
		PageKey:         view.PageKey,
		PageURL:         view.PageURL,
		PageTitle:       view.PageTitle,
		CommentsEnabled: view.CommentsEnabled,
		CreatedAt:       view.CreatedAt,
		UpdatedAt:       view.UpdatedAt,
	}
}

// OriginResponse 是站点允许来源的响应体，携带稳定 ID 供管理端引用。
type OriginResponse struct {
	ID     string `json:"id"`
	Origin string `json:"origin"`
}

// SiteResponse 是站点的 HTTP 响应。
type SiteResponse struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	CanonicalURL string           `json:"canonical_url"`
	Status       string           `json:"status"`
	Origins      []OriginResponse `json:"origins"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

// SiteListResponse 是站点列表响应。
type SiteListResponse struct {
	Sites []SiteResponse `json:"sites"`
}

func toOriginResponse(o domain.Origin) OriginResponse {
	return OriginResponse{
		ID:     strconv.FormatInt(o.ID, 10),
		Origin: o.Origin,
	}
}

func toSiteResponse(s domain.Site) SiteResponse {
	origins := make([]OriginResponse, 0, len(s.Origins))
	for _, o := range s.Origins {
		origins = append(origins, toOriginResponse(o))
	}
	return SiteResponse{
		ID:           strconv.FormatInt(s.ID, 10),
		Name:         s.Name,
		CanonicalURL: s.CanonicalURL,
		Status:       string(s.Status),
		Origins:      origins,
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
	}
}

// SettingsResponse 是设置读取或 PATCH 后的响应，只含公开设置项列表。
type SettingsResponse struct {
	Settings []setting.SettingItem `json:"settings"`
}

// PublicConfigResponse 是匿名读取的站点协议与 Web 主题配置白名单。
// 该 DTO 刻意不复用 SettingsResponse，避免泄露管理员设置或 provider 配置。
type PublicConfigResponse struct {
	UserAgreementURL    string `json:"user_agreement_url"`
	PrivacyPolicyURL    string `json:"privacy_policy_url"`
	LegalConsentVersion int64  `json:"legal_consent_version"`
	BrandPrimaryColor   string `json:"brand_primary_color"`
}

// LegalConsentResetResponse 是管理员主动要求重新同意后的新版本。
type LegalConsentResetResponse struct {
	LegalConsentVersion int64 `json:"legal_consent_version"`
}

// ProviderMetadata 是提供商元数据的 HTTP 表示，不含机密。
// Enabled 仅 OAuth/OIDC 与 Spam 返回；CAPTCHA 提供商省略该字段。
// PublicConfig 是自由表单的公开字段 map，字段集合与 ProviderUpsertRequest 的
// 公开字段一致（client_id、instance_url、issuer_url、team_id、key_id、endpoint、
// file_path、action、region 等）；
// secret 字段永不出现，编辑留空即保留现有 envelope。
type ProviderMetadata struct {
	ProviderKey  string         `json:"provider_key"`
	Kind         string         `json:"kind"`
	Enabled      *bool          `json:"enabled,omitempty"`
	Configured   bool           `json:"configured"`
	PublicConfig map[string]any `json:"public_config"`
}

// ProvidersResponse 是提供商列表响应。
type ProvidersResponse struct {
	Providers []ProviderMetadata `json:"providers"`
}

// PublicCaptchaConfig 是启用的 CAPTCHA provider 的公共投影。
// APIEndpoint 仅 CAP 返回，且已解析为官方 widget 端点。
type PublicCaptchaConfig struct {
	Provider    string `json:"provider"`
	SiteKey     string `json:"site_key"`
	APIEndpoint string `json:"api_endpoint,omitempty"`
}

// CaptchaConfigResponse 是按 action 查询的公共 CAPTCHA 配置响应。
type CaptchaConfigResponse struct {
	Required bool                 `json:"required"`
	Captcha  *PublicCaptchaConfig `json:"captcha,omitempty"`
}

func toCaptchaConfigResponse(cfg *setting.PublicCaptchaConfig) CaptchaConfigResponse {
	if cfg == nil || !cfg.Required {
		return CaptchaConfigResponse{Required: false}
	}
	captchaDTO := PublicCaptchaConfig{Provider: cfg.Provider, SiteKey: cfg.SiteKey}
	if cfg.APIEndpoint != "" {
		captchaDTO.APIEndpoint = cfg.APIEndpoint
	}
	return CaptchaConfigResponse{Required: true, Captcha: &captchaDTO}
}

// BootstrapStatusResponse 是 bootstrap 状态响应。
type BootstrapStatusResponse struct {
	Required bool `json:"required"`
}

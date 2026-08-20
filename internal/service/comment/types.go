// Package comment 是评论与 widget 会话用例的业务层。
// 数据经 repository 读写；设置策略与 CAPTCHA provider 由 setting 层提供；
// 用户写入经 domain.UserWriter 由 identity 层代写。
package comment

import (
	"encoding/json"
	"net"
	"time"

	"furtalk/internal/domain"
)

// AuthCodeRecord 是与已签发授权码绑定的元数据。
// CredentialMode 记录用户批准签发的 widget 凭证模式；交换时必须与实时评论模式
// 一致，缺失/未知模式一律失败关闭。
type AuthCodeRecord struct {
	SiteID         int64     `json:"site_id"`
	Origin         string    `json:"origin"`
	UserID         int64     `json:"user_id"`
	RequestID      string    `json:"request_id"`
	ExpiresAt      time.Time `json:"expires_at"`
	CredentialMode string    `json:"credential_mode"`
}

// CaptchaProjection 是单个 action 的公共 CAPTCHA 渲染投影，只携带公开字段。
// APIEndpoint 仅 CAP 使用，已解析为官方 widget 端点。
type CaptchaProjection struct {
	Required    bool
	Provider    string
	SiteKey     string
	APIEndpoint string
}

// RuntimeCaptcha 是 widget 运行时配置中的按 action 公共 CAPTCHA 投影。
// 渲染提示而非授权决策：写端点始终以实时策略为最终权威。
type RuntimeCaptcha struct {
	Comment *CaptchaProjection
}

// CaptchaConfig 是解密后的 CAPTCHA provider 配置（含机密）。
// Endpoint 仅 CAP 使用，是管理员配置的外部 Standalone 实例基址。
type CaptchaConfig struct {
	Provider  string
	SiteKey   string
	SecretKey string
	Endpoint  string
}

// WebsiteOperation 描述请求中网址字段的三态输入。
// Set=false 表示字段缺省，保持当前网址；Set=true 且 Value=nil 表示显式清空；
// Set=true 且 Value 为合法非空 URL 表示覆盖。
type WebsiteOperation struct {
	Set   bool
	Value *string
}

// OptionalNullableString 表示既可被省略又可被显式置空的字符串字段。
// Set=false 表示请求未提供该字段；Set=true 且 Value=nil 表示显式 null；
// Set=true 且 Value 非空表示普通字符串值。
type OptionalNullableString struct {
	Set   bool
	Value *string
}

// UnmarshalJSON 区分 JSON 中的缺失、null 与字符串三种状态。
func (o *OptionalNullableString) UnmarshalJSON(data []byte) error {
	o.Set = true
	if string(data) == "null" {
		o.Value = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	o.Value = &s
	return nil
}

// CreateInput 携带 widget 评论创建输入。
// Credential 是可选的已解析 widget 凭据：匿名模式普通邮箱可缺省，
// 管理员邮箱与认证模式必须携带有效凭据。
type CreateInput struct {
	SiteID       int64
	PageKey      string
	PageURL      *string
	PageTitle    *string
	ParentID     *int64
	BodyMarkdown string
	IP           net.IP
	UA           string
	CaptchaToken string
	Origin       string
	Email        string
	Nickname     string
	WebsiteURL   WebsiteOperation
	Credential   WidgetCredential
}

// CommentView 是评论的公共视图。
type CommentView struct {
	ID                 int64
	SiteID             int64
	ThreadID           int64
	UserID             int64
	ParentID           *int64
	RootID             *int64
	Depth              int
	BodyMarkdown       string
	Status             domain.CommentStatus
	StatusBeforeDelete *domain.CommentStatus
	AuthorNickname     string
	AuthorWebsite      *string
	AuthorRole         domain.Role
	AuthorAvatarURL    string
	ReplyToUserID      *int64
	ReplyToNickname    *string
	CreatedAt          time.Time
	PublishedAt        *time.Time
	DeletedAt          *time.Time
}

// ThreadView 是一个线程的扁平评论列表及其元数据。
type ThreadView struct {
	ID              int64
	SiteID          int64
	PageKey         string
	PageURL         *string
	PageTitle       *string
	CommentsEnabled bool
	Comments        []CommentView
	NextCursor      *string
}

// LatestCommentView 是站点公开最新评论视图。
type LatestCommentView struct {
	ID              int64
	SiteID          int64
	ThreadID        int64
	PageKey         string
	PageURL         *string
	PageTitle       *string
	UserID          int64
	BodyMarkdown    string
	Status          domain.CommentStatus
	AuthorNickname  string
	AuthorWebsite   *string
	AuthorRole      domain.Role
	AuthorAvatarURL string
	ReplyToUserID   *int64
	ReplyToNickname *string
	CreatedAt       time.Time
	PublishedAt     *time.Time
}

// AdminThreadView 是管理端线程列表/详情视图。
type AdminThreadView struct {
	ID              int64
	SiteID          int64
	SiteName        string
	PageKey         string
	PageURL         *string
	PageTitle       *string
	CommentsEnabled bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AdminThreadListResult 是管理端线程的一页以及匹配总数。
type AdminThreadListResult struct {
	Threads []AdminThreadView
	Total   int64
}

// DeleteResult 报告删除操作的结果。
type DeleteResult struct {
	DeletedRootID int64
	Hard          bool
}

// RuntimeConfig 是 widget 运行时配置数据。
type RuntimeConfig struct {
	SiteID         int64
	Name           string
	CommentMode    string
	Moderation     string
	UserDeleteMode string
	MaxReplyDepth  int
	CommentSort    string
	OwOCatalogURL  string
	Captcha        *RuntimeCaptcha
}

// AuthorizationContextView 是授权页展示所需的只读上下文，不创建授权记录。
type AuthorizationContextView struct {
	SiteID   int64
	SiteName string
	Origin   string
}

// AdminCommentView 是仅管理员可见的视图。
type AdminCommentView struct {
	CommentView
	Email     string
	IPMode    domain.PrivacyMode
	IPValue   *string
	UAMode    domain.PrivacyMode
	UARaw     *string
	UABrowser *string
	UAOS      *string
	UADevice  *string
}

// AdminListResult 是管理员评论的一页以及匹配总数。
type AdminListResult struct {
	Comments []AdminCommentView
	Total    int64
}

// OwnerCommentView 是当前用户本人评论的展示视图，不含邮箱/IP/UA。
type OwnerCommentView struct {
	CommentView
	SiteName  string
	PageKey   string
	PageURL   *string
	PageTitle *string
}

// OwnerCommentDetail 是本人评论详情视图及当前删除策略。
type OwnerCommentDetail struct {
	View           OwnerCommentView
	UserDeleteMode string
}

// OwnerCommentListResult 是本人评论的一页、匹配总数与当前删除策略。
type OwnerCommentListResult struct {
	Comments       []OwnerCommentView
	Total          int64
	UserDeleteMode string
}

// OwnerSiteView 是当前用户发表过评论的站点展示数据。
type OwnerSiteView struct {
	ID   int64
	Name string
}

// IssueInput 是第一方授权码签发请求。
type IssueInput struct {
	SiteID    int64
	Origin    string
	RequestID string
	UserID    int64
	// Role 是签发请求时的第一方主体当前角色，用于模式感知的授权矩阵判定。
	Role domain.Role
}

// AuthCodeResult 是一次性授权码响应。
type AuthCodeResult struct {
	Code      string
	RequestID string
	ExpiresAt time.Time
}

// SessionResult 是成功的 widget 会话签发/交换结果。
type SessionResult struct {
	Token     string
	ExpiresAt time.Time
}

// ProbeResult 是不含敏感信息的 widget 会话探测结果。
type ProbeResult struct {
	Valid          bool
	CredentialMode string
	UserID         int64
	SiteID         int64
	Role           domain.Role
	ExpiresAt      time.Time
}

// toCommentViewWithReply 与 toCommentView 相同，额外携带回复目标当前昵称。
func toCommentViewWithReply(comment *domain.Comment, nickname string, website *string, role domain.Role, avatarURL string, replyNickname *string) CommentView {
	view := toCommentView(comment, nickname, website, role, avatarURL)
	view.ReplyToNickname = replyNickname
	return view
}

// toCommentView 把评论实体转为公共评论视图。
func toCommentView(comment *domain.Comment, nickname string, website *string, role domain.Role, avatarURL string) CommentView {
	return CommentView{
		ID:                 comment.ID,
		SiteID:             comment.SiteID,
		ThreadID:           comment.ThreadID,
		UserID:             comment.UserID,
		ParentID:           comment.ParentID,
		RootID:             comment.RootID,
		Depth:              comment.Depth,
		BodyMarkdown:       comment.BodyMarkdown,
		Status:             comment.Status,
		StatusBeforeDelete: comment.StatusBeforeDelete,
		AuthorNickname:     nickname,
		AuthorWebsite:      website,
		AuthorRole:         role,
		AuthorAvatarURL:    avatarURL,
		ReplyToUserID:      comment.ReplyToUserID,
		CreatedAt:          comment.CreatedAt,
		PublishedAt:        comment.PublishedAt,
		DeletedAt:          comment.DeletedAt,
	}
}

// Package domain 是跨层共享的领域类型层。
// 只承载纯净的业务结构体、枚举常量、错误 sentinel 与跨模块写接口，
// 不依赖任何业务包或框架（仅标准库）；任何包都可以依赖本层。
package domain

import (
	"time"
)

// Role 表示用户角色。
type Role string

// 用户角色枚举。
const (
	// RoleAdmin 表示管理员。
	RoleAdmin Role = "admin"
	// RoleUser 表示普通用户。
	RoleUser Role = "user"
)

// UserStatus 表示用户账户状态。
type UserStatus string

// 用户账户状态枚举。
const (
	// UserStatusActive 表示账户可用。
	UserStatusActive UserStatus = "active"
	// UserStatusDisabled 表示账户已禁用。
	UserStatusDisabled UserStatus = "disabled"
	// UserStatusDeleted 表示账户已被管理员软删除，可恢复。
	UserStatusDeleted UserStatus = "deleted"
)

// SiteStatus 表示站点状态。
type SiteStatus string

// 站点状态枚举。
const (
	// SiteStatusActive 表示站点可用。
	SiteStatusActive SiteStatus = "active"
	// SiteStatusDisabled 表示站点已停用。
	SiteStatusDisabled SiteStatus = "disabled"
)

// CommentStatus 表示评论审核状态。
// 与 GORM CHECK 约束的枚举字符串保持一致。
type CommentStatus string

// 评论审核状态枚举。
const (
	// CommentStatusPending 表示待审核。
	CommentStatusPending CommentStatus = "pending"
	// CommentStatusPublished 表示已发布。
	CommentStatusPublished CommentStatus = "published"
	// CommentStatusSpam 表示标记为垃圾。
	CommentStatusSpam CommentStatus = "spam"
	// CommentStatusDeleted 表示已删除。
	CommentStatusDeleted CommentStatus = "deleted"
)

// PrivacyMode 表示捕获隐私字段（IP/UA）的模式。
type PrivacyMode string

// 隐私字段捕获模式枚举。
const (
	// PrivacyModeNone 表示不捕获。
	PrivacyModeNone PrivacyMode = "none"
	// PrivacyModeCoarse 表示仅捕获粗略信息。
	PrivacyModeCoarse PrivacyMode = "coarse"
	// PrivacyModeFull 表示完整捕获。
	PrivacyModeFull PrivacyMode = "full"
)

// CommentMode 表示实例评论模式的值。
const (
	// CommentModeAnonymous 表示任何人都可评论。
	CommentModeAnonymous = "anonymous"
	// CommentModeAuthenticated 表示仅认证用户可评论。
	CommentModeAuthenticated = "authenticated"
)

// Moderation 表示审核策略的值。
const (
	// ModerationDirect 表示评论直接发布。
	ModerationDirect = "direct"
	// ModerationReview 表示评论需人工审核。
	ModerationReview = "review"
)

// UserDeleteMode 表示用户删除评论的方式。
const (
	// UserDeleteModeSoft 表示软删除（保留占位节点）。
	UserDeleteModeSoft = "soft"
	// UserDeleteModeHard 表示硬删除（物理移除该评论）。
	UserDeleteModeHard = "hard"
)

// CommentSort 表示公开评论列表的排序方向。
type CommentSort string

// 公开评论列表的受控排序方向。
const (
	// CommentSortAsc 表示按 (created_at, id) 升序。
	CommentSortAsc CommentSort = "asc"
	// CommentSortDesc 表示按 (created_at, id) 降序。
	CommentSortDesc CommentSort = "desc"
)

// ValidCommentSort 报告排序方向字符串是否为受控的 asc/desc。
func ValidCommentSort(sort string) bool {
	return CommentSort(sort) == CommentSortAsc || CommentSort(sort) == CommentSortDesc
}

// NormalizeAdminSort 解析管理列表的 sort 参数：空值归一化为 desc（最新优先），
// 显式值必须是受控的 asc/desc，非法值返回验证错误。
func NormalizeAdminSort(raw string) (CommentSort, error) {
	if raw == "" {
		return CommentSortDesc, nil
	}
	if !ValidCommentSort(raw) {
		return "", ErrValidation
	}
	return CommentSort(raw), nil
}

// OffsetForPage 从已归一化的页码与每页数量安全推导 offset（第 1 页返回 0）。
// 页码由 handler 边界保证为正整数；本函数只做纯整数运算，溢出时钳制到最大可用偏移。
func OffsetForPage(page, limit int) int {
	if page <= 1 || limit <= 0 {
		return 0
	}
	max := int(^uint(0) >> 1)
	if page-1 > max/limit {
		return max - (max % limit)
	}
	return (page - 1) * limit
}

// ProviderKind 表示外部提供商类型。
type ProviderKind string

// 提供商类型枚举。
const (
	// ProviderKindCaptcha 表示验证码提供商。
	ProviderKindCaptcha ProviderKind = "captcha"
	// ProviderKindOAuth 表示 OAuth 提供商。
	ProviderKindOAuth ProviderKind = "oauth"
	// ProviderKindOIDC 表示 OIDC 提供商。
	ProviderKindOIDC ProviderKind = "oidc"
)

// CommentEventType 标识一种评论事件类型。
type CommentEventType string

// 评论事件类型枚举。
const (
	// TypeCommentCreated 在评论创建（提交）后发布。
	TypeCommentCreated CommentEventType = "comment.created"
	// TypeCommentPublished 仅在审核策略为 review、管理员把评论发布为
	// published 时发布；direct 策略的评论创建只产生创建事件。
	TypeCommentPublished CommentEventType = "comment.published"
)

// User 是用户的业务数据，不含 GORM tag。
type User struct {
	ID              int64
	Email           string
	EmailNormalized string
	Nickname        string
	WebsiteURL      *string
	Role            Role
	Status          UserStatus
	// SessionVersion 是第一方会话代次，随改密/重置/主动撤销单调递增。
	// 第一方 JWT 携带签发时的版本，鉴权时与当前版本比较。
	SessionVersion  int64
	EmailVerifiedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	// DeletedAt 是软删除时间，nil 表示账户未被软删除。
	DeletedAt *time.Time
	// StatusBeforeDelete 是软删除前的账户状态，仅软删除后有意义。
	StatusBeforeDelete *UserStatus
}

// Principal 是解析出的当前主体，注入请求上下文。
type Principal struct {
	UserID int64
	Role   Role
	Status UserStatus
	// SessionVersion 是解析时缓存的当前会话代次，用于与 JWT 声明比较。
	SessionVersion int64
}

// AuthzInfo 是以用户 id 为键缓存的状态、角色与会话代次数据。
type AuthzInfo struct {
	Role           Role       `json:"role"`
	Status         UserStatus `json:"status"`
	SessionVersion int64      `json:"session_version"`
}

// NotificationPreferences 是用户的邮件偏好数据。
type NotificationPreferences struct {
	ID                int64
	UserID            int64
	ReplyEnabled      bool
	ModerationEnabled bool
	UpdatedAt         time.Time
}

// Comment 是评论的业务实体，不含 GORM tag。
type Comment struct {
	ID       int64
	SiteID   int64
	ThreadID int64
	UserID   int64
	ParentID *int64
	RootID   *int64
	// ReplyToUserID 是被回复作者的 user id；根评论为 nil。
	// 被回复者账号硬删除后由外键 SET NULL 清空。
	ReplyToUserID      *int64
	Depth              int
	BodyMarkdown       string
	Status             CommentStatus
	StatusBeforeDelete *CommentStatus
	IPMode             PrivacyMode
	IPValue            *string
	UAMode             PrivacyMode
	UARaw              *string
	UABrowser          *string
	UAOS               *string
	UADevice           *string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	PublishedAt        *time.Time
	DeletedAt          *time.Time
}

// Thread 是线程的业务数据。
// 线程身份是 (site_id, page_key)，page_url 与 page_title 只是元数据。
// CommentsEnabled 是页面级评论开关，默认开启。
type Thread struct {
	ID              int64
	SiteID          int64
	PageKey         string
	PageURL         *string
	PageTitle       *string
	CommentsEnabled bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AdminThreadFilter 收窄管理员线程列表。nil 字段表示"不过滤"。
type AdminThreadFilter struct {
	SiteID          *int64
	CommentsEnabled *bool
	Q               string
	Sort            CommentSort
	Offset          int
	Limit           int
}

// AdminThread 是管理端线程列表行，关联站点名。
type AdminThread struct {
	Thread
	SiteName string
}

// ThreadPatch 是线程元数据 PATCH 的更新项。nil 字段表示不修改；
// ClearPageTitle 为 true 时显式清空 page_title。
type ThreadPatch struct {
	PageKey         *string
	PageTitle       *string
	ClearPageTitle  bool
	CommentsEnabled *bool
}

// Cursor 是每个列表查询使用的 (created_at, id) 分页位置。
type Cursor struct {
	CreatedAt time.Time
	ID        int64
}

// PublicComment 是评论与作者当前公开资料的连接结果。
// 公开读取时不会加载邮箱；AuthorEmailNormalized 只存在于 domain/service 边界，
// 供服务层派生头像 URL，绝不进入 HTTP DTO。
// ReplyToNickname 是回复目标作者的当前昵称；目标缺失或已注销时为 nil。
type PublicComment struct {
	Comment
	AuthorNickname        string
	AuthorWebsite         *string
	AuthorRole            Role
	AuthorEmailNormalized string
	ReplyToNickname       *string
}

// LatestPublicComment 是站点公开最新评论与所属线程元数据及作者当前公开资料的连接结果。
// 公开读取时不会加载邮箱；AuthorEmailNormalized 只存在于 domain/service 边界，
// 供服务层派生头像 URL，绝不进入 HTTP DTO。
// ReplyToNickname 是回复目标作者的当前昵称；目标缺失或已注销时为 nil。
type LatestPublicComment struct {
	Comment
	AuthorNickname        string
	AuthorWebsite         *string
	AuthorRole            Role
	AuthorEmailNormalized string
	ReplyToNickname       *string
	PageKey               string
	PageURL               *string
	PageTitle             *string
}

// AdminComment 是评论与作者邮箱及当前公开资料的连接结果。
// 保留捕获到的隐私字段，只提供给管理员。
// AuthorEmailNormalized 只用于派生头像 URL，不进入 HTTP DTO。
type AdminComment struct {
	Comment
	AuthorEmail           string
	AuthorNickname        string
	AuthorWebsite         *string
	AuthorRole            Role
	AuthorEmailNormalized string
	ReplyToNickname       *string
}

// AdminFilter 收窄管理员评论列表。nil 字段表示"不过滤"。
// Q 对正文、作者邮箱与昵称做全局包含搜索，与分页统计使用相同的过滤条件。
type AdminFilter struct {
	SiteID   *int64
	ThreadID *int64
	Status   *CommentStatus
	UserID   *int64
	Since    *time.Time
	Until    *time.Time
	Q        string
	Sort     CommentSort
	Offset   int
	Limit    int
}

// OwnerFilter 收窄当前用户本人的评论列表。nil 字段表示"不过滤"。
type OwnerFilter struct {
	SiteID *int64
	Status *CommentStatus
	Offset int
	Limit  int
}

// OwnerComment 是当前用户本人评论与站点/线程/作者公开资料的连接结果。
// AuthorEmailNormalized 只存在于 domain/service 边界，用于派生头像 URL，绝不进入 HTTP DTO。
type OwnerComment struct {
	Comment
	AuthorNickname        string
	AuthorWebsite         *string
	AuthorRole            Role
	AuthorEmailNormalized string
	ReplyToNickname       *string
	SiteName              string
	PageKey               string
	PageURL               *string
	PageTitle             *string
}

// OwnerSite 是当前用户发表过评论的站点。
type OwnerSite struct {
	ID   int64
	Name string
}

// CommentPolicy 是评论用例所需的动态实例策略数据。
type CommentPolicy struct {
	Mode                 string
	Epoch                int64
	Moderation           string
	UserDeleteMode       string
	MaxReplyDepth        int
	PublicRegistration   bool
	CaptchaPolicy        map[string]bool
	Privacy              PrivacyPolicy
	EmailDomainWhitelist []string
	EmailDomainBlacklist []string
	GravatarBaseURL      string
	CommentSort          string
	// OwOCatalogURL 是可选的 widget 远程表情目录地址；空串表示使用内置目录。
	OwOCatalogURL string
}

// PrivacyPolicy 是评论隐私捕获所需的模式数据。
type PrivacyPolicy struct {
	IPMode string
	UAMode string
}

// Origin 是站点允许来源的业务记录，携带稳定 ID 供管理端引用。
type Origin struct {
	ID     int64
	Origin string
}

// Site 是站点的业务表示。
type Site struct {
	ID           int64
	Name         string
	CanonicalURL string
	Status       SiteStatus
	Origins      []Origin
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Settings 是类型化的动态实例配置，由 dynamic_settings 行的值构建。
type Settings struct {
	CommentMode        string               `json:"comment_mode"`
	Moderation         string               `json:"moderation"`
	UserDeleteMode     string               `json:"user_delete_mode"`
	MaxReplyDepth      int                  `json:"max_reply_depth"`
	PublicRegistration bool                 `json:"public_registration"`
	Privacy            PrivacySettings      `json:"privacy"`
	CaptchaPolicy      map[string]bool      `json:"captcha_policy"`
	Notifications      NotificationSettings `json:"notifications"`
	// CaptchaProvider 是当前选择的 CAPTCHA provider key；空串表示未选择。
	CaptchaProvider string `json:"captcha_provider"`
	// EmailDomainWhitelist 非空时仅精确命中的域名允许创建新用户。
	EmailDomainWhitelist []string `json:"email_domain_whitelist"`
	// EmailDomainBlacklist 在白名单为空时精确命中的域名拒绝创建新用户。
	EmailDomainBlacklist []string `json:"email_domain_blacklist"`
	// GravatarBaseURL 是头像 URL 的基址，默认 Gravatar 官方地址。
	GravatarBaseURL string `json:"gravatar_base_url"`
	// CommentSort 是 widget 公开评论列表的默认排序方向，仅允许 asc/desc。
	CommentSort string `json:"comment_sort"`
	// OwOCatalogURL 是 widget 远程表情目录地址；空串表示不配置自定义目录。
	OwOCatalogURL string `json:"owo_catalog_url"`
}

// PrivacySettings 是隐私相关的动态设置：IP 与 UA 的存储粒度。
type PrivacySettings struct {
	IPMode string `json:"ip_mode"`
	UAMode string `json:"ua_mode"`
}

// NotificationSettings 是邮件通知开关的动态设置。
type NotificationSettings struct {
	Moderation bool `json:"moderation"`
	Replies    bool `json:"replies"`
}

// CommentEvent 是净化后的评论通知负载，不携带邮箱、IP 或原始用户数据。
type CommentEvent struct {
	Type      CommentEventType
	SiteID    int64
	ThreadID  int64
	CommentID int64
	UserID    int64
	ParentID  *int64
	Mode      string
}

// PasskeyCredential 是 passkey 凭证的业务数据。
// Transports 是 JSON 编码的 transport 提示列表。
type PasskeyCredential struct {
	ID              int64
	UserID          int64
	CredentialID    string
	PublicKey       []byte
	AttestationType string
	Transports      string
	SignCount       uint32
	BackupEligible  bool
	BackupState     bool
	Name            string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

// ExternalIdentity 是外部身份（OAuth/OIDC 绑定）的业务数据。
type ExternalIdentity struct {
	ID              int64
	UserID          int64
	ProviderKey     string
	ProviderSubject string
	VerifiedEmail   string
	CreatedAt       time.Time
	LastLoginAt     *time.Time
}

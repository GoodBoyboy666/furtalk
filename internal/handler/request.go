package handler

import (
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"furtalk/internal/service/setting"
)

// 请求 DTO。字段名与历史 HTTP 契约完全一致。

// EmailCodeRequest 是请求邮箱验证码的请求体。
type EmailCodeRequest struct {
	Email        string `json:"email"`
	CaptchaToken string `json:"captcha_token"`
}

// EmailCodeLoginRequest 是使用邮箱验证码登录的请求体。
type EmailCodeLoginRequest struct {
	Email        string `json:"email"`
	Code         string `json:"code"`
	CaptchaToken string `json:"captcha_token"`
}

// PasswordLoginRequest 是邮箱密码登录的请求体。
type PasswordLoginRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token"`
}

// PasswordResetCodeRequest 是匿名请求密码重置验证码的请求体。
type PasswordResetCodeRequest struct {
	Email        string `json:"email"`
	CaptchaToken string `json:"captcha_token"`
}

// PasswordResetConfirmRequest 是提交验证码与新密码完成密码重置的请求体。
// 不需要旧密码，也不要求 CAPTCHA。
type PasswordResetConfirmRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

// PasskeyLoginOptionsRequest 是开始 passkey 登录仪式的请求体。
type PasskeyLoginOptionsRequest struct {
	UserHandle *string `json:"user_handle"`
}

// PasskeyFinishRequest 是完成 passkey 断言或注册的请求体。
type PasskeyFinishRequest struct {
	Challenge string `json:"challenge"`
	Response  any    `json:"response"`
}

// PasskeyRenameRequest 是重命名 passkey 凭证的请求体。
type PasskeyRenameRequest struct {
	Name string `json:"name"`
}

// MeUpdateRequest 是更新当前用户资料的请求体。
type MeUpdateRequest struct {
	Nickname   *string `json:"nickname"`
	WebsiteURL *string `json:"website_url"`
}

// NotificationPreferencesRequest 是更新邮件偏好的请求体。
type NotificationPreferencesRequest struct {
	ReplyEnabled      bool `json:"reply_enabled"`
	ModerationEnabled bool `json:"moderation_enabled"`
}

// MePasswordRequest 是个人中心设置/修改密码的请求体。
// 已有密码时必须提交正确的 current_password；无密码用户首设密码忽略该字段。
type MePasswordRequest struct {
	CurrentPassword *string `json:"current_password"`
	NewPassword     string  `json:"new_password"`
}

// AdminUserCreateRequest 是预创建用户的请求体。
// 密码与邮箱验证开关相互独立：设置密码不会自动验证邮箱。
type AdminUserCreateRequest struct {
	Email         string  `json:"email"`
	Nickname      string  `json:"nickname"`
	WebsiteURL    *string `json:"website_url"`
	Role          string  `json:"role"`
	Password      *string `json:"password"`
	EmailVerified bool    `json:"email_verified"`
}

// AdminUserUpdateRequest 是修改用户资料的请求体（PATCH，字段可选）。
// WebsiteURL 使用 OptionalNullableString 区分省略与显式 null；
// 邮箱变化默认保留验证状态，只有显式 email_verified 才改变。
type AdminUserUpdateRequest struct {
	Email         *string                         `json:"email"`
	Nickname      *string                         `json:"nickname"`
	WebsiteURL    identity.OptionalNullableString `json:"website_url"`
	Role          *string                         `json:"role"`
	Status        *string                         `json:"status"`
	EmailVerified *bool                           `json:"email_verified"`
}

// AdminUserResetPasswordRequest 是管理员重置目标用户密码的请求体。
type AdminUserResetPasswordRequest struct {
	Password string `json:"password"`
}

// CreateCommentRequest 是 widget 评论创建请求体。
// WebsiteURL 使用 OptionalNullableString 区分缺省、显式 null 与覆盖值。
type CreateCommentRequest struct {
	PageKey      string                          `json:"page_key"`
	PageURL      *string                         `json:"page_url"`
	PageTitle    *string                         `json:"page_title"`
	ParentID     *string                         `json:"parent_id"`
	BodyMarkdown string                          `json:"body_markdown"`
	CaptchaToken string                          `json:"captcha_token"`
	Email        string                          `json:"email"`
	Nickname     string                          `json:"nickname"`
	WebsiteURL   identity.OptionalNullableString `json:"website_url"`
}

// ReplyRequest 是第一方回复的请求体。
type ReplyRequest struct {
	Body         string `json:"body"`
	CaptchaToken string `json:"captcha_token"`
}

// AuthorizationIssueRequest 是第一方一次性授权码请求。
type AuthorizationIssueRequest struct {
	SiteID    string `json:"site_id"`
	Origin    string `json:"origin"`
	RequestID string `json:"request_id"`
}

// AuthorizationExchangeRequest 是一次性授权码交换请求。
type AuthorizationExchangeRequest struct {
	Code string `json:"code"`
}

// AdminCommentUpdateRequest 只编辑 Markdown 正文。
type AdminCommentUpdateRequest struct {
	Body string `json:"body"`
}

// AdminThreadUpdateRequest 更新线程元数据（PATCH，字段可选，至少一个必填）。
// page_title / page_url 使用 OptionalNullableString：缺省保持、显式 null/空白清空、非空值覆盖。
type AdminThreadUpdateRequest struct {
	PageKey         *string                        `json:"page_key"`
	PageTitle       comment.OptionalNullableString `json:"page_title"`
	PageURL         comment.OptionalNullableString `json:"page_url"`
	CommentsEnabled *bool                          `json:"comments_enabled"`
}

// SiteRequest 是创建站点的请求体。
type SiteRequest struct {
	Name         string `json:"name"`
	CanonicalURL string `json:"canonical_url"`
}

// SiteUpdateRequest 是更新站点的请求体（PATCH，字段可选）。
type SiteUpdateRequest struct {
	Name         *string `json:"name"`
	CanonicalURL *string `json:"canonical_url"`
	Status       *string `json:"status"`
}

// OriginRequest 是添加 origin 的请求体。
type OriginRequest struct {
	Origin string `json:"origin"`
}

// SettingsPatchRequest 是设置 PATCH 请求体，仅提交需要修改的设置项。
type SettingsPatchRequest struct {
	Settings []setting.SettingItem `json:"settings"`
}

// ProviderUpsertRequest 是提供商新增/更新请求体。
// Enabled 仅 OAuth/OIDC 使用；CAPTCHA 提供商不允许携带该字段（传指针区分缺省与 false）。
// key/kind 矩阵由固定 catalog 投影：github→oauth、google→oidc、自定义 key→oidc，
// 以及 gitlab/microsoft/twitter/gitea/apple/discord/line/mastodon 固定预设；
// 未知 key 仅允许 oidc，拒绝任意自定义 oauth。
// Config 是自由表单的 map；各预设允许的公开字段：
//   - oauth/oidc 通用：client_id、client_secret（新建必填；编辑缺省/空值保留现有 Secret，非空才替换）
//   - gitlab：instance_url（默认 https://gitlab.com）
//   - gitea / mastodon：instance_url（必填；mastodon 需根域名且 4.3+）
//   - 自定义 oidc：issuer_url（HTTPS 必填）
//   - apple：client_id（Services ID）、team_id、key_id、private_key（新建必填；编辑缺省/空值保留）
//   - captcha：provider、site_key、secret_key、endpoint（可选；cap 必填）
//
// 管理响应与日志永不含任何 secret 或 envelope 字节。
type ProviderUpsertRequest struct {
	Kind    string         `json:"kind"`
	Enabled *bool          `json:"enabled"`
	Config  map[string]any `json:"config"`
}

// UnsubscribeRequest 携带通知邮件中的签名退订 token。
type UnsubscribeRequest struct {
	Token string `json:"token"`
}

// BootstrapAdminRequest 是创建首位管理员的请求体。
type BootstrapAdminRequest struct {
	SetupToken string `json:"setup_token"`
	Email      string `json:"email"`
	Nickname   string `json:"nickname"`
	Password   string `json:"password"`
}

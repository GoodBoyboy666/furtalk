package handler

import (
	"encoding/json"
	"fmt"

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

// PasswordLoginRequest 邮箱密码登录的请求体。
type PasswordLoginRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token"`
}

// PasswordResetCodeRequest 匿名请求密码重置验证码的请求体。
type PasswordResetCodeRequest struct {
	Email        string `json:"email"`
	CaptchaToken string `json:"captcha_token"`
}

// PasswordResetConfirmRequest 提交验证码与新密码完成密码重置的请求体。
// 不需要旧密码，也不要求 CAPTCHA。
type PasswordResetConfirmRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

// PasskeyLoginOptionsRequest 开始 discoverable passkey 登录仪式的空请求体。
// 保留 DTO 以便 DecodeBody 严格拒绝未来误传的用户标识字段。
type PasskeyLoginOptionsRequest struct{}

// UnmarshalJSON 校验 Passkey 登录 options 请求为空对象。
func (*PasskeyLoginOptionsRequest) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		if err == nil {
			err = fmt.Errorf("request must be a JSON object")
		}
		return err
	}
	if len(fields) != 0 {
		return fmt.Errorf("request must be an empty JSON object")
	}
	return nil
}

// PasskeyFinishRequest 完成 passkey 断言或注册的请求体。
type PasskeyFinishRequest struct {
	Challenge string `json:"challenge"`
	Response  any    `json:"response"`
}

// PasskeyRenameRequest 重命名 passkey 凭证的请求体。
type PasskeyRenameRequest struct {
	Name string `json:"name"`
}

// MeUpdateRequest 更新当前用户资料的请求体。
type MeUpdateRequest struct {
	Nickname   *string `json:"nickname"`
	WebsiteURL *string `json:"website_url"`
}

// NotificationPreferencesRequest 更新邮件偏好的请求体。
type NotificationPreferencesRequest struct {
	ReplyEnabled      bool `json:"reply_enabled"`
	ModerationEnabled bool `json:"moderation_enabled"`
}

// MePasswordRequest 个人中心设置/修改密码的请求体。
// 已有密码时必须提交正确的 current_password；无密码用户首设密码忽略该字段。
type MePasswordRequest struct {
	CurrentPassword *string `json:"current_password"`
	NewPassword     string  `json:"new_password"`
}

// AdminUserCreateRequest 预创建用户的请求体。
// 密码与邮箱验证开关相互独立：设置密码不会自动验证邮箱。
type AdminUserCreateRequest struct {
	Email         string  `json:"email"`
	Nickname      string  `json:"nickname"`
	WebsiteURL    *string `json:"website_url"`
	Role          string  `json:"role"`
	Password      *string `json:"password"`
	EmailVerified bool    `json:"email_verified"`
}

// AdminUserUpdateRequest 修改用户资料的请求体（PATCH，字段可选）。
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

// AdminUserResetPasswordRequest 管理员重置目标用户密码的请求体。
type AdminUserResetPasswordRequest struct {
	Password string `json:"password"`
}

// CreateCommentRequest  widget 评论创建请求体。
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

// ReplyRequest 第一方回复的请求体。
type ReplyRequest struct {
	Body         string `json:"body"`
	CaptchaToken string `json:"captcha_token"`
}

// AuthorizationIssueRequest 第一方一次性授权码请求。
type AuthorizationIssueRequest struct {
	SiteID    string `json:"site_id"`
	Origin    string `json:"origin"`
	RequestID string `json:"request_id"`
}

// AuthorizationExchangeRequest 一次性授权码交换请求。
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

// SiteRequest 创建站点的请求体。
type SiteRequest struct {
	Name         string `json:"name"`
	CanonicalURL string `json:"canonical_url"`
}

// SiteUpdateRequest 更新站点的请求体（PATCH，字段可选）。
type SiteUpdateRequest struct {
	Name         *string `json:"name"`
	CanonicalURL *string `json:"canonical_url"`
	Status       *string `json:"status"`
}

// OriginRequest 添加 origin 的请求体。
type OriginRequest struct {
	Origin string `json:"origin"`
}

// SettingsPatchRequest 设置 PATCH 请求体，仅提交需要修改的设置项。
type SettingsPatchRequest struct {
	Settings []setting.SettingItem `json:"settings"`
}

// ProviderUpsertRequest 提供商新增/更新请求体。
type ProviderUpsertRequest struct {
	Kind    string         `json:"kind"`
	Enabled *bool          `json:"enabled"`
	Config  map[string]any `json:"config"`
}

// UnsubscribeRequest 携带通知邮件中的签名退订 token。
type UnsubscribeRequest struct {
	Token string `json:"token"`
}

// BootstrapAdminRequest 创建首位管理员的请求体。
type BootstrapAdminRequest struct {
	SetupToken string `json:"setup_token"`
	Email      string `json:"email"`
	Nickname   string `json:"nickname"`
	Password   string `json:"password"`
}

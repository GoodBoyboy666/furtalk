package handler

import (
	"net/http"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/service/notification"
)

// errorMappings 返回全部语义错误到 HTTP 响应的单一映射组。
// 排列顺序决定翻译优先级：业务 sentinel 在前，协议错误在后。
func errorMappings() []httpx.Mapping {
	return []httpx.Mapping{
		// identity 域错误。
		{Target: domain.ErrNotFound, Status: http.StatusNotFound, Code: "not_found", Message: "资源不存在"},
		{Target: domain.ErrConflict, Status: http.StatusConflict, Code: "conflict", Message: "资源状态冲突"},
		{Target: domain.ErrValidation, Status: http.StatusUnprocessableEntity, Code: "invalid_input", Message: "请求参数无效"},
		{Target: domain.ErrForbidden, Status: http.StatusForbidden, Code: "forbidden", Message: "权限不足"},
		{Target: domain.ErrInvalidCredentials, Status: http.StatusUnauthorized, Code: "invalid_credentials", Message: "账号或密码错误"},
		{Target: domain.ErrOAuthAccessDenied, Status: http.StatusBadRequest, Code: "oauth_access_denied", Message: "授权已被取消"},
		{Target: domain.ErrOAuthCallbackInvalid, Status: http.StatusBadRequest, Code: "oauth_callback_invalid", Message: "授权回调无效或已过期"},
		{Target: domain.ErrOAuthVerificationFailed, Status: http.StatusBadRequest, Code: "oauth_verification_failed", Message: "第三方登录校验失败"},
		{Target: domain.ErrConfirmationRequired, Status: http.StatusUnprocessableEntity, Code: "invalid_input", Message: "破坏性操作需要显式确认"},
		{Target: domain.ErrDisabled, Status: http.StatusForbidden, Code: "forbidden", Message: "账号已被禁用"},
		{Target: domain.ErrAnonymousRestricted, Status: http.StatusForbidden, Code: "anonymous_mode_restricted", Message: "匿名模式下不可使用第一方访问"},
		{Target: domain.ErrRegistrationClosed, Status: http.StatusUnprocessableEntity, Code: "registration_closed", Message: "公开注册已关闭"},
		{Target: domain.ErrMailUnavailable, Status: http.StatusServiceUnavailable, Code: "mail_unavailable", Message: "邮件服务暂不可用"},
		{Target: domain.ErrRateLimited, Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "请求过于频繁"},
		{Target: domain.ErrLastAdmin, Status: http.StatusConflict, Code: "conflict", Message: "不能移除最后一个管理员"},
		{Target: domain.ErrLastLoginMethod, Status: http.StatusConflict, Code: "conflict", Message: "不能移除最后一个登录方式"},
		{Target: domain.ErrCacheInvalidation, Status: http.StatusInternalServerError, Code: "cache_invalidation_failed", Message: "授权缓存失效失败"},

		// comment 域错误。
		{Target: domain.ErrCaptchaRequired, Status: http.StatusUnprocessableEntity, Code: "invalid_input", Message: "需要完成验证码"},
		{Target: domain.ErrCaptchaUnavailable, Status: http.StatusServiceUnavailable, Code: "service_unavailable", Message: "验证码服务暂不可用"},
		{Target: domain.ErrCaptchaFailed, Status: http.StatusForbidden, Code: "forbidden", Message: "验证码验证失败"},
		{Target: domain.ErrProviderNotFound, Status: http.StatusNotFound, Code: "not_found", Message: "提供商不存在或未启用"},
		{Target: domain.ErrParentNotFound, Status: http.StatusNotFound, Code: "not_found", Message: "父评论不存在"},
		{Target: domain.ErrParentDeleted, Status: http.StatusConflict, Code: "conflict", Message: "父评论已删除"},
		{Target: domain.ErrCrossThreadReply, Status: http.StatusBadRequest, Code: "invalid_input", Message: "回复不能跨线程"},
		{Target: domain.ErrDepthExceeded, Status: http.StatusUnprocessableEntity, Code: "invalid_input", Message: "回复深度超过限制"},
		{Target: domain.ErrSiteInactive, Status: http.StatusForbidden, Code: "forbidden", Message: "站点已停用"},
		{Target: domain.ErrThreadClosed, Status: http.StatusConflict, Code: "thread_closed", Message: "评论区已关闭"},
		{Target: domain.ErrCredentialStale, Status: http.StatusForbidden, Code: "forbidden", Message: "凭证已过期，请重新获取"},
		{Target: domain.ErrCredentialMode, Status: http.StatusForbidden, Code: "forbidden", Message: "评论模式已变更，请刷新"},

		// setting 域错误。
		{Target: domain.ErrUnavailable, Status: http.StatusServiceUnavailable, Code: "service_unavailable", Message: "服务暂不可用"},
		{Target: domain.ErrSecretCorrupt, Status: http.StatusInternalServerError, Code: "internal_error", Message: "提供商密钥数据损坏"},

		// bootstrap 域错误。
		{Target: domain.ErrTokenInvalid, Status: http.StatusGone, Code: "bootstrap_unavailable", Message: "初始化已不可用"},
		{Target: domain.ErrAlreadyInitialized, Status: http.StatusGone, Code: "bootstrap_unavailable", Message: "初始化已不可用"},
		{Target: domain.ErrEmailExists, Status: http.StatusConflict, Code: "email_already_registered", Message: "该邮箱已被注册"},
		{Target: domain.ErrEmailDomainNotAllowed, Status: http.StatusUnprocessableEntity, Code: "email_domain_not_allowed", Message: "该邮箱域名不允许注册"},

		// notification 域错误。
		{Target: notification.ErrInvalidToken, Status: http.StatusBadRequest, Code: "invalid_unsubscribe_token", Message: "退订令牌无效"},

		// 协议错误位于映射组末尾，优先级最低。
	}
}

// NewTranslator 构造不可变、确定性的语义错误翻译表。
func NewTranslator() (*httpx.Translator, error) {
	return httpx.NewTranslator(
		errorMappings(),
		httpx.ProtocolErrorMappings(),
	)
}

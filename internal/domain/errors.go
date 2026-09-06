package domain

import "errors"

// 跨模块共享的错误 sentinel。
// 各 service 原样透传这些错误；HTTP 映射集中在 handler 层。
var (
	// ErrNotFound 在用户、评论、线程、站点、设置或提供商不存在时返回。
	ErrNotFound = errors.New("domain: not found")
	// ErrConflict 在资源状态冲突或唯一约束冲突时返回。
	ErrConflict = errors.New("domain: conflict")
	// ErrValidation 在输入不符合规范时返回。
	ErrValidation = errors.New("domain: validation failed")
	// ErrForbidden 在主体无权限执行操作时返回。
	ErrForbidden = errors.New("domain: forbidden")
	// ErrInvalidCredentials 在登录凭证或 widget 凭证无效时返回，保持通用以抑制枚举攻击。
	ErrInvalidCredentials = errors.New("domain: invalid credentials")
	// ErrOAuthAccessDenied 在用户取消第三方授权时返回。
	ErrOAuthAccessDenied = errors.New("domain: oauth access denied")
	// ErrOAuthCallbackInvalid 在 OAuth 回调的 state/handoff 缺失、过期、重放或与提供商不匹配时返回。
	ErrOAuthCallbackInvalid = errors.New("domain: oauth callback invalid")
	// ErrOAuthVerificationFailed 在授权码交换或第三方令牌校验失败时返回。
	ErrOAuthVerificationFailed = errors.New("domain: oauth verification failed")
	// ErrConfirmationRequired 在破坏性删除缺少显式确认时返回。
	ErrConfirmationRequired = errors.New("domain: confirmation required")

	// ErrDisabled 在账户被禁用时返回。
	ErrDisabled = errors.New("domain: disabled")
	// ErrAnonymousRestricted 在匿名模式下普通用户使用第一方 API 时返回。
	ErrAnonymousRestricted = errors.New("domain: anonymous mode restricted")
	// ErrRegistrationClosed 在公开注册关闭时返回。
	ErrRegistrationClosed = errors.New("domain: registration closed")
	// ErrMailUnavailable 在邮件服务未配置或投递失败时返回。
	ErrMailUnavailable = errors.New("domain: mail unavailable")
	// ErrLastAdmin 在试图降级或禁用最后一名活跃管理员时返回。
	ErrLastAdmin = errors.New("domain: last admin")
	// ErrLastLoginMethod 在试图移除用户最后一种登录方式时返回。
	ErrLastLoginMethod = errors.New("domain: last login method")
	// ErrCacheInvalidation 在提交后授权缓存失效失败时返回。
	ErrCacheInvalidation = errors.New("domain: cache invalidation failed")

	// ErrCaptchaRequired 在需要完成验证码时返回。
	ErrCaptchaRequired = errors.New("domain: captcha required")
	// ErrCaptchaUnavailable 在验证码服务不可用时返回。
	ErrCaptchaUnavailable = errors.New("domain: captcha unavailable")
	// ErrCaptchaFailed 在验证码校验失败时返回。
	ErrCaptchaFailed = errors.New("domain: captcha failed")
	// ErrProviderNotFound 在验证码、OAuth 或 OIDC 提供商不存在或未启用时返回。
	ErrProviderNotFound = errors.New("domain: provider not found")
	// ErrParentNotFound 在父评论不存在时返回。
	ErrParentNotFound = errors.New("domain: parent not found")
	// ErrParentDeleted 在父评论已删除时返回。
	ErrParentDeleted = errors.New("domain: parent deleted")
	// ErrCrossThreadReply 在回复跨线程时返回。
	ErrCrossThreadReply = errors.New("domain: cross-thread reply")
	// ErrDepthExceeded 在回复深度超过限制时返回。
	ErrDepthExceeded = errors.New("domain: depth exceeded")
	// ErrSiteInactive 在站点停用时返回。
	ErrSiteInactive = errors.New("domain: site inactive")
	// ErrThreadClosed 在线程的评论区关闭时返回。
	ErrThreadClosed = errors.New("domain: thread closed")
	// ErrCredentialStale 在 widget 凭证代次过期时返回。
	ErrCredentialStale = errors.New("domain: credential stale")
	// ErrCredentialMode 在 widget 凭证评论模式不匹配时返回。
	ErrCredentialMode = errors.New("domain: credential mode mismatch")

	// ErrUnavailable 在外部服务不可用时返回。
	ErrUnavailable = errors.New("domain: unavailable")
	// ErrRateLimited 在业务流程预算或并发容量耗尽时返回。
	ErrRateLimited = errors.New("domain: rate limited")
	// ErrSecretCorrupt 在 provider 配置的密文损坏或版本不符时返回。
	ErrSecretCorrupt = errors.New("domain: secret corrupt")

	// ErrTokenInvalid 在 setup token 无效、过期或已使用时返回。
	ErrTokenInvalid = errors.New("domain: token invalid")
	// ErrAlreadyInitialized 在实例已完成首次运行引导时返回。
	ErrAlreadyInitialized = errors.New("domain: already initialized")
	// ErrEmailExists 在首次引导时邮箱已存在时返回。
	ErrEmailExists = errors.New("domain: email exists")
	// ErrEmailDomainNotAllowed 在邮箱域名被域名名单策略拒绝注册时返回。
	// 该规则不是保密信息，明确提示而不伪装成凭据失败。
	ErrEmailDomainNotAllowed = errors.New("domain: email domain not allowed")
	// ErrAuthorizationRequired 在提交邮箱对应管理员但缺少有效 widget_authenticated
	// 凭据时返回，用于匿名模式的受控授权信号。
	ErrAuthorizationRequired = errors.New("domain: authorization required")
)

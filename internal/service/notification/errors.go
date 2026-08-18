package notification

import "errors"

// ErrInvalidToken 在退订令牌无效、过期或超出允许范围时返回。
var ErrInvalidToken = errors.New("notification: invalid token")

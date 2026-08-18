package httpx

import "context"

// OriginsProvider 是动态 CORS 中间件解析站点精确 origin 白名单的消费者拥有接口。
// 由 sites service 实现，经 internal/app 组合根注入，使中间件不依赖 GORM 与 repository。
type OriginsProvider interface {
	// AllowedOrigins 返回某个活跃站点允许的精确 origins。
	// 被禁用、不存在或出错的站点返回空列表，CORS 校验失败。
	AllowedOrigins(ctx context.Context, siteID int64) ([]string, error)
}

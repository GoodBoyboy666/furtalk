package app

import (
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

// persistenceModule 供应事务运行器与全部仓储。
func persistenceModule() fx.Option {
	return fx.Provide(
		newRepositories,
	)
}

// repositories 聚合全部 repository 实例。
type repositories struct {
	txRunner *gormtx.Runner

	users      *repository.UserRepo
	passkeys   *repository.PasskeyRepo
	identities *repository.ExternalIdentityRepo
	prefs      *repository.PreferenceRepo
	sites      *repository.SiteRepo
	threads    *repository.ThreadRepo
	comments   *repository.CommentRepo
	settings   *repository.SettingsRepo
	bootstrap  *repository.BootstrapRepo
}

// newRepositories 从已就绪的 *gorm.DB 构造全部仓储。
func newRepositories(db *gorm.DB) *repositories {
	return &repositories{
		txRunner:   gormtx.NewRunner(db),
		users:      repository.NewUserRepo(db),
		passkeys:   repository.NewPasskeyRepo(db),
		identities: repository.NewExternalIdentityRepo(db),
		prefs:      repository.NewPreferenceRepo(db),
		sites:      repository.NewSiteRepo(db),
		threads:    repository.NewThreadRepo(db),
		comments:   repository.NewCommentRepo(db),
		settings:   repository.NewSettingsRepo(db),
		bootstrap:  repository.NewBootstrapRepo(db),
	}
}

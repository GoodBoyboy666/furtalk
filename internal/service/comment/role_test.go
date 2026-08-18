package comment

import (
	"context"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
)

// TestPublicCommentRoleFlow 证明管理员发表评论后，创建响应与公开列表读取都携带
// 作者角色，且普通用户评论为 user。角色只依赖服务端返回的 author_role，不额外暴露个人信息。
func TestPublicCommentRoleFlow(t *testing.T) {
	db := avatarTestDB(t)
	fx := seedReplyFixture(t, db)

	admin := &domain.User{
		Email:           "admin@example.com",
		EmailNormalized: "admin@example.com",
		Nickname:        "admin",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
	}
	if err := repository.NewUserRepo(db).Create(context.Background(), admin); err != nil {
		t.Fatalf("create admin: %v", err)
	}

	pol := domain.CommentPolicy{
		Mode:            domain.CommentModeAuthenticated,
		Moderation:      domain.ModerationDirect,
		MaxReplyDepth:   5,
		CaptchaPolicy:   map[string]bool{},
		Privacy:         domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
		GravatarBaseURL: "https://www.gravatar.com/avatar",
		CommentSort:     string(domain.CommentSortAsc),
	}
	runner := &recordingTxRunner{inner: gormtx.NewRunner(db)}
	bus := &recordingEventBus{}
	svc := avatarTestService(db, pol, bus, runner)
	ctx := context.Background()

	adminView, err := svc.CreateReplyFirstParty(ctx, admin.ID, domain.RoleAdmin, fx.ParentID, "admin reply", "", nil, "ua")
	if err != nil {
		t.Fatalf("create admin reply: %v", err)
	}
	if adminView.AuthorRole != domain.RoleAdmin {
		t.Fatalf("create response role = %q, want admin", adminView.AuthorRole)
	}

	userView, err := svc.CreateReplyFirstParty(ctx, fx.UserID, domain.RoleUser, fx.ParentID, "user reply", "", nil, "ua")
	if err != nil {
		t.Fatalf("create user reply: %v", err)
	}
	if userView.AuthorRole != domain.RoleUser {
		t.Fatalf("create response role = %q, want user", userView.AuthorRole)
	}

	threadView, err := svc.ListPublic(ctx, fx.SiteID, "page-key", "", "", 10)
	if err != nil {
		t.Fatalf("list public: %v", err)
	}
	got := map[domain.Role]bool{}
	for _, c := range threadView.Comments {
		got[c.AuthorRole] = true
	}
	if !got[domain.RoleAdmin] || !got[domain.RoleUser] {
		t.Fatalf("public list roles = %v, want both admin and user", got)
	}

	adminList, err := svc.AdminList(ctx, domain.AdminFilter{}, 1)
	if err != nil {
		t.Fatalf("admin list: %v", err)
	}
	adminRoles := map[domain.Role]bool{}
	for _, c := range adminList.Comments {
		adminRoles[c.AuthorRole] = true
	}
	if !adminRoles[domain.RoleAdmin] || !adminRoles[domain.RoleUser] {
		t.Fatalf("admin list roles = %v, want both admin and user", adminRoles)
	}
}

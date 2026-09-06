package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/middleware"
	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"furtalk/internal/service/site"
	"github.com/gin-gonic/gin"
)

// adminSessionPolicyReader 返回匿名模式、注册关闭、验证码关闭的评论策略。
type adminSessionPolicyReader struct{}

func (adminSessionPolicyReader) CommentPolicy(context.Context) (domain.CommentPolicy, error) {
	return domain.CommentPolicy{
		Mode:               domain.CommentModeAnonymous,
		Epoch:              1,
		Moderation:         domain.ModerationDirect,
		UserDeleteMode:     domain.UserDeleteModeSoft,
		MaxReplyDepth:      5,
		PublicRegistration: false,
		CaptchaPolicy:      map[string]bool{},
		Privacy:            domain.PrivacyPolicy{IPMode: "none", UAMode: "none"},
		CommentSort:        string(domain.CommentSortAsc),
	}, nil
}

// dbPrincipalStore 从真实用户仓储解析当前主体。
type dbPrincipalStore struct {
	users *repository.UserRepo
}

func (s dbPrincipalStore) Resolve(ctx context.Context, userID int64) (domain.Principal, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return domain.Principal{}, err
	}
	return domain.Principal{UserID: user.ID, Role: user.Role, Status: user.Status, SessionVersion: user.SessionVersion}, nil
}

// adminSessionGate 只要求活跃主体；匿名模式下的角色矩阵由服务层强制。
type adminSessionGate struct{}

func (adminSessionGate) RequireUser(context.Context, domain.Principal) error { return nil }

// buildAdminAuthorizationRouter 装配匿名管理员保护全链路：widget 端点 + 第一方授权
// 端点共用同一套真实仓储、签名器与主体解析。
func buildAdminAuthorizationRouter(t *testing.T) (*gin.Engine, *comment.WidgetSigner, *repository.UserRepo, int64, int64) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "widget-admin-authz.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, model.All()...); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	ctx := context.Background()

	siteRepo := repository.NewSiteRepo(db)
	sitesService := site.NewService(siteRepo)
	created, err := sitesService.Create(ctx, "Site", testWidgetOrigin)
	if err != nil {
		t.Fatalf("create site: %v", err)
	}
	if _, err := sitesService.AddOrigin(ctx, created.ID, testWidgetOrigin); err != nil {
		t.Fatalf("add origin: %v", err)
	}

	userRepo := repository.NewUserRepo(db)
	admin := &domain.User{
		Email:           "admin@example.com",
		EmailNormalized: "admin@example.com",
		Nickname:        "admin",
		Role:            domain.RoleAdmin,
		Status:          domain.UserStatusActive,
	}
	if err := userRepo.Create(ctx, admin); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	ordinary := &domain.User{
		Email:           "user@example.com",
		EmailNormalized: "user@example.com",
		Nickname:        "user",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
	}
	if err := userRepo.Create(ctx, ordinary); err != nil {
		t.Fatalf("create ordinary user: %v", err)
	}

	widgetSigner := comment.NewWidgetSigner(comment.WidgetSignerConfig{
		Issuer:   "https://app.example",
		Key:      []byte("widget-admin-authz-test-key"),
		Lifetime: time.Hour,
	})
	verifier := comment.NewWidgetJWTVerifierFromSigner(widgetSigner)
	identitySigner := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: time.Hour,
	})
	authz := dbPrincipalStore{users: userRepo}
	userW := identity.NewService(identity.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Users:    userRepo,
		Policy:   authPolicyReader{},
	})
	svc := comment.NewService(comment.Dependencies{
		TxRunner: gormtx.NewRunner(db),
		Threads:  repository.NewThreadRepo(db),
		Comments: repository.NewCommentRepo(db),
		Sites:    siteRepo,
		Users:    userRepo,
		Settings: adminSessionPolicyReader{},
		UserW:    userW,
		Authz:    authz,
		Signer:   widgetSigner,
		Verifier: verifier,
		Codes:    comment.NewAuthCodeStore(cache.NewMemory(cache.DefaultMemoryLimit)),
		Logger:   nil,
	})

	origins := httpxOrigins{svc: sitesService}
	router := gin.New()
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router.Use(httpx.ErrorWriter(translator))
	router.Use(middleware.JWTVerification(identitySigner))
	router.Use(middleware.PrincipalResolution(authz))
	RegisterWidget(router.Group("/api/v1"), svc, verifier, adminSessionSettingsReader{}, authz, origins)
	RegisterFirstPartyCommentAuthorizationWithAdmission(router.Group("/api/v1"), svc, adminSessionGate{}, nil)
	return router, widgetSigner, userRepo, admin.ID, ordinary.ID
}

// adminSessionSettingsReader 提供 widget 中间件读取的当前模式与 epoch。
type adminSessionSettingsReader struct{}

func (adminSessionSettingsReader) WidgetConfig(context.Context) (string, int64, error) {
	return domain.CommentModeAnonymous, 1, nil
}

// adminFPCookie 签发管理员的第一方会话 cookie。
func adminFPCookie(t *testing.T, userID int64) *http.Cookie {
	t.Helper()
	signer := identity.NewSigner(identity.SignerConfig{
		Issuer:   "test",
		Key:      []byte("test-key"),
		Lifetime: time.Hour,
	})
	token, err := signer.SignFirstParty(userID, 1)
	if err != nil {
		t.Fatalf("sign first-party token: %v", err)
	}
	return &http.Cookie{Name: middleware.FirstPartyCookieName, Value: token}
}

// postWidgetComment 提交 widget 评论创建请求并返回 recorder。
func postWidgetComment(router *gin.Engine, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/widget/sites/1/comments", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testWidgetOrigin)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// exchangeWidgetCode 以给定 cookie 携带的 widget 会话兑换授权码。
func exchangeWidgetCode(router *gin.Engine, code string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/widget/comment-authorizations/exchange", strings.NewReader(`{"code":"`+code+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testWidgetOrigin)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// issueAuthorizationCode 以给定 FP cookie 为当前主体签发一次性授权码。
func issueAuthorizationCode(t *testing.T, router *gin.Engine, login *http.Cookie, requestID string) string {
	t.Helper()
	body := `{"site_id":"1","origin":"https://site.example","request_id":"` + requestID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comment-authorizations", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(login)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp AuthorizationIssueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode issue response: %v", err)
	}
	return resp.Code
}

// widgetCookieOf 返回响应 Set-Cookie 中的 widget cookie，未设置时返回空。
func widgetCookieOf(rec *httptest.ResponseRecorder) string {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == middleware.WidgetCookieName {
			return cookie.Value
		}
	}
	return ""
}

// probeWidgetSession 携带给定 widget cookie 探测会话。
func probeWidgetSession(router *gin.Engine, cookieValue string) (*httptest.ResponseRecorder, WidgetSessionResponse) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/widget/session", nil)
	req.Header.Set("Origin", testWidgetOrigin)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: middleware.WidgetCookieName, Value: cookieValue})
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var resp WidgetSessionResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp
}

// TestCreateAnonymousAdminEmailReturnsNeedAuthCodeNoCookie 证明管理员邮箱在匿名模式
// 无凭据时只返回受控的 need_auth_code，不写 cookie、不创建/修改用户、不创建评论。
func TestCreateAnonymousAdminEmailReturnsNeedAuthCodeNoCookie(t *testing.T) {
	router, _, userRepo, adminID, _ := buildAdminAuthorizationRouter(t)

	rec := postWidgetComment(router, `{"page_key":"page","email":"ADMIN@example.com","nickname":"renamed","body_markdown":"hi"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp WidgetAuthorizationRequiredResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.NeedAuthCode {
		t.Fatalf("need_auth_code = false, want true; body=%s", rec.Body.String())
	}
	if cookie := widgetCookieOf(rec); cookie != "" {
		t.Fatalf("unexpected widget cookie: %q", cookie)
	}
	admin, err := userRepo.FindByID(context.Background(), adminID)
	if err != nil {
		t.Fatalf("find admin: %v", err)
	}
	if admin.Nickname != "admin" {
		t.Fatalf("admin nickname changed to %q, want unchanged", admin.Nickname)
	}
}

// TestAdminAnonymousExchangeAndAuthorizedComment 覆盖完整成功链路：管理员邮箱触发
// need_auth_code -> popup 签发 -> exchange 得到 widget_authenticated -> 携带有效
// 凭据与匹配邮箱重试评论成功，probe 随即可用。
func TestAdminAnonymousExchangeAndAuthorizedComment(t *testing.T) {
	router, _, _, adminID, _ := buildAdminAuthorizationRouter(t)

	rec := postWidgetComment(router, `{"page_key":"page","email":"admin@example.com","nickname":"admin","body_markdown":"hi"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	login := adminFPCookie(t, adminID)
	code := issueAuthorizationCode(t, router, login, "request-123")

	exchange := exchangeWidgetCode(router, code)
	if exchange.Code != http.StatusNoContent {
		t.Fatalf("exchange status = %d, want 204; body=%s", exchange.Code, exchange.Body.String())
	}
	cookie := widgetCookieOf(exchange)
	if cookie == "" {
		t.Fatalf("expected a widget cookie on 204")
	}

	_, probe := probeWidgetSession(router, cookie)
	if !probe.Valid {
		t.Fatalf("probe valid = false, want true; body=%+v", probe)
	}
	if probe.CredentialMode != domain.CommentModeAuthenticated || probe.UserID != "1" {
		t.Fatalf("probe = %+v, want authenticated credential for user 1", probe)
	}

	// 携带有效凭据与匹配管理员邮箱的评论创建成功。
	rec = postWidgetComment(router, `{"page_key":"page","email":"admin@example.com","nickname":"admin","body_markdown":"authorized comment"}`, &http.Cookie{Name: middleware.WidgetCookieName, Value: cookie})
	if rec.Code != http.StatusCreated {
		t.Fatalf("authorized comment status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// 携带凭据但邮箱不匹配的评论创建必须拒绝。
	rec = postWidgetComment(router, `{"page_key":"page","email":"user@example.com","nickname":"admin","body_markdown":"mismatch"}`, &http.Cookie{Name: middleware.WidgetCookieName, Value: cookie})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched email status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}

	// 无凭据但邮箱不匹配普通邮箱时，管理员凭据不能用于普通邮箱。
	rec = postWidgetComment(router, `{"page_key":"page","email":"user@example.com","nickname":"admin","body_markdown":"ordinary"}`, &http.Cookie{Name: middleware.WidgetCookieName, Value: cookie})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary with admin credential status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// TestCreateAnonymousClosedRegistrationDeniesUnknown 证明注册关闭时未知邮箱无法匿名
// 发布评论，而已存在的普通用户仍可继续发表评论。
func TestCreateAnonymousClosedRegistrationDeniesUnknown(t *testing.T) {
	router, _, _, _, _ := buildAdminAuthorizationRouter(t)

	rec := postWidgetComment(router, `{"page_key":"page","email":"unknown@example.com","nickname":"visitor","body_markdown":"hi"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown email status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if cookie := widgetCookieOf(rec); cookie != "" {
		t.Fatalf("unexpected widget cookie")
	}

	// 已存在普通用户不受注册关闭影响。
	rec = postWidgetComment(router, `{"page_key":"page","email":"user@example.com","nickname":"user","body_markdown":"hi"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("existing ordinary status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if cookie := widgetCookieOf(rec); cookie != "" {
		t.Fatalf("anonymous ordinary posting must not write a widget cookie")
	}
}

// TestAnonymousAuthorizationIssueRejectsOrdinaryUser 证明匿名模式下普通第一方主体
// 不能通过 popup 签发授权码（仅管理员可），无法借此取得 widget 凭据。
func TestAnonymousAuthorizationIssueRejectsOrdinaryUser(t *testing.T) {
	router, _, _, _, ordinaryID := buildAdminAuthorizationRouter(t)

	login := adminFPCookie(t, ordinaryID)
	body := `{"site_id":"1","origin":"https://site.example","request_id":"request-ordinary"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comment-authorizations", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(login)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminAnonymousCodeExchangeRejectsDemotedPrincipal 证明签发后管理员被禁用，
// 授权码交换与既有 widget 凭证探测都失败关闭。
func TestAdminAnonymousCodeExchangeRejectsDemotedPrincipal(t *testing.T) {
	router, _, userRepo, adminID, _ := buildAdminAuthorizationRouter(t)

	login := adminFPCookie(t, adminID)
	code := issueAuthorizationCode(t, router, login, "request-demote")

	if err := userRepo.UpdateRoleStatus(context.Background(), adminID, domain.RoleAdmin, domain.UserStatusDisabled); err != nil {
		t.Fatalf("disable admin: %v", err)
	}

	exchange := exchangeWidgetCode(router, code)
	if exchange.Code != http.StatusUnauthorized {
		t.Fatalf("exchange status = %d, want 401; body=%s", exchange.Code, exchange.Body.String())
	}
	if cookie := widgetCookieOf(exchange); cookie != "" {
		t.Fatalf("unexpected widget cookie for demoted admin")
	}
}

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/service/comment"
	"github.com/gin-gonic/gin"
)

// widgetTestCredential 是中间件测试使用的固定 widget 凭证。
type widgetTestCredential struct {
	userID    int64
	siteID    int64
	epoch     int64
	expiresAt time.Time
}

func (c widgetTestCredential) UserID() int64        { return c.userID }
func (c widgetTestCredential) SiteID() int64        { return c.siteID }
func (c widgetTestCredential) Epoch() int64         { return c.epoch }
func (c widgetTestCredential) ExpiresAt() time.Time { return c.expiresAt }

// widgetTestVerifier 返回固定的已验证 widget 凭证。
type widgetTestVerifier struct {
	cred comment.WidgetCredential
}

func (v widgetTestVerifier) Verify(context.Context, string) (comment.WidgetCredential, error) {
	return v.cred, nil
}

// failingWidgetTestVerifier 模拟无法解析/已停用的 cookie 值（含旧 widget_anonymous）。
type failingWidgetTestVerifier struct{}

func (failingWidgetTestVerifier) Verify(context.Context, string) (comment.WidgetCredential, error) {
	return nil, domain.ErrInvalidCredentials
}

// widgetTestSettingsReader 返回固定的当前模式与凭证代次。
type widgetTestSettingsReader struct {
	mode  string
	epoch int64
}

func (r widgetTestSettingsReader) WidgetConfig(context.Context) (string, int64, error) {
	return r.mode, r.epoch, nil
}

// TestWidgetOptionalResolutionMatrix 锁定统一评论创建路由的可选凭证解析：
// 缺省 Cookie 视为无凭证放行；present-invalid（含旧 widget_anonymous）不授予
// principal 并机会性清除；有效签名但 stale epoch / 非活跃主体 / 站点不匹配的
// Cookie 不授予 principal 且不清除；只有完全有效的 widget_authenticated 才进入
// 请求上下文。管理员邮箱与认证模式的失败关闭由 handler/service 基于无 principal
// 继续实现。
func TestWidgetOptionalResolutionMatrix(t *testing.T) {
	gin.SetMode(gin.TestMode)

	validCred := widgetTestCredential{userID: 1, siteID: 1, epoch: 1, expiresAt: time.Now().Add(time.Hour)}
	adminPrincipal := domain.Principal{UserID: 1, Role: domain.RoleAdmin, Status: domain.UserStatusActive}

	tests := []struct {
		name      string
		verifier  comment.WidgetCredentialVerifier
		cred      comment.WidgetCredential
		settings  widgetTestSettingsReader
		pathSite  string
		principal domain.Principal
		wantGrant bool // handler 是否获得 principal
		wantClear bool // 是否写清除 cookie
	}{
		{name: "absent cookie", verifier: widgetTestVerifier{cred: validCred}, wantGrant: false, wantClear: false},
		{name: "invalid cookie", verifier: failingWidgetTestVerifier{}, settings: widgetTestSettingsReader{mode: domain.CommentModeAuthenticated, epoch: 1}, wantGrant: false, wantClear: true},
		{name: "stale epoch", verifier: widgetTestVerifier{cred: validCred}, settings: widgetTestSettingsReader{mode: domain.CommentModeAuthenticated, epoch: 2}, wantGrant: false, wantClear: false},
		{name: "site mismatch", verifier: widgetTestVerifier{cred: validCred}, settings: widgetTestSettingsReader{mode: domain.CommentModeAuthenticated, epoch: 1}, pathSite: "2", wantGrant: false, wantClear: false},
		{name: "anonymous ordinary", verifier: widgetTestVerifier{cred: validCred}, settings: widgetTestSettingsReader{mode: domain.CommentModeAnonymous, epoch: 1}, principal: domain.Principal{UserID: 1, Role: domain.RoleUser, Status: domain.UserStatusActive}, wantGrant: false, wantClear: false},
		{name: "valid authenticated", verifier: widgetTestVerifier{cred: validCred}, settings: widgetTestSettingsReader{mode: domain.CommentModeAuthenticated, epoch: 1}, pathSite: "1", wantGrant: true, wantClear: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := tt.principal
			if principal.Role == "" {
				principal = adminPrincipal
			}
			handler := WidgetOptionalResolution(
				tt.verifier,
				tt.settings,
				fakePrincipalStore{principal: principal},
			)
			r := gin.New()
			r.GET("/widget/sites/:site_id/comments", handler, func(c *gin.Context) {
				_, granted := WidgetCredentialOf(c)
				if granted != tt.wantGrant {
					t.Fatalf("principal granted = %v, want %v", granted, tt.wantGrant)
				}
				c.Status(http.StatusOK)
			})
			req := httptest.NewRequest(http.MethodGet, "/widget/sites/"+firstNonEmpty(tt.pathSite, "1")+"/comments", nil)
			if tt.name != "absent cookie" {
				req.AddCookie(&http.Cookie{Name: WidgetCookieName, Value: "raw"})
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d (handler must always run); body=%s", rec.Code, http.StatusOK, rec.Body.String())
			}
			cleared := false
			for _, cookie := range rec.Result().Cookies() {
				if cookie.Name == WidgetCookieName && cookie.MaxAge < 0 {
					cleared = true
				}
			}
			if cleared != tt.wantClear {
				t.Fatalf("cookie cleared = %v, want %v; set-cookies=%v", cleared, tt.wantClear, rec.Result().Cookies())
			}
		})
	}
}

// firstNonEmpty 返回第一个非空字符串，用于默认路径站点参数。
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// TestWidgetPrincipalResolutionRoleMatrix 验证受保护 widget 路由的中间件
// 与 Probe 使用同一角色判定：认证模式下普通用户与管理员都放行；匿名模式下
// widget 凭据只允许活跃管理员；非活跃一律拒绝。
func TestWidgetPrincipalResolutionRoleMatrix(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name   string
		mode   string
		role   domain.Role
		status domain.UserStatus
		want   int
	}{
		{name: "authenticated admin", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, status: domain.UserStatusActive, want: http.StatusOK},
		{name: "authenticated user", mode: domain.CommentModeAuthenticated, role: domain.RoleUser, status: domain.UserStatusActive, want: http.StatusOK},
		{name: "anonymous admin", mode: domain.CommentModeAnonymous, role: domain.RoleAdmin, status: domain.UserStatusActive, want: http.StatusOK},
		{name: "anonymous user", mode: domain.CommentModeAnonymous, role: domain.RoleUser, status: domain.UserStatusActive, want: http.StatusForbidden},
		{name: "authenticated admin disabled", mode: domain.CommentModeAuthenticated, role: domain.RoleAdmin, status: domain.UserStatusDisabled, want: http.StatusForbidden},
		{name: "anonymous admin disabled", mode: domain.CommentModeAnonymous, role: domain.RoleAdmin, status: domain.UserStatusDisabled, want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := widgetTestCredential{userID: 1, siteID: 1, epoch: 1, expiresAt: time.Now().Add(time.Hour)}
			handler := WidgetPrincipalResolution(
				widgetTestVerifier{cred: cred},
				widgetTestSettingsReader{mode: tt.mode, epoch: 1},
				fakePrincipalStore{principal: domain.Principal{UserID: 1, Role: tt.role, Status: tt.status}},
			)
			r := gin.New()
			r.GET("/protected", handler, func(c *gin.Context) {
				c.Status(http.StatusOK)
			})
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.AddCookie(&http.Cookie{Name: WidgetCookieName, Value: "raw"})
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

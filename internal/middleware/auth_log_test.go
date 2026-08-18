package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/logging"
	tokenclaims "furtalk/internal/platform/token"
	"furtalk/internal/service/comment"
	"github.com/gin-gonic/gin"
	gojwt "github.com/golang-jwt/jwt/v5"
)

type fakePrincipalStore struct {
	principal domain.Principal
	err       error
}

func (f fakePrincipalStore) Resolve(ctx context.Context, userID int64) (domain.Principal, error) {
	return f.principal, f.err
}

// identityPrincipalStore 返回与请求主体一致的 principal，用于隔离测试。
type identityPrincipalStore struct{}

func (identityPrincipalStore) Resolve(ctx context.Context, userID int64) (domain.Principal, error) {
	return domain.Principal{UserID: userID, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 1}, nil
}

// decodeLog 解码 AccessLog 捕获的单行 JSON 记录。
func decodeLog(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode access log: %v\nraw: %s", err, buf.String())
	}
	return record
}

// TestPrincipalResolutionAppendsUserID 验证第一方 principal 解析成功后，
// user_id 被追加到请求 context，并能出现在 AccessLog 中。
func TestPrincipalResolutionAppendsUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)

	r := gin.New()
	r.Use(httpx.RequestID())
	r.Use(httpx.AccessLog(logger))
	r.Use(func(c *gin.Context) {
		c.Set(claimsKey, &tokenclaims.Claims{SessionVersion: 1, RegisteredClaims: gojwt.RegisteredClaims{Subject: "7"}})
		c.Next()
	})
	r.Use(PrincipalResolution(fakePrincipalStore{principal: domain.Principal{UserID: 7, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 1}}))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}

	record := decodeLog(t, &buf)
	if record["user_id"] != "7" {
		t.Fatalf("user_id = %v, want 7", record["user_id"])
	}
}

// TestPrincipalResolutionSkipsAnonymous 验证无 claims 的请求不追加 user_id。
func TestPrincipalResolutionSkipsAnonymous(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)

	r := gin.New()
	r.Use(httpx.RequestID())
	r.Use(httpx.AccessLog(logger))
	r.Use(PrincipalResolution(fakePrincipalStore{principal: domain.Principal{UserID: 7, Role: domain.RoleUser, Status: domain.UserStatusActive}}))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe", nil))

	record := decodeLog(t, &buf)
	if _, ok := record["user_id"]; ok {
		t.Fatalf("anonymous request must not carry user_id, got %v", record["user_id"])
	}
}

// TestPrincipalResolutionClearsStaleSessionOnMissingUser 验证 JWT 有效但用户
// 不存在时：公开 handler 不被阻断、两枚第一方 Cookie 被清除、访问日志不携带 user_id。
func TestPrincipalResolutionClearsStaleSessionOnMissingUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)

	r := gin.New()
	r.Use(httpx.RequestID())
	r.Use(httpx.AccessLog(logger))
	r.Use(func(c *gin.Context) {
		c.Set(claimsKey, &tokenclaims.Claims{RegisteredClaims: gojwt.RegisteredClaims{Subject: "99"}})
		c.Next()
	})
	r.Use(PrincipalResolution(fakePrincipalStore{err: domain.ErrNotFound}))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (public handler must not be blocked)", recorder.Code)
	}
	record := decodeLog(t, &buf)
	if _, ok := record["user_id"]; ok {
		t.Fatalf("stale session must not carry user_id, got %v", record["user_id"])
	}
	assertStaleCookiesCleared(t, recorder)
}

// TestPrincipalResolutionStaleSessionStillRequiresAuth 验证同一残留会话无法绕过
// RequireUser / RequireAdmin 门禁：缺少 principal 时按现有契约返回 401。
func TestPrincipalResolutionStaleSessionStillRequiresAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	run := func(t *testing.T, gate gin.HandlerFunc) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set(claimsKey, &tokenclaims.Claims{RegisteredClaims: gojwt.RegisteredClaims{Subject: "99"}})
			c.Next()
		})
		r.Use(PrincipalResolution(fakePrincipalStore{err: domain.ErrNotFound}))
		r.GET("/protected", gate, func(c *gin.Context) { c.Status(http.StatusNoContent) })

		recorder := httptest.NewRecorder()
		r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/protected", nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), `"code":"unauthorized"`) {
			t.Fatalf("body = %s, want unauthorized code", recorder.Body.String())
		}
	}

	t.Run("RequireUser", func(t *testing.T) {
		run(t, RequireUser(fakeRequireUserGate{}))
	})
	t.Run("RequireAdmin", func(t *testing.T) {
		run(t, RequireAdmin(fakeRequireAdminGate{}))
	})
}

// TestPrincipalResolutionFailClosedOnStoreError 验证 principal 存储返回非
// ErrNotFound 错误时仍 fail closed，保持 authorization_unavailable 契约。
func TestPrincipalResolutionFailClosedOnStoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)

	r := gin.New()
	r.Use(httpx.RequestID())
	r.Use(httpx.AccessLog(logger))
	r.Use(func(c *gin.Context) {
		c.Set(claimsKey, &tokenclaims.Claims{RegisteredClaims: gojwt.RegisteredClaims{Subject: "7"}})
		c.Next()
	})
	r.Use(PrincipalResolution(fakePrincipalStore{err: errors.New("authz backend down")}))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"code":"authorization_unavailable"`) {
		t.Fatalf("body = %s, want authorization_unavailable code", recorder.Body.String())
	}
	record := decodeLog(t, &buf)
	if _, ok := record["user_id"]; ok {
		t.Fatalf("fail-closed request must not carry user_id, got %v", record["user_id"])
	}
}

// fakeRequireUserGate 是恒通过的 RequireUser 门禁替身，仅用于证明门禁本身未被调用。
type fakeRequireUserGate struct{}

func (fakeRequireUserGate) RequireUser(context.Context, domain.Principal) error { return nil }

// fakeRequireAdminGate 是恒通过的 RequireAdmin 门禁替身，仅用于证明门禁本身未被调用。
type fakeRequireAdminGate struct{}

func (fakeRequireAdminGate) RequireAdmin(context.Context, domain.Principal) error { return nil }

// assertStaleCookiesCleared 断言响应以 Max-Age=-1 清除了两枚第一方 Cookie。
func assertStaleCookiesCleared(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookie count = %d, want 2 cleared cookies", len(cookies))
	}
	names := map[string]bool{}
	for _, cookie := range cookies {
		names[cookie.Name] = true
		if cookie.MaxAge != -1 || cookie.Value != "" {
			t.Errorf("stale session cookie %s not cleared: %+v", cookie.Name, cookie)
		}
	}
	if !names[FirstPartyCookieName] || !names[CSRFCookieName] {
		t.Fatalf("cleared cookies = %v, want %s and %s", cookies, FirstPartyCookieName, CSRFCookieName)
	}
}

// TestPrincipalResolutionRequestsIsolated 验证连续请求的 user_id 不串字段。
func TestPrincipalResolutionRequestsIsolated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)

	r := gin.New()
	r.Use(httpx.RequestID())
	r.Use(httpx.AccessLog(logger))
	r.Use(func(c *gin.Context) {
		switch c.GetHeader("X-Test-User") {
		case "a":
			c.Set(claimsKey, &tokenclaims.Claims{SessionVersion: 1, RegisteredClaims: gojwt.RegisteredClaims{Subject: "1"}})
		case "b":
			c.Set(claimsKey, &tokenclaims.Claims{SessionVersion: 1, RegisteredClaims: gojwt.RegisteredClaims{Subject: "2"}})
		}
		c.Next()
	})
	r.Use(PrincipalResolution(identityPrincipalStore{}))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for _, tc := range []struct {
		header string
		user   string
	}{
		{header: "a", user: "1"},
		{header: "b", user: "2"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Header.Set("X-Test-User", tc.header)
		recorder := httptest.NewRecorder()
		r.ServeHTTP(recorder, req)
	}

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("records = %d, want 2", len(lines))
	}
	var first, second map[string]any
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatal(err)
	}
	if first["user_id"] != "1" || second["user_id"] != "2" {
		t.Fatalf("user_id leaked across requests: %v / %v", first["user_id"], second["user_id"])
	}
}

// fakeWidgetCredential 实现 comment.WidgetCredential 接口的测试替身。
type fakeWidgetCredential struct {
	userID int64
	siteID int64
	epoch  int64
}

func (f fakeWidgetCredential) UserID() int64        { return f.userID }
func (f fakeWidgetCredential) SiteID() int64        { return f.siteID }
func (f fakeWidgetCredential) Epoch() int64         { return f.epoch }
func (f fakeWidgetCredential) ExpiresAt() time.Time { return time.Now().Add(time.Hour) }

type fakeWidgetVerifier struct {
	cred comment.WidgetCredential
	err  error
}

func (f fakeWidgetVerifier) Verify(ctx context.Context, raw string) (comment.WidgetCredential, error) {
	return f.cred, f.err
}

type fakeWidgetSettings struct {
	mode  string
	epoch int64
	err   error
}

func (f fakeWidgetSettings) WidgetConfig(ctx context.Context) (string, int64, error) {
	return f.mode, f.epoch, f.err
}

// TestWidgetPrincipalResolutionAppendsUserAndSiteID 验证 widget 凭据解析成功后，
// user_id 与 site_id 被追加到请求 context。
func TestWidgetPrincipalResolutionAppendsUserAndSiteID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)

	r := gin.New()
	r.Use(httpx.RequestID())
	r.Use(httpx.AccessLog(logger))
	r.Use(WidgetPrincipalResolution(
		fakeWidgetVerifier{cred: fakeWidgetCredential{userID: 5, siteID: 3, epoch: 1}},
		fakeWidgetSettings{mode: domain.CommentModeAuthenticated, epoch: 1},
		fakePrincipalStore{principal: domain.Principal{UserID: 5, Role: domain.RoleUser, Status: domain.UserStatusActive}},
	))
	r.GET("/widget/:site_id", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := httptest.NewRequest(http.MethodGet, "/widget/3", nil)
	req.AddCookie(&http.Cookie{Name: WidgetCookieName, Value: "raw"})
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}

	record := decodeLog(t, &buf)
	if record["user_id"] != "5" || record["site_id"] != "3" {
		t.Fatalf("context IDs = %v/%v, want 5/3", record["user_id"], record["site_id"])
	}
}

// TestPrincipalResolutionSessionVersionMismatch 验证 JWT 会话代次与当前不一致时，
// 按陈旧会话处理：清除两枚 Cookie、不设置 principal、公开路由继续以匿名执行。
func TestPrincipalResolutionSessionVersionMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)

	r := gin.New()
	r.Use(httpx.RequestID())
	r.Use(httpx.AccessLog(logger))
	r.Use(func(c *gin.Context) {
		c.Set(claimsKey, &tokenclaims.Claims{SessionVersion: 1, RegisteredClaims: gojwt.RegisteredClaims{Subject: "7"}})
		c.Next()
	})
	r.Use(PrincipalResolution(fakePrincipalStore{principal: domain.Principal{UserID: 7, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 2}}))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (public handler must not be blocked)", recorder.Code)
	}
	record := decodeLog(t, &buf)
	if _, ok := record["user_id"]; ok {
		t.Fatalf("stale session must not carry user_id, got %v", record["user_id"])
	}
	assertStaleCookiesCleared(t, recorder)
}

// TestPrincipalResolutionSessionVersionMissing 验证缺少会话代次的旧格式 JWT
// 按陈旧会话处理：清除 Cookie 并以匿名继续。
func TestPrincipalResolutionSessionVersionMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logging.NewWithFormat(&buf, logging.FormatJSON)

	r := gin.New()
	r.Use(httpx.RequestID())
	r.Use(httpx.AccessLog(logger))
	r.Use(func(c *gin.Context) {
		c.Set(claimsKey, &tokenclaims.Claims{RegisteredClaims: gojwt.RegisteredClaims{Subject: "7"}})
		c.Next()
	})
	r.Use(PrincipalResolution(fakePrincipalStore{principal: domain.Principal{UserID: 7, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 1}}))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (public handler must not be blocked)", recorder.Code)
	}
	record := decodeLog(t, &buf)
	if _, ok := record["user_id"]; ok {
		t.Fatalf("legacy session must not carry user_id, got %v", record["user_id"])
	}
	assertStaleCookiesCleared(t, recorder)
}

// TestPrincipalResolutionSessionVersionNonPositive 验证非正会话代次按陈旧会话处理。
func TestPrincipalResolutionSessionVersionNonPositive(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(claimsKey, &tokenclaims.Claims{SessionVersion: -1, RegisteredClaims: gojwt.RegisteredClaims{Subject: "7"}})
		c.Next()
	})
	r.Use(PrincipalResolution(fakePrincipalStore{principal: domain.Principal{UserID: 7, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 1}}))
	r.GET("/protected", RequireUser(fakeRequireUserGate{}), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	assertStaleCookiesCleared(t, recorder)
}

// TestPrincipalResolutionSessionVersionMatch 验证代次一致时 principal 正常注入。
func TestPrincipalResolutionSessionVersionMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(claimsKey, &tokenclaims.Claims{SessionVersion: 3, RegisteredClaims: gojwt.RegisteredClaims{Subject: "7"}})
		c.Next()
	})
	r.Use(PrincipalResolution(fakePrincipalStore{principal: domain.Principal{UserID: 7, Role: domain.RoleUser, Status: domain.UserStatusActive, SessionVersion: 3}}))
	r.GET("/protected", RequireUser(fakeRequireUserGate{}), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", recorder.Code, recorder.Body.String())
	}
}

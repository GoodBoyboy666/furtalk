package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/setting"

	"github.com/gin-gonic/gin"
)

func useFixedSpamKeywordFile(t *testing.T, content string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "configs", "spam", "keywords.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixed keyword directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixed keyword file: %v", err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
}

// newSettingsTestRouter 构建挂载设置路由的测试引擎，provider 服务可传 nil。
func newSettingsTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	router, _ := newSettingsTestRouterWithProviders(t)
	return router
}

// newSettingsTestRouterWithProviders 构建设置路由测试引擎并返回 provider 服务，
// 供测试注入通知通道 tester。
func newSettingsTestRouterWithProviders(t *testing.T) (*gin.Engine, *setting.ProviderService) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "handler-settings.db")
	db, err := database.Connect(database.Config{Dialect: "sqlite", Path: dsn})
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, cerr := db.DB(); cerr == nil {
			_ = sqlDB.Close()
		}
	})
	if err := database.AutoMigrate(db, &model.DynamicSetting{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	svc := setting.NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	providers := setting.NewProviderService(gormtx.NewRunner(db), repository.NewSettingsRepo(db), []byte("test-master-key-0123456789abcdef"))
	svc.SetCaptchaValidator(providers)
	providers.SetSettingsInvalidator(svc.Invalidate)
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("new translator: %v", err)
	}
	router := gin.New()
	router.Use(httpx.ErrorWriter(translator))
	RegisterAdminSettings(router.Group("/api/v1/admin"), svc, providers)
	RegisterPublicConfig(router.Group("/api/v1"), svc)
	return router, providers
}

func TestPublicConfigIsAllowlistedAndNoStore(t *testing.T) {
	router := newSettingsTestRouter(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /config = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", recorder.Header().Get("Cache-Control"))
	}
	body := recorder.Body.String()
	for _, forbidden := range []string{"captcha_policy", "provider", "credential_epoch", "settings"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("public config leaked %q: %s", forbidden, body)
		}
	}
	var response PublicConfigResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode public config: %v", err)
	}
	if response.LegalConsentVersion != 1 || response.BrandPrimaryColor != "#18181B" {
		t.Fatalf("default public config = %+v", response)
	}
}

func TestPublicConfigAndLegalConsentReset(t *testing.T) {
	router := newSettingsTestRouter(t)
	patch := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/settings", strings.NewReader(
		`{"settings":[{"key":"user_agreement_url","type":"string","value":"https://example.com/terms"},{"key":"brand_primary_color","type":"string","value":"#6750a4"}]}`))
	patch.Header.Set("Content-Type", "application/json")
	patchRecorder := httptest.NewRecorder()
	router.ServeHTTP(patchRecorder, patch)
	if patchRecorder.Code != http.StatusOK {
		t.Fatalf("patch = %d, body=%s", patchRecorder.Code, patchRecorder.Body.String())
	}
	get := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	getRecorder := httptest.NewRecorder()
	router.ServeHTTP(getRecorder, get)
	var before PublicConfigResponse
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &before); err != nil {
		t.Fatalf("decode before reset: %v", err)
	}
	if before.UserAgreementURL != "https://example.com/terms" || before.BrandPrimaryColor != "#6750A4" {
		t.Fatalf("public config after patch = %+v", before)
	}

	reset := httptest.NewRequest(http.MethodPost, "/api/v1/admin/settings/legal-consent/reset", nil)
	resetRecorder := httptest.NewRecorder()
	router.ServeHTTP(resetRecorder, reset)
	if resetRecorder.Code != http.StatusOK {
		t.Fatalf("reset = %d, body=%s", resetRecorder.Code, resetRecorder.Body.String())
	}
	var resetResponse LegalConsentResetResponse
	if err := json.Unmarshal(resetRecorder.Body.Bytes(), &resetResponse); err != nil {
		t.Fatalf("decode reset: %v", err)
	}
	if resetResponse.LegalConsentVersion != 2 {
		t.Fatalf("reset response = %+v, want version 2", resetResponse)
	}
	getRecorder = httptest.NewRecorder()
	router.ServeHTTP(getRecorder, get)
	var after PublicConfigResponse
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &after); err != nil {
		t.Fatalf("decode after reset: %v", err)
	}
	if after.LegalConsentVersion != 2 || after.UserAgreementURL != before.UserAgreementURL || after.BrandPrimaryColor != before.BrandPrimaryColor {
		t.Fatalf("reset changed public config = %+v", after)
	}
}

// TestSettingsRouteIsPatch 验证设置更新只接受 PATCH，旧 PUT 路由不存在。
func TestSettingsRouteIsPatch(t *testing.T) {
	router := newSettingsTestRouter(t)

	put := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", strings.NewReader(`{}`))
	put.Header.Set("Content-Type", "application/json")
	putRecorder := httptest.NewRecorder()
	router.ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusNotFound {
		t.Fatalf("PUT /admin/settings = %d, want 404", putRecorder.Code)
	}

	patch := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/settings", nil)
	patch.Header.Set("Content-Type", "application/json")
	patchRecorder := httptest.NewRecorder()
	router.ServeHTTP(patchRecorder, patch)
	if patchRecorder.Code != http.StatusBadRequest {
		t.Fatalf("PATCH with empty body = %d, want 400", patchRecorder.Code)
	}
}

// TestSettingsPatchAndGet 验证 PATCH 成功返回完整公开列表，GET 返回同一契约，
// 响应不含 version 与内部 epoch。
func TestSettingsPatchAndGet(t *testing.T) {
	router := newSettingsTestRouter(t)

	patch := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/settings",
		strings.NewReader(`{"settings":[{"key":"moderation","type":"string","value":"review"}]}`))
	patch.Header.Set("Content-Type", "application/json")
	patchRecorder := httptest.NewRecorder()
	router.ServeHTTP(patchRecorder, patch)
	if patchRecorder.Code != http.StatusOK {
		t.Fatalf("PATCH = %d, body=%s", patchRecorder.Code, patchRecorder.Body.String())
	}
	body := patchRecorder.Body.String()
	if strings.Contains(body, "version") || strings.Contains(body, "credential_epoch") {
		t.Fatalf("response must not contain version fields: %s", body)
	}
	if strings.Contains(body, "internal.widget_credential_epoch") {
		t.Fatalf("response must not contain internal epoch: %s", body)
	}
	var resp SettingsResponse
	if err := json.Unmarshal(patchRecorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var moderation setting.SettingItem
	for _, item := range resp.Settings {
		if item.Key == "moderation" {
			moderation = item
		}
	}
	if moderation.Value != "review" {
		t.Fatalf("moderation = %+v, want review", moderation)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings", nil)
	getRecorder := httptest.NewRecorder()
	router.ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200", getRecorder.Code)
	}
	if !strings.Contains(getRecorder.Body.String(), `"moderation"`) {
		t.Fatalf("GET response misses moderation: %s", getRecorder.Body.String())
	}
}

// TestSettingsPatchRejectsInvalidBody 验证非法 PATCH 输入返回参数错误。
func TestSettingsPatchRejectsInvalidBody(t *testing.T) {
	router := newSettingsTestRouter(t)

	cases := []string{
		`{"settings":[]}`,
		`{"settings":[{"key":"internal.widget_credential_epoch","type":"integer","value":1}]}`,
		`{"settings":[{"key":"comment_mode","type":"integer","value":1}]}`,
		`{"settings":[{"key":"moderation","type":"string","value":null}]}`,
	}
	for _, payload := range cases {
		request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/settings", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("PATCH %s = %d, want 422; body=%s", payload, recorder.Code, recorder.Body.String())
		}
	}
}

// TestAdminProviderCaptchaUpsertOmitsEnabled 验证 CAPTCHA provider 的 upsert 不接受
// enabled 字段；携带 enabled 时返回 422 且不落库。
func TestAdminProviderCaptchaUpsertOmitsEnabled(t *testing.T) {
	router := newSettingsTestRouter(t)

	ok := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/cap", strings.NewReader(
		`{"kind":"captcha","config":{"provider":"cap","site_key":"s","secret_key":"sec","endpoint":"https://cap.example.com"}}`))
	ok.Header.Set("Content-Type", "application/json")
	okRecorder := httptest.NewRecorder()
	router.ServeHTTP(okRecorder, ok)
	if okRecorder.Code != http.StatusNoContent {
		t.Fatalf("captcha upsert without enabled = %d, want 204; body=%s", okRecorder.Code, okRecorder.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/cap", strings.NewReader(
		`{"kind":"captcha","enabled":true,"config":{"provider":"cap","site_key":"s","secret_key":"sec","endpoint":"https://cap.example.com"}}`))
	bad.Header.Set("Content-Type", "application/json")
	badRecorder := httptest.NewRecorder()
	router.ServeHTTP(badRecorder, bad)
	if badRecorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("captcha upsert with enabled = %d, want 422; body=%s", badRecorder.Code, badRecorder.Body.String())
	}

	// 拒绝的写入不得落库：列表只剩 cap。
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var resp ProvidersResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Providers) != 1 || resp.Providers[0].ProviderKey != "cap" {
		t.Fatalf("providers = %+v, want only cap", resp.Providers)
	}
}

// TestAdminProviderListKindSpecificEnabled 验证列表对 CAPTCHA 省略 enabled，
// 对 OAuth/OIDC 保留 enabled。
func TestAdminProviderListKindSpecificEnabled(t *testing.T) {
	router := newSettingsTestRouter(t)

	put := func(path, payload string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, path, strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("PUT %s = %d, want 204; body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
	put("/api/v1/admin/providers/cap", `{"kind":"captcha","config":{"provider":"cap","site_key":"s","secret_key":"sec","endpoint":"https://cap.example.com"}}`)
	put("/api/v1/admin/providers/github", `{"kind":"oauth","enabled":true,"config":{"client_id":"c","client_secret":"cs"}}`)
	put("/api/v1/admin/providers/google", `{"kind":"oidc","config":{"client_id":"c","client_secret":"cs"}}`)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", recorder.Code)
	}
	var resp ProvidersResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Providers) != 3 {
		t.Fatalf("provider count = %d, want 3; body=%s", len(resp.Providers), recorder.Body.String())
	}
	for _, p := range resp.Providers {
		switch p.ProviderKey {
		case "cap":
			if p.Kind != "captcha" {
				t.Fatalf("cap kind = %q, want captcha", p.Kind)
			}
			if p.Enabled != nil {
				t.Fatalf("captcha item must omit enabled: %+v", p)
			}
		case "github":
			if p.Enabled == nil || *p.Enabled != true {
				t.Fatalf("github enabled = %+v, want true", p.Enabled)
			}
		case "google":
			if p.Enabled == nil || *p.Enabled != false {
				t.Fatalf("google enabled = %+v, want false", p.Enabled)
			}
		default:
			t.Fatalf("unexpected provider %q", p.ProviderKey)
		}
	}
}

// TestAdminProviderSpamRequiresEnabled 验证 spam provider 必须携带 enabled，缺失返回 422。
func TestAdminProviderSpamRequiresEnabled(t *testing.T) {
	router := newSettingsTestRouter(t)

	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/spam.local", strings.NewReader(
		`{"kind":"spam","config":{"action":"pending"}}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("spam upsert without enabled = %d, want 422; body=%s", recorder.Code, recorder.Body.String())
	}
}

// TestAdminProviderSpamLocalRoundTrip 验证本地词库渠道可保存、列表返回 configured/enabled，
// 且响应不含机密或正文。
func TestAdminProviderSpamLocalRoundTrip(t *testing.T) {
	useFixedSpamKeywordFile(t, "广告\n")
	router := newSettingsTestRouter(t)

	payload := `{"kind":"spam","enabled":true,"config":{"check_nickname":true,"action":"pending"}}`
	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/spam.local", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("spam.local upsert = %d, want 204; body=%s", recorder.Code, recorder.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers", nil)
	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, list)
	var resp ProvidersResponse
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Providers) != 1 {
		t.Fatalf("providers = %+v, want 1", resp.Providers)
	}
	p := resp.Providers[0]
	if p.Kind != "spam" || !p.Configured || p.Enabled == nil || !*p.Enabled {
		t.Fatalf("spam.local meta = %+v, want spam/configured/enabled", p)
	}
	if listRecorder.Body.String() != "" {
		if strings.Contains(listRecorder.Body.String(), "check_nickname") && !strings.Contains(listRecorder.Body.String(), "pending") {
			t.Fatalf("list must not expose secrets; body=%s", listRecorder.Body.String())
		}
	}
}

// TestAdminProviderSpamSecretSafe 验证 Akismet 保存后列表不回显 secret，
// 未配置 Secret 的启用被拒绝。
func TestAdminProviderSpamSecretSafe(t *testing.T) {
	router := newSettingsTestRouter(t)

	put := func(payload string) int {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/spam.akismet", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder.Code
	}
	if code := put(`{"kind":"spam","enabled":true,"config":{"action":"spam"}}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("enable akismet without secret = %d, want 422", code)
	}
	if code := put(`{"kind":"spam","enabled":true,"config":{"action":"spam","api_key":"ak-secret"}}`); code != http.StatusNoContent {
		t.Fatalf("upsert akismet = %d, want 204", code)
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers", nil)
	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, list)
	if strings.Contains(listRecorder.Body.String(), "ak-secret") {
		t.Fatalf("list leaks secret: %s", listRecorder.Body.String())
	}
	var resp ProvidersResponse
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Providers) != 1 || resp.Providers[0].ProviderKey != "spam.akismet" {
		t.Fatalf("providers = %+v, want only spam.akismet", resp.Providers)
	}
}

// TestAdminProviderSpamUnknownKey 验证未知 spam key 被拒绝。
func TestAdminProviderSpamUnknownKey(t *testing.T) {
	router := newSettingsTestRouter(t)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/spam.bogus", strings.NewReader(
		`{"kind":"spam","enabled":true,"config":{"action":"spam"}}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown spam key = %d, want 422; body=%s", recorder.Code, recorder.Body.String())
	}
}

// fakeNotificationTester 记录测试调用并返回可配置错误。
type fakeNotificationTester struct {
	called bool
	err    error
}

func (f *fakeNotificationTester) TestNotification(context.Context, string, setting.NotificationConfig) error {
	f.called = true
	return f.err
}

// TestAdminProviderNotificationRequiresEnabled 验证通知通道 upsert 必须携带 enabled。
func TestAdminProviderNotificationRequiresEnabled(t *testing.T) {
	router := newSettingsTestRouter(t)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/notification.telegram", strings.NewReader(
		`{"kind":"notification","config":{"bot_token":"t","chat_id":"1"}}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("notification upsert without enabled = %d, want 422; body=%s", recorder.Code, recorder.Body.String())
	}
}

// TestAdminProviderNotificationRoundTrip 验证通知通道可保存、列表返回
// kind/enabled/configured 且不回显机密。
func TestAdminProviderNotificationRoundTrip(t *testing.T) {
	router := newSettingsTestRouter(t)
	put := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/notification.telegram", strings.NewReader(
		`{"kind":"notification","enabled":true,"config":{"bot_token":"bot-secret-xyz","chat_id":"123"}}`))
	put.Header.Set("Content-Type", "application/json")
	putRecorder := httptest.NewRecorder()
	router.ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusNoContent {
		t.Fatalf("telegram upsert = %d, want 204; body=%s", putRecorder.Code, putRecorder.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers", nil)
	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, list)
	if strings.Contains(listRecorder.Body.String(), "bot-secret-xyz") {
		t.Fatalf("list leaks secret: %s", listRecorder.Body.String())
	}
	var resp ProvidersResponse
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	var found *ProviderMetadata
	for i := range resp.Providers {
		if resp.Providers[i].ProviderKey == "notification.telegram" {
			found = &resp.Providers[i]
		}
	}
	if found == nil {
		t.Fatalf("notification.telegram missing from %+v", resp.Providers)
	}
	if found.Kind != "notification" || found.Enabled == nil || !*found.Enabled || !found.Configured {
		t.Fatalf("telegram meta = %+v, want notification/configured/enabled", found)
	}
}

// TestAdminProviderNotificationBarkPublicMeta 验证 Bark 列表仅返回公开 server_url，
// 绝不回显 device_key。
func TestAdminProviderNotificationBarkPublicMeta(t *testing.T) {
	router := newSettingsTestRouter(t)
	put := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/notification.bark", strings.NewReader(
		`{"kind":"notification","enabled":true,"config":{"server_url":"https://api.day.app","device_key":"device-secret-xyz"}}`))
	put.Header.Set("Content-Type", "application/json")
	putRecorder := httptest.NewRecorder()
	router.ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusNoContent {
		t.Fatalf("bark upsert = %d, want 204; body=%s", putRecorder.Code, putRecorder.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers", nil)
	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, list)
	body := listRecorder.Body.String()
	if strings.Contains(body, "device-secret-xyz") {
		t.Fatalf("list leaks device key: %s", body)
	}
	if !strings.Contains(body, "https://api.day.app") {
		t.Fatalf("list should expose public server_url: %s", body)
	}
}

// TestAdminProviderNotificationDelete 验证通知通道可删除。
func TestAdminProviderNotificationDelete(t *testing.T) {
	router := newSettingsTestRouter(t)
	put := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/notification.webhook", strings.NewReader(
		`{"kind":"notification","enabled":false,"config":{"webhook_url":"http://127.0.0.1:9000/hook"}}`))
	put.Header.Set("Content-Type", "application/json")
	putRecorder := httptest.NewRecorder()
	router.ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusNoContent {
		t.Fatalf("webhook upsert = %d, want 204; body=%s", putRecorder.Code, putRecorder.Body.String())
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/providers/notification.webhook", nil)
	delRecorder := httptest.NewRecorder()
	router.ServeHTTP(delRecorder, del)
	if delRecorder.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", delRecorder.Code)
	}
	list := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers", nil)
	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, list)
	if strings.Contains(listRecorder.Body.String(), "notification.webhook") {
		t.Fatalf("deleted provider still listed: %s", listRecorder.Body.String())
	}
}

// TestAdminProviderNotificationTest 验证测试端点实际调用 tester。
func TestAdminProviderNotificationTest(t *testing.T) {
	router, providers := newSettingsTestRouterWithProviders(t)
	tester := &fakeNotificationTester{}
	providers.SetNotificationTester(tester)

	// 保存停用的通道后仍可测试。
	put := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/notification.telegram", strings.NewReader(
		`{"kind":"notification","enabled":false,"config":{"bot_token":"t","chat_id":"1"}}`))
	put.Header.Set("Content-Type", "application/json")
	putRecorder := httptest.NewRecorder()
	router.ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusNoContent {
		t.Fatalf("upsert = %d, want 204", putRecorder.Code)
	}

	test := httptest.NewRequest(http.MethodPost, "/api/v1/admin/providers/notification.telegram/test", nil)
	testRecorder := httptest.NewRecorder()
	router.ServeHTTP(testRecorder, test)
	if testRecorder.Code != http.StatusOK {
		t.Fatalf("test = %d, want 200; body=%s", testRecorder.Code, testRecorder.Body.String())
	}
	if !tester.called {
		t.Fatal("tester was not called")
	}
}

// TestAdminProviderNotificationTestUnavailable 验证未接线 tester 时测试端点返回 503。
func TestAdminProviderNotificationTestUnavailable(t *testing.T) {
	router, _ := newSettingsTestRouterWithProviders(t)
	put := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/notification.telegram", strings.NewReader(
		`{"kind":"notification","enabled":false,"config":{"bot_token":"t","chat_id":"1"}}`))
	put.Header.Set("Content-Type", "application/json")
	putRecorder := httptest.NewRecorder()
	router.ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusNoContent {
		t.Fatalf("upsert = %d, want 204", putRecorder.Code)
	}
	test := httptest.NewRequest(http.MethodPost, "/api/v1/admin/providers/notification.telegram/test", nil)
	testRecorder := httptest.NewRecorder()
	router.ServeHTTP(testRecorder, test)
	if testRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("test without tester = %d, want 503; body=%s", testRecorder.Code, testRecorder.Body.String())
	}
}

// TestAdminProviderNotificationInvalidURL 验证非法 webhook 地址 upsert 返回 422。
func TestAdminProviderNotificationInvalidURL(t *testing.T) {
	router := newSettingsTestRouter(t)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/notification.slack", strings.NewReader(
		`{"kind":"notification","enabled":true,"config":{"webhook_url":"https://evil.com/services/T/B/X"}}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid slack url = %d, want 422; body=%s", recorder.Code, recorder.Body.String())
	}
}

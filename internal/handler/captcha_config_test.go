package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// newCaptchaConfigTestRouter 构建挂载管理设置/提供商与公共 CAPTCHA 配置端点的测试引擎。
func newCaptchaConfigTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dsn := filepath.Join(t.TempDir(), "handler-captcha-config.db")
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
	admin := router.Group("/api/v1/admin")
	RegisterAdminSettings(admin, svc, providers)
	RegisterCaptchaConfig(router.Group("/api/v1"), setting.NewCaptchaConfigService(svc, providers))
	return router
}

// getJSON 向 path 发起 GET 请求。
func getJSON(router *gin.Engine, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

// TestCaptchaConfigDisabledReturnsRequiredFalse 验证策略关闭时返回 required=false 且无 provider 读取。
func TestCaptchaConfigDisabledReturnsRequiredFalse(t *testing.T) {
	router := newCaptchaConfigTestRouter(t)

	rec := getJSON(router, "/api/v1/captcha/config?action=password_login")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var resp CaptchaConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Required {
		t.Fatalf("required = true, want false")
	}
	if resp.Captcha != nil {
		t.Fatalf("captcha object present for disabled action: %+v", resp.Captcha)
	}
}

// TestCaptchaConfigActionValidation 验证 action 缺失时返回 422。
func TestCaptchaConfigActionValidation(t *testing.T) {
	router := newCaptchaConfigTestRouter(t)

	for _, path := range []string{"/api/v1/captcha/config", "/api/v1/captcha/config?action="} {
		rec := getJSON(router, path)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s status = %d, want 422; body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

// TestCaptchaConfigEnabledSecretFree 验证策略开启且 CAP 配置完成后，响应含公开字段且不含机密。
func TestCaptchaConfigEnabledSecretFree(t *testing.T) {
	router := newCaptchaConfigTestRouter(t)
	enableCaptchaConfig(t, router, "cap", "cap-site", "cap-secret", "https://cap.example.com")

	rec := getJSON(router, "/api/v1/captcha/config?action=password_login")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "cap-secret") || strings.Contains(body, "secret") {
		t.Fatalf("response leaked a secret: %s", body)
	}
	var resp CaptchaConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Required || resp.Captcha == nil {
		t.Fatalf("response = %+v, want required + captcha", resp)
	}
	if resp.Captcha.Provider != "cap" || resp.Captcha.SiteKey != "cap-site" {
		t.Fatalf("captcha projection mismatch: %+v", resp.Captcha)
	}
	if resp.Captcha.APIEndpoint != "https://cap.example.com/cap-site/" {
		t.Fatalf("api_endpoint = %q, want widget endpoint", resp.Captcha.APIEndpoint)
	}
}

// TestCaptchaConfigNonCAPNoEndpoint 验证非 CAP 提供方响应不含 api_endpoint。
func TestCaptchaConfigNonCAPNoEndpoint(t *testing.T) {
	router := newCaptchaConfigTestRouter(t)
	enableCaptchaConfig(t, router, "recaptcha", "rc-site", "rc-secret", "")

	rec := getJSON(router, "/api/v1/captcha/config?action=password_login")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "api_endpoint") {
		t.Fatalf("recaptcha response must omit api_endpoint: %s", rec.Body.String())
	}
	var resp CaptchaConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Captcha == nil || resp.Captcha.Provider != "recaptcha" || resp.Captcha.SiteKey != "rc-site" {
		t.Fatalf("captcha projection mismatch: %+v", resp.Captcha)
	}
}

// TestCaptchaConfigEnabledProviderUnavailable 验证策略开启但 provider 未配置时返回 503。
func TestCaptchaConfigEnabledProviderUnavailable(t *testing.T) {
	router := newCaptchaConfigTestRouter(t)
	enableCaptchaPolicy(t, router)

	rec := getJSON(router, "/api/v1/captcha/config?action=password_login")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

// enableCaptchaConfig 先配置并选择 CAPTCHA provider，再开启 password_login 策略。
func enableCaptchaConfig(t *testing.T, router *gin.Engine, provider, siteKey, secretKey, endpoint string) {
	t.Helper()
	setupProvider(router, provider, siteKey, secretKey, endpoint)
	selectCaptchaProvider(router, provider)
	enableCaptchaPolicy(t, router)
}

// setupProvider 通过管理端点配置 CAPTCHA provider（不携带 enabled）；
// provider key 必须等于 provider 类型。
func setupProvider(router *gin.Engine, provider, siteKey, secretKey, endpoint string) {
	config := map[string]any{"provider": provider, "site_key": siteKey, "secret_key": secretKey}
	if endpoint != "" {
		config["endpoint"] = endpoint
	}
	conf, err := json.Marshal(config)
	if err != nil {
		panic(err)
	}
	payload := `{"kind":"captcha","config":` + string(conf) + `}`
	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/providers/"+provider,
		strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK && recorder.Code != http.StatusNoContent {
		panic("setup provider failed: " + recorder.Body.String())
	}
}

// selectCaptchaProvider 通过设置 PATCH 选择 CAPTCHA provider。
func selectCaptchaProvider(router *gin.Engine, providerKey string) {
	payload := `{"settings":[{"key":"captcha_provider","type":"string","value":"` + providerKey + `"}]}`
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/settings", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		panic("select captcha provider failed: " + recorder.Body.String())
	}
}

// enableCaptchaPolicy 通过设置 PATCH 开启 password_login 策略。
func enableCaptchaPolicy(t *testing.T, router *gin.Engine) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/settings",
		strings.NewReader(`{"settings":[{"key":"captcha_policy","type":"json","value":{"password_login":true}}]}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("enable captcha policy failed: %d %s", recorder.Code, recorder.Body.String())
	}
}

// TestCaptchaConfigResponseShape 验证响应 DTO 的 JSON 结构与 omitempty 行为。
func TestCaptchaConfigResponseShape(t *testing.T) {
	enabled := toCaptchaConfigResponse(&setting.PublicCaptchaConfig{
		Required:    true,
		Provider:    "cap",
		SiteKey:     "site-1",
		APIEndpoint: "https://cap.example.com/site-1/",
	})
	raw, err := json.Marshal(enabled)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"required":true`) {
		t.Fatalf("enabled response missing required=true: %s", raw)
	}
	if !strings.Contains(string(raw), `"api_endpoint":"https://cap.example.com/site-1/"`) {
		t.Fatalf("enabled response missing api_endpoint: %s", raw)
	}
	if strings.Contains(string(raw), "secret") {
		t.Fatalf("response leaked a secret: %s", raw)
	}

	disabled := toCaptchaConfigResponse(&setting.PublicCaptchaConfig{Required: false})
	raw2, err := json.Marshal(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw2), "captcha") {
		t.Fatalf("disabled response must omit captcha object: %s", raw2)
	}
	if !strings.Contains(string(raw2), `"required":false`) {
		t.Fatalf("disabled response missing required=false: %s", raw2)
	}

	recaptcha := toCaptchaConfigResponse(&setting.PublicCaptchaConfig{
		Required: true,
		Provider: "recaptcha",
		SiteKey:  "rk",
	})
	raw3, _ := json.Marshal(recaptcha)
	if strings.Contains(string(raw3), "api_endpoint") {
		t.Fatalf("recaptcha response must omit api_endpoint: %s", raw3)
	}
	if !strings.Contains(string(raw3), `"provider":"recaptcha"`) {
		t.Fatalf("recaptcha response missing provider: %s", raw3)
	}
}

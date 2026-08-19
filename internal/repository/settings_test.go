package repository

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// newSettingsTestDB 打开临时 SQLite 数据库并迁移动态设置表。
func newSettingsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "settings-test.db")
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
	return db
}

// TestSettingsSeedMissing 验证缺失默认项被播种,已存在的 key 不被覆盖。
func TestSettingsSeedMissing(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	first := []DynamicSettingRow{{
		Key: "comment_mode", Type: "string", Value: []byte(`"anonymous"`), UpdatedBy: 0,
	}}
	if err := repo.SeedMissing(ctx, first); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	second := []DynamicSettingRow{{
		Key: "comment_mode", Type: "string", Value: []byte(`"authenticated"`), UpdatedBy: 0,
	}}
	if err := repo.SeedMissing(ctx, second); err != nil {
		t.Fatalf("seed second: %v", err)
	}

	rows, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("row count = %d, want 1", len(rows))
	}
	if string(rows[0].Value) != `"anonymous"` {
		t.Fatalf("value = %s, want %q (existing key must not be overwritten)", rows[0].Value, `"anonymous"`)
	}
}

// TestSettingsUpsertOverwritesSameKey 验证同 key 再次写入覆盖旧值且不产生新行。
func TestSettingsUpsertOverwritesSameKey(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	first := []DynamicSettingRow{{
		Key: "max_reply_depth", Type: "integer", Value: []byte(`3`), UpdatedBy: 1,
	}}
	if err := repo.Upsert(ctx, first); err != nil {
		t.Fatalf("upsert first: %v", err)
	}
	second := []DynamicSettingRow{{
		Key: "max_reply_depth", Type: "integer", Value: []byte(`5`), UpdatedBy: 2,
	}}
	if err := repo.Upsert(ctx, second); err != nil {
		t.Fatalf("upsert second: %v", err)
	}

	rows, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("row count = %d, want 1", len(rows))
	}
	if string(rows[0].Value) != `5` {
		t.Fatalf("value = %s, want 5", rows[0].Value)
	}
	if rows[0].UpdatedBy != 2 {
		t.Fatalf("updated_by = %d, want 2", rows[0].UpdatedBy)
	}
}

// TestSettingsBatchAtomicity 验证同事务批次内任一项失败时,整批都不落库。
func TestSettingsBatchAtomicity(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	runner := gormtx.NewRunner(db)
	ctx := context.Background()

	err := runner.RunInTx(ctx, func(ctx context.Context) error {
		if err := repo.Upsert(ctx, []DynamicSettingRow{{
			Key: "moderation", Type: "string", Value: []byte(`"review"`), UpdatedBy: 1,
		}}); err != nil {
			return err
		}
		// 非法 type 触发 CHECK 约束,批次必须整体失败。
		return repo.Upsert(ctx, []DynamicSettingRow{{
			Key: "broken", Type: "nope", Value: []byte(`1`), UpdatedBy: 1,
		}})
	})
	if err == nil {
		t.Fatal("batch with invalid type must fail")
	}

	rows, listErr := repo.List(ctx)
	if listErr != nil {
		t.Fatalf("list: %v", listErr)
	}
	if len(rows) != 0 {
		t.Fatalf("row count = %d, want 0 (batch must roll back entirely)", len(rows))
	}
}

// TestSettingsInternalEpochRow 验证内部 epoch 行可播种、覆盖且包含在 List 结果中。
func TestSettingsInternalEpochRow(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	epoch := []DynamicSettingRow{{
		Key: "internal.widget_credential_epoch", Type: "integer", Value: []byte(`0`), UpdatedBy: 0,
	}}
	if err := repo.SeedMissing(ctx, epoch); err != nil {
		t.Fatalf("seed epoch: %v", err)
	}
	if err := repo.Upsert(ctx, []DynamicSettingRow{{
		Key: "internal.widget_credential_epoch", Type: "integer", Value: []byte(`7`), UpdatedBy: 0,
	}}); err != nil {
		t.Fatalf("upsert epoch: %v", err)
	}

	rows, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("row count = %d, want 1", len(rows))
	}
	if rows[0].Key != "internal.widget_credential_epoch" || string(rows[0].Value) != `7` {
		t.Fatalf("epoch row = %+v, want internal key with value 7", rows[0])
	}
}

// TestSettingsCaptchaProviderRoundTrip 验证 CAPTCHA provider 以 <key>_provider 的 JSON
// 动态设置行保存，upsert/get/list/delete 均只访问该行且无 enabled 语义。
func TestSettingsCaptchaProviderRoundTrip(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	if err := repo.UpsertCaptchaProvider(ctx, &CaptchaProviderRow{
		ProviderKey:      "cap-main",
		PublicConfig:     []byte(`{"provider":"cap","site_key":"site-1","endpoint":"https://cap.example.com"}`),
		SecretKeyVersion: 1,
		SecretNonce:      []byte("0123456789ab"),
		SecretCiphertext: []byte{1, 2, 3, 4},
	}); err != nil {
		t.Fatalf("upsert captcha provider: %v", err)
	}

	rows, err := repo.ListCaptchaProviders(ctx)
	if err != nil {
		t.Fatalf("list captcha providers: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("captcha provider row count = %d, want 1", len(rows))
	}
	if rows[0].ProviderKey != "cap-main" {
		t.Fatalf("provider key mismatch: %+v", rows[0])
	}
	if string(rows[0].PublicConfig) != `{"provider":"cap","site_key":"site-1","endpoint":"https://cap.example.com"}` {
		t.Fatalf("public config mismatch: %s", rows[0].PublicConfig)
	}
	if rows[0].SecretKeyVersion != 1 || string(rows[0].SecretNonce) != "0123456789ab" ||
		string(rows[0].SecretCiphertext) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("secret envelope mismatch: %+v", rows[0])
	}

	got, err := repo.GetCaptchaProvider(ctx, "cap-main")
	if err != nil {
		t.Fatalf("get captcha provider: %v", err)
	}
	if got.ProviderKey != "cap-main" {
		t.Fatalf("get mismatch: %+v", got)
	}
	if _, err := repo.GetCaptchaProvider(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get missing error = %v, want ErrNotFound", err)
	}

	if err := repo.DeleteCaptchaProvider(ctx, "cap-main"); err != nil {
		t.Fatalf("delete captcha provider: %v", err)
	}
	if _, err := repo.GetCaptchaProvider(ctx, "cap-main"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get after delete error = %v, want ErrNotFound", err)
	}
	if err := repo.DeleteCaptchaProvider(ctx, "cap-main"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing error = %v, want ErrNotFound", err)
	}
}

// TestSettingsAuthProviderRoundTrip 验证 OAuth/OIDC provider 保留 kind/enabled 语义。
func TestSettingsAuthProviderRoundTrip(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	if err := repo.UpsertAuthProvider(ctx, &AuthProviderRow{
		ProviderKey:      "github",
		Kind:             domain.ProviderKindOAuth,
		Enabled:          true,
		PublicConfig:     []byte(`{"client_id":"cid","auth_url":"https://a.example","token_url":"https://t.example"}`),
		SecretKeyVersion: 1,
		SecretNonce:      []byte("0123456789ab"),
		SecretCiphertext: []byte{1, 2, 3, 4},
	}); err != nil {
		t.Fatalf("upsert auth provider: %v", err)
	}

	rows, err := repo.ListAuthProviders(ctx)
	if err != nil {
		t.Fatalf("list auth providers: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("auth provider row count = %d, want 1", len(rows))
	}
	if rows[0].ProviderKey != "github" || rows[0].Kind != domain.ProviderKindOAuth || !rows[0].Enabled {
		t.Fatalf("auth provider row mismatch: %+v", rows[0])
	}

	got, err := repo.GetAuthProvider(ctx, "github")
	if err != nil {
		t.Fatalf("get auth provider: %v", err)
	}
	if got.ProviderKey != "github" || got.Kind != domain.ProviderKindOAuth {
		t.Fatalf("get mismatch: %+v", got)
	}
	if _, err := repo.GetAuthProvider(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get missing error = %v, want ErrNotFound", err)
	}

	if err := repo.DeleteAuthProvider(ctx, "github"); err != nil {
		t.Fatalf("delete auth provider: %v", err)
	}
	if _, err := repo.GetAuthProvider(ctx, "github"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get after delete error = %v, want ErrNotFound", err)
	}
}

// TestSettingsCaptchaRowStoredWithoutEnabled 验证 CAPTCHA provider 落为 type=json 的
// <provider>_provider 行，value 是 JSON 对象且不含 enabled 字段。
func TestSettingsCaptchaRowStoredWithoutEnabled(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	if err := repo.UpsertCaptchaProvider(ctx, &CaptchaProviderRow{
		ProviderKey:      "cap-main",
		PublicConfig:     []byte(`{"provider":"cap","site_key":"s"}`),
		SecretKeyVersion: 1,
		SecretNonce:      []byte("0123456789ab"),
		SecretCiphertext: []byte("zz"),
	}); err != nil {
		t.Fatalf("upsert captcha provider: %v", err)
	}

	var stored model.DynamicSetting
	if err := gormtx.DB(ctx, db).Where("key = ?", "cap-main_provider").First(&stored).Error; err != nil {
		t.Fatalf("query stored row: %v", err)
	}
	if stored.Type != "json" {
		t.Fatalf("stored type = %q, want json", stored.Type)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(stored.Value), &raw); err != nil {
		t.Fatalf("value is not a JSON object: %v", err)
	}
	if raw["kind"] != "captcha" {
		t.Fatalf("captcha discriminator = %v, want captcha: %s", raw["kind"], stored.Value)
	}
	if _, has := raw["enabled"]; has {
		t.Fatalf("captcha row must not contain enabled: %s", stored.Value)
	}
	if _, has := raw["public_config"]; !has {
		t.Fatalf("captcha row must keep public_config: %s", stored.Value)
	}
	if raw["secret_key_version"] != float64(1) {
		t.Fatalf("secret_key_version = %v, want 1", raw["secret_key_version"])
	}
}

// TestSettingsAuthRowStoredWithEnabled 验证 OAuth/OIDC 行保留 kind 与 enabled 字段。
func TestSettingsAuthRowStoredWithEnabled(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	if err := repo.UpsertAuthProvider(ctx, &AuthProviderRow{
		ProviderKey: "github",
		Kind:        domain.ProviderKindOAuth,
		Enabled:     false,
	}); err != nil {
		t.Fatalf("upsert auth provider: %v", err)
	}

	var stored model.DynamicSetting
	if err := gormtx.DB(ctx, db).Where("key = ?", "github_provider").First(&stored).Error; err != nil {
		t.Fatalf("query stored row: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(stored.Value), &raw); err != nil {
		t.Fatalf("value is not a JSON object: %v", err)
	}
	if raw["kind"] != "oauth" || raw["enabled"] != false {
		t.Fatalf("value mismatch: %s", stored.Value)
	}
	if _, has := raw["public_config"]; has {
		t.Fatalf("empty public config must be omitted: %s", stored.Value)
	}
	if raw["secret_key_version"] != float64(0) {
		t.Fatalf("secret_key_version = %v, want 0", raw["secret_key_version"])
	}
}

// TestSettingsProviderTypeSpecificLookup 验证类型化 get 只匹配对应类型；
// 对错误类型或缺失行都返回 ErrNotFound。
func TestSettingsProviderTypeSpecificLookup(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	if err := repo.UpsertAuthProvider(ctx, &AuthProviderRow{
		ProviderKey: "github", Kind: domain.ProviderKindOAuth, Enabled: true,
	}); err != nil {
		t.Fatalf("upsert auth provider: %v", err)
	}
	if err := repo.UpsertCaptchaProvider(ctx, &CaptchaProviderRow{
		ProviderKey:      "cap-main",
		PublicConfig:     []byte(`{"provider":"cap","site_key":"s"}`),
		SecretKeyVersion: 1, SecretNonce: []byte("n"), SecretCiphertext: []byte("c"),
	}); err != nil {
		t.Fatalf("upsert captcha provider: %v", err)
	}

	if _, err := repo.GetCaptchaProvider(ctx, "github"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get captcha on auth row = %v, want ErrNotFound", err)
	}
	if _, err := repo.GetAuthProvider(ctx, "cap-main"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get auth on captcha row = %v, want ErrNotFound", err)
	}
	if err := repo.DeleteCaptchaProvider(ctx, "github"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete captcha on auth row = %v, want ErrNotFound", err)
	}
	if err := repo.DeleteAuthProvider(ctx, "cap-main"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete auth on captcha row = %v, want ErrNotFound", err)
	}

	captchas, err := repo.ListCaptchaProviders(ctx)
	if err != nil {
		t.Fatalf("list captcha: %v", err)
	}
	if len(captchas) != 1 || captchas[0].ProviderKey != "cap-main" {
		t.Fatalf("captcha list = %+v, want only cap-main", captchas)
	}
	auths, err := repo.ListAuthProviders(ctx)
	if err != nil {
		t.Fatalf("list auth: %v", err)
	}
	if len(auths) != 1 || auths[0].ProviderKey != "github" {
		t.Fatalf("auth list = %+v, want only github", auths)
	}
}

// TestSettingsSelectorKeyIsNotProviderRow 验证 captcha_provider 是公开设置 key，
// 不进入 provider 列表，也不被 IsProviderSettingKey 判定为 provider 行。
func TestSettingsSelectorKeyIsNotProviderRow(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	if IsProviderSettingKey(CaptchaProviderSettingKey) {
		t.Fatalf("%q must be a public setting key, not a provider row", CaptchaProviderSettingKey)
	}
	if err := repo.Upsert(ctx, []DynamicSettingRow{{
		Key: CaptchaProviderSettingKey, Type: "string", Value: []byte(`"cap-main"`), UpdatedBy: 1,
	}}); err != nil {
		t.Fatalf("upsert selector: %v", err)
	}
	if err := repo.UpsertCaptchaProvider(ctx, &CaptchaProviderRow{
		ProviderKey: "cap-main", PublicConfig: []byte(`{"provider":"cap","site_key":"s"}`),
	}); err != nil {
		t.Fatalf("upsert captcha: %v", err)
	}

	captchas, err := repo.ListCaptchaProviders(ctx)
	if err != nil {
		t.Fatalf("list captcha: %v", err)
	}
	if len(captchas) != 1 || captchas[0].ProviderKey != "cap-main" {
		t.Fatalf("captcha list must ignore the selector row: %+v", captchas)
	}

	got, err := repo.Get(ctx, CaptchaProviderSettingKey)
	if err != nil {
		t.Fatalf("get selector: %v", err)
	}
	if string(got.Value) != `"cap-main"` {
		t.Fatalf("selector value = %s, want %q", got.Value, `"cap-main"`)
	}
	if _, err := repo.Get(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get missing error = %v, want ErrNotFound", err)
	}
}

// TestSettingsListProvidersSkipsNonProvider 验证列表只返回 _provider 后缀行，
// 普通设置行不进入 provider 列表。
func TestSettingsListProvidersSkipsNonProvider(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	if err := repo.SeedMissing(ctx, []DynamicSettingRow{{
		Key: "comment_mode", Type: "string", Value: []byte(`"anonymous"`), UpdatedBy: 0,
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := repo.UpsertAuthProvider(ctx, &AuthProviderRow{
		ProviderKey: "gh", Kind: domain.ProviderKindOAuth, Enabled: false,
	}); err != nil {
		t.Fatalf("upsert provider: %v", err)
	}

	rows, err := repo.ListAuthProviders(ctx)
	if err != nil {
		t.Fatalf("list providers: %v", err)
	}
	if len(rows) != 1 || rows[0].ProviderKey != "gh" {
		t.Fatalf("provider list = %+v, want only gh", rows)
	}
}

// TestSettingsLockRows 验证锁读取返回指定 key 的行,未指定 key 不返回。
func TestSettingsLockRows(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	seed := []DynamicSettingRow{
		{Key: "comment_mode", Type: "string", Value: []byte(`"anonymous"`), UpdatedBy: 0},
		{Key: "internal.widget_credential_epoch", Type: "integer", Value: []byte(`0`), UpdatedBy: 0},
	}
	if err := repo.SeedMissing(ctx, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	locked, err := repo.LockRows(ctx, []string{"comment_mode", "internal.widget_credential_epoch"})
	if err != nil {
		t.Fatalf("lock rows: %v", err)
	}
	if len(locked) != 2 {
		t.Fatalf("locked count = %d, want 2", len(locked))
	}
	for _, row := range locked {
		if row.Key != "comment_mode" && row.Key != "internal.widget_credential_epoch" {
			t.Fatalf("unexpected locked key %q", row.Key)
		}
	}
}

// TestSettingsPostgresSimpleProtocolBindsJSONAsString 验证仓储模型边界将 JSON 值作为 string 绑定，
// 防止 PostgreSQL 在 PreferSimpleProtocol 模式下将 []byte 推断为 bytea (\x...) 导致 SQLSTATE 22P02。
func TestSettingsPostgresSimpleProtocolBindsJSONAsString(t *testing.T) {
	row := DynamicSettingRow{
		Key:       "comment_mode",
		Type:      "string",
		Value:     []byte(`"anonymous"`),
		UpdatedBy: 0,
	}

	m := toDynamicSettingModel(row)
	if _, ok := any(m.Value).(string); !ok {
		t.Fatalf("toDynamicSettingModel must convert Value to Go string, got %T", m.Value)
	}
	if m.Value != `"anonymous"` {
		t.Fatalf("converted Value = %q, want %q", m.Value, `"anonymous"`)
	}

	// 验证 GORM Postgres PreferSimpleProtocol 下生成的变量绑定为 string 文本，绝非 []byte
	sqliteDB := newSettingsTestDB(t)
	sqlDB, err := sqliteDB.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}
	pgDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn:                 sqlDB,
		PreferSimpleProtocol: true,
		WithoutReturning:     false,
	}), &gorm.Config{
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("init postgres dry run db: %v", err)
	}

	stmt := pgDB.Create(&m).Statement
	foundValueVar := false
	for _, v := range stmt.Vars {
		if s, ok := v.(string); ok && s == `"anonymous"` {
			foundValueVar = true
		}
		if b, ok := v.([]byte); ok && string(b) == `"anonymous"` {
			t.Fatalf("GORM postgres statement bound JSON value as []byte (%v); PostgreSQL simple protocol encodes this as bytea (\\x...) causing 22P02", b)
		}
	}
	if !foundValueVar {
		t.Fatalf("expected string value \"anonymous\" in statement vars, got %v", stmt.Vars)
	}

	// 验证逆向转换 toDynamicSettingRow 把 string 正确转回 []byte
	back := toDynamicSettingRow(m)
	if string(back.Value) != `"anonymous"` {
		t.Fatalf("toDynamicSettingRow Value = %s, want %q", back.Value, `"anonymous"`)
	}
}

// TestSettingsAllJSONTypesRoundTrip 验证 string/integer/boolean/object/array 等合法 JSON 语义在
// 仓储播种、更新与读取往返后保持原始值不变。
func TestSettingsAllJSONTypesRoundTrip(t *testing.T) {
	db := newSettingsTestDB(t)
	repo := NewSettingsRepo(db)
	ctx := context.Background()

	testCases := []DynamicSettingRow{
		{Key: "str_setting", Type: "string", Value: []byte(`"hello world"`), UpdatedBy: 1},
		{Key: "int_setting", Type: "integer", Value: []byte(`42`), UpdatedBy: 1},
		{Key: "bool_setting", Type: "boolean", Value: []byte(`true`), UpdatedBy: 1},
		{Key: "bool_setting_false", Type: "boolean", Value: []byte(`false`), UpdatedBy: 1},
		{Key: "obj_setting", Type: "json", Value: []byte(`{"a":1,"b":"text","c":[true,false]}`), UpdatedBy: 1},
		{Key: "arr_setting", Type: "json", Value: []byte(`["item1",2,{"nested":true}]`), UpdatedBy: 1},
	}

	// 1. 播种
	if err := repo.SeedMissing(ctx, testCases); err != nil {
		t.Fatalf("seed all json types: %v", err)
	}

	// 2. 单个读取并校验
	for _, tc := range testCases {
		got, err := repo.Get(ctx, tc.Key)
		if err != nil {
			t.Fatalf("get %q: %v", tc.Key, err)
		}
		if string(got.Value) != string(tc.Value) {
			t.Fatalf("key %q value = %s, want %s", tc.Key, got.Value, tc.Value)
		}
		if got.Type != tc.Type {
			t.Fatalf("key %q type = %s, want %s", tc.Key, got.Type, tc.Type)
		}
	}

	// 3. 批量更新
	updatedCases := []DynamicSettingRow{
		{Key: "str_setting", Type: "string", Value: []byte(`"updated string"`), UpdatedBy: 2},
		{Key: "int_setting", Type: "integer", Value: []byte(`100`), UpdatedBy: 2},
		{Key: "bool_setting", Type: "boolean", Value: []byte(`false`), UpdatedBy: 2},
		{Key: "obj_setting", Type: "json", Value: []byte(`{"updated":true,"count":10}`), UpdatedBy: 2},
	}
	if err := repo.Upsert(ctx, updatedCases); err != nil {
		t.Fatalf("upsert all json types: %v", err)
	}

	for _, tc := range updatedCases {
		got, err := repo.Get(ctx, tc.Key)
		if err != nil {
			t.Fatalf("get updated %q: %v", tc.Key, err)
		}
		if string(got.Value) != string(tc.Value) {
			t.Fatalf("updated key %q value = %s, want %s", tc.Key, got.Value, tc.Value)
		}
		if got.UpdatedBy != 2 {
			t.Fatalf("updated key %q updated_by = %d, want 2", tc.Key, got.UpdatedBy)
		}
	}

	// 4. List 校验
	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list settings: %v", err)
	}
	if len(list) != len(testCases) {
		t.Fatalf("list count = %d, want %d", len(list), len(testCases))
	}
}

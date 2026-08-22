package setting

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"furtalk/internal/domain"
	"furtalk/internal/platform/database"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
)

// newTestServiceDB 打开临时 SQLite 数据库并构建设置服务，返回 db 供重建服务验证持久化。
func newTestServiceDB(t *testing.T) (*gorm.DB, *Service) {
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
	return db, NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
}

// newTestService 打开临时 SQLite 数据库并构建设置服务。
func newTestService(t *testing.T) *Service {
	t.Helper()
	_, svc := newTestServiceDB(t)
	return svc
}

// newTestServiceWithProviders 构建设置服务与提供商服务，互接选择校验与缓存失效回调。
func newTestServiceWithProviders(t *testing.T) (*gorm.DB, *Service, *ProviderService) {
	t.Helper()
	db, svc := newTestServiceDB(t)
	providers := NewProviderService(gormtx.NewRunner(db), repository.NewSettingsRepo(db), []byte("test-master-key-0123456789abcdef"))
	svc.SetCaptchaValidator(providers)
	providers.SetSettingsInvalidator(svc.Invalidate)
	return db, svc, providers
}

type afterCommitTxRunner struct {
	delegate    TxRunner
	afterCommit func()
}

func (r afterCommitTxRunner) RunInTx(ctx context.Context, fn func(context.Context) error) error {
	if err := r.delegate.RunInTx(ctx, fn); err != nil {
		return err
	}
	r.afterCommit()
	return nil
}

// TestGetSeedsDefaultsAndPersists 验证首次 Get 返回全部默认设置并已持久化。
func TestGetSeedsDefaultsAndPersists(t *testing.T) {
	db, svc := newTestServiceDB(t)
	ctx := context.Background()

	first, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if !reflect.DeepEqual(first.Settings, DefaultSettings()) {
		t.Fatalf("settings = %+v, want defaults %+v", first.Settings, DefaultSettings())
	}
	if first.Epoch != 0 {
		t.Fatalf("epoch = %d, want 0", first.Epoch)
	}

	// 默认项必须已持久化:重建空缓存服务后仍读到默认值。
	fresh := NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	second, err := fresh.Get(ctx)
	if err != nil {
		t.Fatalf("fresh get: %v", err)
	}
	if !reflect.DeepEqual(second.Settings, DefaultSettings()) {
		t.Fatalf("fresh settings = %+v, want defaults", second.Settings)
	}
}

// TestPatchValidationErrors 验证各类非法 PATCH 输入返回参数错误且无部分写入。
func TestPatchValidationErrors(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		items []SettingItem
	}{
		{name: "empty", items: []SettingItem{}},
		{name: "duplicate key", items: []SettingItem{
			{Key: SettingKeyModeration, Type: SettingTypeString, Value: "review"},
			{Key: SettingKeyModeration, Type: SettingTypeString, Value: "direct"},
		}},
		{name: "invalid key", items: []SettingItem{
			{Key: "UPPER_CASE", Type: SettingTypeString, Value: "x"},
		}},
		{name: "reserved key", items: []SettingItem{
			{Key: SettingKeyInternalEpoch, Type: SettingTypeInteger, Value: 1},
		}},
		{name: "null value", items: []SettingItem{
			{Key: SettingKeyCommentMode, Type: SettingTypeString, Value: nil},
		}},
		{name: "unsupported type", items: []SettingItem{
			{Key: "custom", Type: "float", Value: 1},
		}},
		{name: "known key type mismatch", items: []SettingItem{
			{Key: SettingKeyCommentMode, Type: SettingTypeInteger, Value: 1},
		}},
		{name: "scalar as json", items: []SettingItem{
			{Key: "custom", Type: SettingTypeJSON, Value: "text"},
		}},
		{name: "known invalid value", items: []SettingItem{
			{Key: SettingKeyModeration, Type: SettingTypeString, Value: "bogus"},
		}},
		{name: "known invalid comment sort", items: []SettingItem{
			{Key: SettingKeyCommentSort, Type: SettingTypeString, Value: "sideways"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Patch(ctx, tc.items, 1)
			if !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("Patch error = %v, want ErrValidation", err)
			}
			view, err := svc.Get(ctx)
			if err != nil {
				t.Fatalf("get after rejected patch: %v", err)
			}
			if !reflect.DeepEqual(view.Settings, DefaultSettings()) {
				t.Fatalf("settings after rejected patch = %+v, want defaults", view.Settings)
			}
		})
	}
}

// TestPatchBatchAtomicity 验证批次中已知设置非法值时整体失败，合法项也不写入。
func TestPatchBatchAtomicity(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	_, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyModeration, Type: SettingTypeString, Value: "review"},
		{Key: SettingKeyCommentMode, Type: SettingTypeString, Value: "bogus"},
	}, 1)
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Patch error = %v, want ErrValidation", err)
	}

	items, err := svc.PublicItems(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, item := range items {
		if item.Key == SettingKeyModeration {
			t.Fatalf("moderation must not be written by failed batch")
		}
	}
}

// TestPatchLastWriteWins 验证同 key 多次 PATCH 后读取最新值，不要求版本号。
func TestPatchLastWriteWins(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyMaxReplyDepth, Type: SettingTypeInteger, Value: float64(3)},
	}, 1); err != nil {
		t.Fatalf("patch first: %v", err)
	}
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyMaxReplyDepth, Type: SettingTypeInteger, Value: float64(8)},
	}, 2); err != nil {
		t.Fatalf("patch second: %v", err)
	}

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.MaxReplyDepth != 8 {
		t.Fatalf("max_reply_depth = %d, want 8", view.Settings.MaxReplyDepth)
	}
}

// TestPatchOnlySubmittedKeysChange 验证 PATCH 只修改提交项，其余保持原值。
func TestPatchOnlySubmittedKeysChange(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyModeration, Type: SettingTypeString, Value: "review"},
	}, 1); err != nil {
		t.Fatalf("patch: %v", err)
	}

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.Moderation != "review" {
		t.Fatalf("moderation = %q, want review", view.Settings.Moderation)
	}
	if view.Settings.CommentMode != DefaultSettings().CommentMode {
		t.Fatalf("comment_mode changed unexpectedly: %q", view.Settings.CommentMode)
	}
	if view.Settings.MaxReplyDepth != DefaultSettings().MaxReplyDepth {
		t.Fatalf("max_reply_depth changed unexpectedly: %d", view.Settings.MaxReplyDepth)
	}
}

// TestPatchUnknownKeyRoundTrip 验证合法未知 key 可存储并随公开列表返回。
func TestPatchUnknownKeyRoundTrip(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	items, err := svc.Patch(ctx, []SettingItem{
		{Key: "custom_flag", Type: SettingTypeBoolean, Value: true},
	}, 1)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	var found bool
	for _, item := range items {
		if item.Key == "custom_flag" {
			found = true
			if item.Value != true {
				t.Fatalf("custom_flag value = %v, want true", item.Value)
			}
		}
		if item.Key == SettingKeyInternalEpoch {
			t.Fatalf("internal epoch leaked into public list")
		}
	}
	if !found {
		t.Fatalf("custom_flag missing from response")
	}
}

// TestPatchEpochIncrement 验证 comment_mode 实际变化时 epoch 恰好递增一次，
// 相同值或其他 key 更新不递增。
func TestPatchEpochIncrement(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCommentMode, Type: SettingTypeString, Value: "authenticated"},
	}, 1); err != nil {
		t.Fatalf("patch mode: %v", err)
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Epoch != 1 {
		t.Fatalf("epoch = %d, want 1 after mode change", view.Epoch)
	}

	// 其他 key 更新不递增。
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyModeration, Type: SettingTypeString, Value: "review"},
	}, 1); err != nil {
		t.Fatalf("patch moderation: %v", err)
	}
	view, err = svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Epoch != 1 {
		t.Fatalf("epoch = %d, want 1 after non-mode update", view.Epoch)
	}

	// 相同模式重复写入不递增。
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCommentMode, Type: SettingTypeString, Value: "authenticated"},
	}, 1); err != nil {
		t.Fatalf("patch same mode: %v", err)
	}
	view, err = svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Epoch != 1 {
		t.Fatalf("epoch = %d, want 1 after same-mode write", view.Epoch)
	}

	// 再次发生实际变化时递增。
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCommentMode, Type: SettingTypeString, Value: "anonymous"},
	}, 1); err != nil {
		t.Fatalf("patch mode back: %v", err)
	}
	view, err = svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Epoch != 2 {
		t.Fatalf("epoch = %d, want 2 after second mode change", view.Epoch)
	}
}

// TestProviderSettingKeysIsolatedFromPublic 验证 provider 动态设置行不进入公开设置
// 列表与类型化快照，PATCH 也拒绝以 *_provider 后缀操作 provider 行。
func TestProviderSettingKeysIsolatedFromPublic(t *testing.T) {
	db, svc := newTestServiceDB(t)
	ctx := context.Background()

	repo := repository.NewSettingsRepo(db)
	if err := repo.UpsertAuthProvider(ctx, &repository.AuthProviderRow{
		ProviderKey: "github", Kind: domain.ProviderKindOAuth, Enabled: false,
	}); err != nil {
		t.Fatalf("upsert provider: %v", err)
	}
	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("get: %v", err)
	}

	items, err := svc.PublicItems(ctx)
	if err != nil {
		t.Fatalf("public items: %v", err)
	}
	for _, item := range items {
		if repository.IsProviderSettingKey(item.Key) {
			t.Fatalf("provider key %q leaked into public items", item.Key)
		}
	}

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get snapshot: %v", err)
	}
	if !reflect.DeepEqual(view.Settings, DefaultSettings()) {
		t.Fatalf("provider row altered typed snapshot: %+v", view.Settings)
	}

	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: "github_provider", Type: SettingTypeJSON, Value: map[string]any{"kind": "oauth"}},
	}, 1); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("patch provider key error = %v, want ErrValidation", err)
	}
}

// TestPatchInvalidatesCache 验证成功 PATCH 后缓存失效，Get 返回新值。
func TestPatchInvalidatesCache(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyPublicRegistration, Type: SettingTypeBoolean, Value: false},
	}, 1); err != nil {
		t.Fatalf("patch: %v", err)
	}

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.PublicRegistration {
		t.Fatal("public_registration must be false after patch")
	}
}

// TestCacheMissPublicationCoordinatesWithPatchInvalidation 验证旧快照的 miss 发布
// 一定先于已提交 PATCH 的失效操作完成，PATCH 返回后不会残留旧缓存。
func TestCacheMissPublicationCoordinatesWithPatchInvalidation(t *testing.T) {
	db, seedService := newTestServiceDB(t)
	ctx := context.Background()

	if _, err := seedService.Get(ctx); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}

	rowsLoaded := make(chan struct{})
	releaseMiss := make(chan struct{})
	transactionCommitted := make(chan struct{})
	continuePatch := make(chan struct{})
	var releaseMissOnce sync.Once
	var continuePatchOnce sync.Once
	releaseCacheMiss := func() {
		releaseMissOnce.Do(func() { close(releaseMiss) })
	}
	releasePatch := func() {
		continuePatchOnce.Do(func() { close(continuePatch) })
	}

	svc := NewService(afterCommitTxRunner{
		delegate: gormtx.NewRunner(db),
		afterCommit: func() {
			close(transactionCommitted)
			<-continuePatch
		},
	}, repository.NewSettingsRepo(db))

	var intercepted atomic.Bool
	const callbackName = "setting:test_pause_cache_miss_after_query"
	if err := db.Callback().Query().After("gorm:query").Register(callbackName, func(*gorm.DB) {
		if intercepted.CompareAndSwap(false, true) {
			close(rowsLoaded)
			<-releaseMiss
		}
	}); err != nil {
		t.Fatalf("register query callback: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Callback().Query().Remove(callbackName)
	})
	t.Cleanup(func() {
		releaseCacheMiss()
		releasePatch()
	})

	type getResult struct {
		view View
		err  error
	}
	getDone := make(chan getResult, 1)
	go func() {
		view, err := svc.Get(ctx)
		getDone <- getResult{view: view, err: err}
	}()
	<-rowsLoaded

	patchDone := make(chan error, 1)
	go func() {
		_, err := svc.Patch(ctx, []SettingItem{
			{Key: SettingKeyPublicRegistration, Type: SettingTypeBoolean, Value: false},
		}, 1)
		patchDone <- err
	}()
	select {
	case <-transactionCommitted:
	case err := <-patchDone:
		releaseCacheMiss()
		t.Fatalf("patch before commit boundary: %v", err)
	}

	missHoldsCacheLock := !svc.mu.TryLock()
	if !missHoldsCacheLock {
		svc.mu.Unlock()
	}
	releasePatch()

	var patchErr error
	if missHoldsCacheLock {
		releaseCacheMiss()
	} else {
		patchErr = <-patchDone
		releaseCacheMiss()
	}

	miss := <-getDone
	if miss.err != nil {
		t.Fatalf("cache miss get: %v", miss.err)
	}
	if !miss.view.Settings.PublicRegistration {
		t.Fatal("paused cache miss must contain the pre-PATCH value")
	}
	if missHoldsCacheLock {
		patchErr = <-patchDone
	}
	if patchErr != nil {
		t.Fatalf("patch: %v", patchErr)
	}

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get after overlapping patch: %v", err)
	}
	if view.Settings.PublicRegistration {
		t.Fatal("public_registration must be false after overlapping patch returns")
	}
}

// TestGetSeedsCaptchaProviderDefault 验证默认 captcha_provider 为空串且出现在公开设置项中。
func TestGetSeedsCaptchaProviderDefault(t *testing.T) {
	db, svc := newTestServiceDB(t)
	ctx := context.Background()

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.CaptchaProvider != "" {
		t.Fatalf("captcha_provider = %q, want empty default", view.Settings.CaptchaProvider)
	}
	items, err := svc.PublicItems(ctx)
	if err != nil {
		t.Fatalf("public items: %v", err)
	}
	var found bool
	for _, item := range items {
		if item.Key == SettingKeyCaptchaProvider {
			found = true
			if item.Type != SettingTypeString || item.Value != "" {
				t.Fatalf("captcha_provider item = %+v, want string empty", item)
			}
		}
		if repository.IsProviderSettingKey(item.Key) {
			t.Fatalf("provider row key %q leaked into public items", item.Key)
		}
	}
	if !found {
		t.Fatalf("captcha_provider missing from public items")
	}
	// 重建服务后仍从数据库读到默认值。
	fresh := NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	second, err := fresh.Get(ctx)
	if err != nil {
		t.Fatalf("fresh get: %v", err)
	}
	if second.Settings.CaptchaProvider != "" {
		t.Fatalf("fresh captcha_provider = %q, want empty", second.Settings.CaptchaProvider)
	}
}

// TestPatchCaptchaProviderSelectionValidation 验证 PATCH 选择 CAPTCHA provider 时
// 校验目标存在且可用；选择缺失或类型不符时失败关闭且不写入。
func TestPatchCaptchaProviderSelectionValidation(t *testing.T) {
	_, svc, providers := newTestServiceWithProviders(t)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	if err := providers.UpsertCaptcha(ctx, "cap", json.RawMessage(
		`{"provider":"cap","site_key":"s","secret_key":"sec","endpoint":"https://cap.example.com"}`)); err != nil {
		t.Fatalf("upsert captcha: %v", err)
	}
	if err := providers.UpsertAuth(ctx, "github", domain.ProviderKindOAuth, true, json.RawMessage(
		`{"client_id":"c","client_secret":"cs","auth_url":"https://a.example","token_url":"https://t.example"}`)); err != nil {
		t.Fatalf("upsert auth: %v", err)
	}

	// 选择已配置的 CAPTCHA provider 成功。
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCaptchaProvider, Type: SettingTypeString, Value: "cap"},
	}, 1); err != nil {
		t.Fatalf("patch valid selection: %v", err)
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.CaptchaProvider != "cap" {
		t.Fatalf("captcha_provider = %q, want cap", view.Settings.CaptchaProvider)
	}

	// 选择不存在的 provider 失败关闭且不改动选择。
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCaptchaProvider, Type: SettingTypeString, Value: "missing"},
	}, 1); !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("patch missing selection error = %v, want ErrCaptchaUnavailable", err)
	}
	view, err = svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.CaptchaProvider != "cap" {
		t.Fatalf("selection changed despite failed patch: %q", view.Settings.CaptchaProvider)
	}

	// 选择非 CAPTCHA provider 失败关闭。
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCaptchaProvider, Type: SettingTypeString, Value: "github"},
	}, 1); !errors.Is(err, domain.ErrCaptchaUnavailable) {
		t.Fatalf("patch auth selection error = %v, want ErrCaptchaUnavailable", err)
	}

	// 清空选择成功。
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCaptchaProvider, Type: SettingTypeString, Value: ""},
	}, 1); err != nil {
		t.Fatalf("patch clear selection: %v", err)
	}
	view, err = svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.CaptchaProvider != "" {
		t.Fatalf("captcha_provider = %q, want empty after clear", view.Settings.CaptchaProvider)
	}
}

// TestPatchCaptchaProviderInvalidatesCache 验证选择变更后缓存失效，Get 立即返回新值。
func TestPatchCaptchaProviderInvalidatesCache(t *testing.T) {
	_, svc, providers := newTestServiceWithProviders(t)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	if err := providers.UpsertCaptcha(ctx, "turnstile", json.RawMessage(
		`{"provider":"turnstile","site_key":"s","secret_key":"sec"}`)); err != nil {
		t.Fatalf("upsert captcha: %v", err)
	}
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCaptchaProvider, Type: SettingTypeString, Value: "turnstile"},
	}, 1); err != nil {
		t.Fatalf("patch selection: %v", err)
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.CaptchaProvider != "turnstile" {
		t.Fatalf("captcha_provider = %q, want turnstile (cache must be invalidated)", view.Settings.CaptchaProvider)
	}
}

// TestCommentSortDefaultIsAsc 验证默认 comment_sort 为 asc 且出现在公开设置项中。
func TestCommentSortDefaultIsAsc(t *testing.T) {
	db, svc := newTestServiceDB(t)
	ctx := context.Background()

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.CommentSort != string(domain.CommentSortAsc) {
		t.Fatalf("comment_sort = %q, want asc default", view.Settings.CommentSort)
	}
	items, err := svc.PublicItems(ctx)
	if err != nil {
		t.Fatalf("public items: %v", err)
	}
	var found bool
	for _, item := range items {
		if item.Key == SettingKeyCommentSort {
			found = true
			if item.Type != SettingTypeString || item.Value != string(domain.CommentSortAsc) {
				t.Fatalf("comment_sort item = %+v, want string asc", item)
			}
		}
	}
	if !found {
		t.Fatalf("comment_sort missing from public items")
	}
	// 重建服务后仍从数据库读到默认值。
	fresh := NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	second, err := fresh.Get(ctx)
	if err != nil {
		t.Fatalf("fresh get: %v", err)
	}
	if second.Settings.CommentSort != string(domain.CommentSortAsc) {
		t.Fatalf("fresh comment_sort = %q, want asc", second.Settings.CommentSort)
	}
}

// TestPatchCommentSortRoundTrip 验证 asc/desc 往返持久化、缓存失效与公开列表回读。
func TestPatchCommentSortRoundTrip(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCommentSort, Type: SettingTypeString, Value: string(domain.CommentSortDesc)},
	}, 1); err != nil {
		t.Fatalf("patch desc: %v", err)
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get after desc patch: %v", err)
	}
	if view.Settings.CommentSort != string(domain.CommentSortDesc) {
		t.Fatalf("comment_sort = %q, want desc", view.Settings.CommentSort)
	}
	items, err := svc.PublicItems(ctx)
	if err != nil {
		t.Fatalf("public items: %v", err)
	}
	var seen string
	for _, item := range items {
		if item.Key == SettingKeyCommentSort {
			seen, _ = item.Value.(string)
		}
	}
	if seen != string(domain.CommentSortDesc) {
		t.Fatalf("public items comment_sort = %q, want desc", seen)
	}

	// 切回 asc。
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCommentSort, Type: SettingTypeString, Value: string(domain.CommentSortAsc)},
	}, 2); err != nil {
		t.Fatalf("patch asc: %v", err)
	}
	view, err = svc.Get(ctx)
	if err != nil {
		t.Fatalf("get after asc patch: %v", err)
	}
	if view.Settings.CommentSort != string(domain.CommentSortAsc) {
		t.Fatalf("comment_sort = %q, want asc", view.Settings.CommentSort)
	}
}

// TestPatchCommentSortRejectsInvalid 验证非法 comment_sort 值被整体拒绝且不落库。
func TestPatchCommentSortRejectsInvalid(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyCommentSort, Type: SettingTypeString, Value: "bogus"},
	}, 1); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("patch invalid sort error = %v, want ErrValidation", err)
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.CommentSort != string(domain.CommentSortAsc) {
		t.Fatalf("comment_sort = %q after rejected patch, want asc default", view.Settings.CommentSort)
	}
}

// TestEmojiCatalogURLDefaultAndRoundTrip 验证 emoji_catalog_url 默认空串，
// 保存 HTTPS 值后持久化，清空后恢复空串。
func TestEmojiCatalogURLDefaultAndRoundTrip(t *testing.T) {
	db, svc := newTestServiceDB(t)
	ctx := context.Background()

	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.EmojiCatalogURL != "" {
		t.Fatalf("emoji_catalog_url default = %q, want empty", view.Settings.EmojiCatalogURL)
	}

	if _, err := svc.Patch(ctx, []SettingItem{
		{Key: SettingKeyEmojiCatalogURL, Type: SettingTypeString, Value: "https://cdn.example/emoji.json?signature=abc"},
	}, 1); err != nil {
		t.Fatalf("patch catalog url: %v", err)
	}
	view, err = svc.Get(ctx)
	if err != nil {
		t.Fatalf("get after patch: %v", err)
	}
	if view.Settings.EmojiCatalogURL != "https://cdn.example/emoji.json?signature=abc" {
		t.Fatalf("emoji_catalog_url = %q, want configured value", view.Settings.EmojiCatalogURL)
	}

	// 重建服务验证持久化。
	rebuilt := NewService(gormtx.NewRunner(db), repository.NewSettingsRepo(db))
	view, err = rebuilt.Get(ctx)
	if err != nil {
		t.Fatalf("rebuilt get: %v", err)
	}
	if view.Settings.EmojiCatalogURL != "https://cdn.example/emoji.json?signature=abc" {
		t.Fatalf("rebuilt emoji_catalog_url = %q, want persisted value", view.Settings.EmojiCatalogURL)
	}

	// 清空。
	if _, err := rebuilt.Patch(ctx, []SettingItem{
		{Key: SettingKeyEmojiCatalogURL, Type: SettingTypeString, Value: ""},
	}, 2); err != nil {
		t.Fatalf("patch clear: %v", err)
	}
	view, err = rebuilt.Get(ctx)
	if err != nil {
		t.Fatalf("get after clear: %v", err)
	}
	if view.Settings.EmojiCatalogURL != "" {
		t.Fatalf("emoji_catalog_url after clear = %q, want empty", view.Settings.EmojiCatalogURL)
	}
}

// TestPatchEmojiCatalogURLRejectsInvalid 验证非法 emoji_catalog_url 值被整体拒绝且不落库。
func TestPatchEmojiCatalogURLRejectsInvalid(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	for _, raw := range []string{
		"http://cdn.example/emoji.json",
		"https://user:pass@cdn.example/emoji.json",
		"https://cdn.example/emoji.json#fragment",
		"ftp://cdn.example/emoji.json",
	} {
		if _, err := svc.Patch(ctx, []SettingItem{
			{Key: SettingKeyEmojiCatalogURL, Type: SettingTypeString, Value: raw},
		}, 1); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("patch invalid catalog url %q error = %v, want ErrValidation", raw, err)
		}
	}
	view, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.Settings.EmojiCatalogURL != "" {
		t.Fatalf("emoji_catalog_url = %q after rejected patches, want empty default", view.Settings.EmojiCatalogURL)
	}
}

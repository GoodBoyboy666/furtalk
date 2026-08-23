package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DynamicSettingRow 是 dynamic_settings 行的仓储边界表示。
type DynamicSettingRow struct {
	Key       string
	Type      string
	Value     []byte
	UpdatedBy int64
}

// SettingsRepo 持久化按 key 存取的动态设置项。
type SettingsRepo struct {
	db *gorm.DB
}

// NewSettingsRepo 构建设置仓储。
func NewSettingsRepo(db *gorm.DB) *SettingsRepo {
	return &SettingsRepo{db: db}
}

// List 按 key 升序返回全部动态设置行。
func (r *SettingsRepo) List(ctx context.Context) ([]DynamicSettingRow, error) {
	var rows []model.DynamicSetting
	if err := gormtx.DB(ctx, r.db).Order("key").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list dynamic settings: %w", err)
	}
	out := make([]DynamicSettingRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDynamicSettingRow(row))
	}
	return out, nil
}

// Get 按 key 返回单个动态设置行；不存在时返回 domain.ErrNotFound。
func (r *SettingsRepo) Get(ctx context.Context, key string) (*DynamicSettingRow, error) {
	var row model.DynamicSetting
	err := gormtx.DB(ctx, r.db).Where("key = ?", key).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get dynamic setting: %w", err)
	}
	out := toDynamicSettingRow(row)
	return &out, nil
}

// LockRows 锁定并返回指定 key 的设置行，供事务内先读后写使用。
// 仅 PostgreSQL 生成 FOR UPDATE；SQLite 不支持该子句，单进程写事务由
// busy timeout 兜底，返回行仍按当前事务可见性读取。
func (r *SettingsRepo) LockRows(ctx context.Context, keys []string) ([]DynamicSettingRow, error) {
	query := gormtx.DB(ctx, r.db).Where("key IN ?", keys)
	if r.db.Dialector.Name() != "sqlite" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var rows []model.DynamicSetting
	if err := query.Order("key").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("lock dynamic settings: %w", err)
	}
	out := make([]DynamicSettingRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDynamicSettingRow(row))
	}
	return out, nil
}

// SeedMissing 批量插入缺失的设置项;已存在的 key 保持不变(ON CONFLICT DO NOTHING)。
// 并发首次播种时各写入方互不覆盖。
func (r *SettingsRepo) SeedMissing(ctx context.Context, rows []DynamicSettingRow) error {
	if len(rows) == 0 {
		return nil
	}
	models := make([]model.DynamicSetting, 0, len(rows))
	for _, s := range rows {
		models = append(models, toDynamicSettingModel(s))
	}
	err := gormtx.DB(ctx, r.db).Clauses(clause.OnConflict{DoNothing: true}).Create(&models).Error
	if err != nil {
		return fmt.Errorf("seed dynamic settings: %w", err)
	}
	return nil
}

// Upsert 批量写入设置项;同 key 已存在时直接覆盖(ON CONFLICT DO UPDATE),
// 未提交的 key 保持原值。批次在单个事务内全部成功或全部失败。
func (r *SettingsRepo) Upsert(ctx context.Context, rows []DynamicSettingRow) error {
	if len(rows) == 0 {
		return nil
	}
	models := make([]model.DynamicSetting, 0, len(rows))
	for _, s := range rows {
		models = append(models, toDynamicSettingModel(s))
	}
	err := gormtx.DB(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"type", "value", "updated_by", "updated_at"}),
	}).Create(&models).Error
	if err != nil {
		return fmt.Errorf("upsert dynamic settings: %w", err)
	}
	return nil
}

// toDynamicSettingRow 把 GORM 行转为仓储边界 DynamicSettingRow。
func toDynamicSettingRow(row model.DynamicSetting) DynamicSettingRow {
	return DynamicSettingRow{
		Key:       row.Key,
		Type:      row.Type,
		Value:     []byte(row.Value),
		UpdatedBy: row.UpdatedBy,
	}
}

// toDynamicSettingModel 把仓储边界行转为 GORM 模型。
func toDynamicSettingModel(s DynamicSettingRow) model.DynamicSetting {
	return model.DynamicSetting{
		Key:       s.Key,
		Type:      s.Type,
		Value:     string(s.Value),
		UpdatedBy: s.UpdatedBy,
	}
}

// CaptchaProviderSettingKey 是 CAPTCHA 选择设置 key。
// 它以公开设置行保存当前选中的 CAPTCHA provider key，不是 provider 配置行。
const CaptchaProviderSettingKey = "captcha_provider"

// providerSettingSuffix 是 provider 配置动态设置 key 的后缀。
const providerSettingSuffix = "_provider"

// providerSettingKey 把 provider key 映射为动态设置 key。
func providerSettingKey(providerKey string) string {
	return providerKey + providerSettingSuffix
}

// ProviderSettingKey 把 provider key 映射为动态设置 key，供上层校验行 key 冲突。
func ProviderSettingKey(providerKey string) string {
	return providerSettingKey(providerKey)
}

// IsProviderSettingKey 报告 key 是否属于 provider 配置动态设置行。
// provider 行是内部设置，通用设置读写须将其过滤，不得进入公开设置；
// captcha_provider 是公开选择设置而非 provider 配置行，明确排除。
func IsProviderSettingKey(key string) bool {
	return key != CaptchaProviderSettingKey && strings.HasSuffix(key, providerSettingSuffix)
}

// CaptchaProviderRow 是 CAPTCHA provider 配置行的仓储边界表示，含密文字段。
// CAPTCHA 行没有 kind 之外的启用语义，不保存 enabled。
type CaptchaProviderRow struct {
	ProviderKey      string
	PublicConfig     []byte
	SecretKeyVersion int
	SecretNonce      []byte
	SecretCiphertext []byte
}

// AuthProviderRow 是 OAuth/OIDC provider 配置行的仓储边界表示，含密文字段。
type AuthProviderRow struct {
	ProviderKey      string
	Kind             domain.ProviderKind
	Enabled          bool
	PublicConfig     []byte
	SecretKeyVersion int
	SecretNonce      []byte
	SecretCiphertext []byte
}

// SpamProviderRow 是垃圾检测 provider 配置行的仓储边界表示，含密文字段。
// 垃圾检测 provider 与 OAuth/OIDC 一样携带 enabled，允许多个渠道同时启用。
type SpamProviderRow struct {
	ProviderKey      string
	Enabled          bool
	PublicConfig     []byte
	SecretKeyVersion int
	SecretNonce      []byte
	SecretCiphertext []byte
}

// captchaProviderEnvelope 是 CAPTCHA provider 存入 dynamic_settings 的 JSON value。
// 只含 kind 判别符与公开/密文块，绝不包含 enabled。
type captchaProviderEnvelope struct {
	Kind             domain.ProviderKind `json:"kind"`
	PublicConfig     json.RawMessage     `json:"public_config,omitempty"`
	SecretKeyVersion int                 `json:"secret_key_version"`
	SecretNonce      []byte              `json:"secret_nonce,omitempty"`
	SecretCiphertext []byte              `json:"secret_ciphertext,omitempty"`
}

// authProviderEnvelope 是 OAuth/OIDC provider 存入 dynamic_settings 的 JSON value。
type authProviderEnvelope struct {
	Kind             domain.ProviderKind `json:"kind"`
	Enabled          bool                `json:"enabled"`
	PublicConfig     json.RawMessage     `json:"public_config,omitempty"`
	SecretKeyVersion int                 `json:"secret_key_version"`
	SecretNonce      []byte              `json:"secret_nonce,omitempty"`
	SecretCiphertext []byte              `json:"secret_ciphertext,omitempty"`
}

// spamProviderEnvelope 是垃圾检测 provider 存入 dynamic_settings 的 JSON value。
// 与 OAuth/OIDC 一样携带 enabled；本地词库渠道允许无 Secret 信封。
type spamProviderEnvelope struct {
	Kind             domain.ProviderKind `json:"kind"`
	Enabled          bool                `json:"enabled"`
	PublicConfig     json.RawMessage     `json:"public_config,omitempty"`
	SecretKeyVersion int                 `json:"secret_key_version"`
	SecretNonce      []byte              `json:"secret_nonce,omitempty"`
	SecretCiphertext []byte              `json:"secret_ciphertext,omitempty"`
}

// decodedProviderRow 是 provider 动态设置行解码后的中间表示，供类型化方法过滤。
type decodedProviderRow struct {
	providerKey      string
	kind             domain.ProviderKind
	enabled          bool
	publicConfig     json.RawMessage
	secretKeyVersion int
	secretNonce      []byte
	secretCiphertext []byte
}

// ListCaptchaProviders 按 provider key 升序返回全部 CAPTCHA provider 配置行。
func (r *SettingsRepo) ListCaptchaProviders(ctx context.Context) ([]CaptchaProviderRow, error) {
	rows, err := r.listProviderDecoded(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]CaptchaProviderRow, 0, len(rows))
	for _, row := range rows {
		if row.kind != domain.ProviderKindCaptcha {
			continue
		}
		out = append(out, row.toCaptchaRow())
	}
	return out, nil
}

// GetCaptchaProvider 按 provider key 查询 CAPTCHA 配置行；
// 行缺失或类型不是 CAPTCHA 时返回 domain.ErrNotFound。
func (r *SettingsRepo) GetCaptchaProvider(ctx context.Context, providerKey string) (*CaptchaProviderRow, error) {
	row, err := r.getProviderDecoded(ctx, providerKey)
	if err != nil {
		return nil, err
	}
	if row.kind != domain.ProviderKindCaptcha {
		return nil, domain.ErrNotFound
	}
	out := row.toCaptchaRow()
	return &out, nil
}

// UpsertCaptchaProvider 写入 CAPTCHA provider 配置，key 冲突时原地覆盖 JSON value。
func (r *SettingsRepo) UpsertCaptchaProvider(ctx context.Context, s *CaptchaProviderRow) error {
	env := captchaProviderEnvelope{
		Kind:             domain.ProviderKindCaptcha,
		SecretKeyVersion: s.SecretKeyVersion,
		SecretNonce:      s.SecretNonce,
		SecretCiphertext: s.SecretCiphertext,
	}
	if len(s.PublicConfig) > 0 {
		env.PublicConfig = json.RawMessage(s.PublicConfig)
	}
	return r.upsertProviderValue(ctx, s.ProviderKey, env)
}

// DeleteCaptchaProvider 删除 CAPTCHA provider 配置行；行缺失或类型不符时返回 domain.ErrNotFound。
func (r *SettingsRepo) DeleteCaptchaProvider(ctx context.Context, providerKey string) error {
	if _, err := r.GetCaptchaProvider(ctx, providerKey); err != nil {
		return err
	}
	return r.deleteProviderRow(ctx, providerKey)
}

// ListAuthProviders 按 provider key 升序返回全部 OAuth/OIDC provider 配置行。
func (r *SettingsRepo) ListAuthProviders(ctx context.Context) ([]AuthProviderRow, error) {
	rows, err := r.listProviderDecoded(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AuthProviderRow, 0, len(rows))
	for _, row := range rows {
		if row.kind != domain.ProviderKindOAuth && row.kind != domain.ProviderKindOIDC {
			continue
		}
		out = append(out, row.toAuthRow())
	}
	return out, nil
}

// GetAuthProvider 按 provider key 查询 OAuth/OIDC 配置行；
// 行缺失或类型不是 OAuth/OIDC 时返回 domain.ErrNotFound。
func (r *SettingsRepo) GetAuthProvider(ctx context.Context, providerKey string) (*AuthProviderRow, error) {
	row, err := r.getProviderDecoded(ctx, providerKey)
	if err != nil {
		return nil, err
	}
	if row.kind != domain.ProviderKindOAuth && row.kind != domain.ProviderKindOIDC {
		return nil, domain.ErrNotFound
	}
	out := row.toAuthRow()
	return &out, nil
}

// UpsertAuthProvider 写入 OAuth/OIDC provider 配置，key 冲突时原地覆盖 JSON value。
func (r *SettingsRepo) UpsertAuthProvider(ctx context.Context, s *AuthProviderRow) error {
	env := authProviderEnvelope{
		Kind:             s.Kind,
		Enabled:          s.Enabled,
		SecretKeyVersion: s.SecretKeyVersion,
		SecretNonce:      s.SecretNonce,
		SecretCiphertext: s.SecretCiphertext,
	}
	if len(s.PublicConfig) > 0 {
		env.PublicConfig = json.RawMessage(s.PublicConfig)
	}
	return r.upsertProviderValue(ctx, s.ProviderKey, env)
}

// DeleteAuthProvider 删除 OAuth/OIDC provider 配置行；行缺失或类型不符时返回 domain.ErrNotFound。
func (r *SettingsRepo) DeleteAuthProvider(ctx context.Context, providerKey string) error {
	if _, err := r.GetAuthProvider(ctx, providerKey); err != nil {
		return err
	}
	return r.deleteProviderRow(ctx, providerKey)
}

// ListSpamProviders 按 provider key 升序返回全部垃圾检测 provider 配置行。
func (r *SettingsRepo) ListSpamProviders(ctx context.Context) ([]SpamProviderRow, error) {
	rows, err := r.listProviderDecoded(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SpamProviderRow, 0, len(rows))
	for _, row := range rows {
		if row.kind != domain.ProviderKindSpam {
			continue
		}
		out = append(out, row.toSpamRow())
	}
	return out, nil
}

// GetSpamProvider 按 provider key 查询垃圾检测配置行；
// 行缺失或类型不是 spam 时返回 domain.ErrNotFound。
func (r *SettingsRepo) GetSpamProvider(ctx context.Context, providerKey string) (*SpamProviderRow, error) {
	row, err := r.getProviderDecoded(ctx, providerKey)
	if err != nil {
		return nil, err
	}
	if row.kind != domain.ProviderKindSpam {
		return nil, domain.ErrNotFound
	}
	out := row.toSpamRow()
	return &out, nil
}

// UpsertSpamProvider 写入垃圾检测 provider 配置，key 冲突时原地覆盖 JSON value。
func (r *SettingsRepo) UpsertSpamProvider(ctx context.Context, s *SpamProviderRow) error {
	env := spamProviderEnvelope{
		Kind:             domain.ProviderKindSpam,
		Enabled:          s.Enabled,
		SecretKeyVersion: s.SecretKeyVersion,
		SecretNonce:      s.SecretNonce,
		SecretCiphertext: s.SecretCiphertext,
	}
	if len(s.PublicConfig) > 0 {
		env.PublicConfig = json.RawMessage(s.PublicConfig)
	}
	return r.upsertProviderValue(ctx, s.ProviderKey, env)
}

// DeleteSpamProvider 删除垃圾检测 provider 配置行；行缺失或类型不符时返回 domain.ErrNotFound。
func (r *SettingsRepo) DeleteSpamProvider(ctx context.Context, providerKey string) error {
	if _, err := r.GetSpamProvider(ctx, providerKey); err != nil {
		return err
	}
	return r.deleteProviderRow(ctx, providerKey)
}

// toCaptchaRow 把解码中间表示转为 CAPTCHA 行。
func (d decodedProviderRow) toCaptchaRow() CaptchaProviderRow {
	return CaptchaProviderRow{
		ProviderKey:      d.providerKey,
		PublicConfig:     d.publicConfig,
		SecretKeyVersion: d.secretKeyVersion,
		SecretNonce:      d.secretNonce,
		SecretCiphertext: d.secretCiphertext,
	}
}

// toAuthRow 把解码中间表示转为 OAuth/OIDC 行。
func (d decodedProviderRow) toAuthRow() AuthProviderRow {
	return AuthProviderRow{
		ProviderKey:      d.providerKey,
		Kind:             d.kind,
		Enabled:          d.enabled,
		PublicConfig:     d.publicConfig,
		SecretKeyVersion: d.secretKeyVersion,
		SecretNonce:      d.secretNonce,
		SecretCiphertext: d.secretCiphertext,
	}
}

// toSpamRow 把解码中间表示转为垃圾检测行。
func (d decodedProviderRow) toSpamRow() SpamProviderRow {
	return SpamProviderRow{
		ProviderKey:      d.providerKey,
		Enabled:          d.enabled,
		PublicConfig:     d.publicConfig,
		SecretKeyVersion: d.secretKeyVersion,
		SecretNonce:      d.secretNonce,
		SecretCiphertext: d.secretCiphertext,
	}
}

// listProviderDecoded 返回全部 provider 配置行解码后的中间表示，按 key 升序；
// 排除公开选择设置 captcha_provider 行。
func (r *SettingsRepo) listProviderDecoded(ctx context.Context) ([]decodedProviderRow, error) {
	var rows []model.DynamicSetting
	if err := gormtx.DB(ctx, r.db).
		Where("key LIKE ? ESCAPE '\\'", "%\\_provider").
		Where("key <> ?", CaptchaProviderSettingKey).
		Order("key").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list provider configs: %w", err)
	}
	out := make([]decodedProviderRow, 0, len(rows))
	for _, row := range rows {
		provider, err := decodeProviderRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, provider)
	}
	return out, nil
}

// getProviderDecoded 按 key 返回单个 provider 配置行解码后的中间表示；缺失时返回 domain.ErrNotFound。
func (r *SettingsRepo) getProviderDecoded(ctx context.Context, providerKey string) (decodedProviderRow, error) {
	var row model.DynamicSetting
	err := gormtx.DB(ctx, r.db).
		Where("key = ?", providerSettingKey(providerKey)).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return decodedProviderRow{}, domain.ErrNotFound
	}
	if err != nil {
		return decodedProviderRow{}, fmt.Errorf("get provider config: %w", err)
	}
	return decodeProviderRow(row)
}

// decodeProviderRow 把 provider 动态设置行 value 解码为中间表示。
func decodeProviderRow(row model.DynamicSetting) (decodedProviderRow, error) {
	var discriminator struct {
		Kind domain.ProviderKind `json:"kind"`
	}
	if err := json.Unmarshal([]byte(row.Value), &discriminator); err != nil {
		return decodedProviderRow{}, fmt.Errorf("decode provider setting %q: %w", row.Key, err)
	}
	out := decodedProviderRow{
		providerKey: strings.TrimSuffix(row.Key, providerSettingSuffix),
		kind:        discriminator.Kind,
	}
	switch discriminator.Kind {
	case domain.ProviderKindCaptcha:
		var env captchaProviderEnvelope
		if err := json.Unmarshal([]byte(row.Value), &env); err != nil {
			return decodedProviderRow{}, fmt.Errorf("decode provider setting %q: %w", row.Key, err)
		}
		out.publicConfig = normalizePublicConfig(env.PublicConfig)
		out.secretKeyVersion = env.SecretKeyVersion
		out.secretNonce = env.SecretNonce
		out.secretCiphertext = env.SecretCiphertext
	case domain.ProviderKindOAuth, domain.ProviderKindOIDC:
		var env authProviderEnvelope
		if err := json.Unmarshal([]byte(row.Value), &env); err != nil {
			return decodedProviderRow{}, fmt.Errorf("decode provider setting %q: %w", row.Key, err)
		}
		out.enabled = env.Enabled
		out.publicConfig = normalizePublicConfig(env.PublicConfig)
		out.secretKeyVersion = env.SecretKeyVersion
		out.secretNonce = env.SecretNonce
		out.secretCiphertext = env.SecretCiphertext
	case domain.ProviderKindSpam:
		var env spamProviderEnvelope
		if err := json.Unmarshal([]byte(row.Value), &env); err != nil {
			return decodedProviderRow{}, fmt.Errorf("decode provider setting %q: %w", row.Key, err)
		}
		out.enabled = env.Enabled
		out.publicConfig = normalizePublicConfig(env.PublicConfig)
		out.secretKeyVersion = env.SecretKeyVersion
		out.secretNonce = env.SecretNonce
		out.secretCiphertext = env.SecretCiphertext
	default:
		return decodedProviderRow{}, fmt.Errorf("%w: unknown provider kind %q", domain.ErrValidation, discriminator.Kind)
	}
	return out, nil
}

// normalizePublicConfig 把 JSON null 或空 public_config 归一化为 nil。
func normalizePublicConfig(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// upsertProviderValue 把 provider 信封编码后写入 provider 配置行，key 冲突时原地覆盖。
func (r *SettingsRepo) upsertProviderValue(ctx context.Context, providerKey string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode provider setting %q: %w", providerSettingKey(providerKey), err)
	}
	row := model.DynamicSetting{
		Key:       providerSettingKey(providerKey),
		Type:      "json",
		Value:     string(payload),
		UpdatedBy: 0,
	}
	err = gormtx.DB(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"type", "value", "updated_by", "updated_at"}),
	}).Create(&row).Error
	if err != nil {
		return fmt.Errorf("upsert provider config: %w", err)
	}
	return nil
}

// deleteProviderRow 删除单个 provider 配置行。
func (r *SettingsRepo) deleteProviderRow(ctx context.Context, providerKey string) error {
	err := gormtx.DB(ctx, r.db).
		Where("key = ?", providerSettingKey(providerKey)).
		Delete(&model.DynamicSetting{}).Error
	if err != nil {
		return fmt.Errorf("delete provider config: %w", err)
	}
	return nil
}

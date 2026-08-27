// Package setting 是动态实例配置与提供商配置管理的业务层。
// 只依赖 domain 与 repository；provider 密钥的加密/解密是本层的业务逻辑。
package setting

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"furtalk/internal/domain"
	"furtalk/internal/platform/value"
	"furtalk/internal/repository"
)

// maxReplyDepthLimit 是最大回复深度的上限。
const maxReplyDepthLimit = 50

// 已知设置 key 的稳定常量。
const (
	SettingKeyCommentMode        = "comment_mode"
	SettingKeyModeration         = "moderation"
	SettingKeyUserDeleteMode     = "user_delete_mode"
	SettingKeyMaxReplyDepth      = "max_reply_depth"
	SettingKeyPublicRegistration = "public_registration"
	SettingKeyPrivacy            = "privacy"
	SettingKeyCaptchaPolicy      = "captcha_policy"
	SettingKeyNotifications      = "notifications"
	// SettingKeyCaptchaProvider 是当前选择的 CAPTCHA provider key 设置。
	// 它是公开 string 设置；值为 provider key，空串表示未选择。
	SettingKeyCaptchaProvider = repository.CaptchaProviderSettingKey

	// SettingKeyEmailDomainWhitelist 是公开 json 设置：非空时仅精确命中的域名允许注册。
	SettingKeyEmailDomainWhitelist = "email_domain_whitelist"
	// SettingKeyEmailDomainBlacklist 是公开 json 设置：白名单为空时精确命中的域名拒绝注册。
	SettingKeyEmailDomainBlacklist = "email_domain_blacklist"
	// SettingKeyGravatarBaseURL 是公开 string 设置：头像 URL 基址。
	SettingKeyGravatarBaseURL = "gravatar_base_url"
	// SettingKeyCommentSort 是公开 string 设置：widget 默认排序，允许 asc/desc/hot。
	SettingKeyCommentSort = "comment_sort"
	// SettingKeyEmojiCatalogURL 是公开 string 设置：widget 远程表情目录的绝对 HTTPS URL。
	// 空串表示不配置；query 允许，userinfo 与 fragment 不允许。
	SettingKeyEmojiCatalogURL = "emoji_catalog_url"

	// SettingKeyInternalEpoch 持久化 Widget 凭证代次的保留内部 key。
	// 它不通过管理 API 暴露，也不能由管理 API 修改。
	SettingKeyInternalEpoch = "internal.widget_credential_epoch"
)

// internalKeyPrefix 是保留的内部设置 key 前缀。
const internalKeyPrefix = "internal."

// settingKeyPattern 是公开设置 key 的格式：小写字母开头，可含小写字母、数字、下划线与点。
var settingKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.]*$`)

// SettingType 是设置项的公开类型。
type SettingType string

// 支持的公开设置类型。
const (
	SettingTypeString  SettingType = "string"
	SettingTypeInteger SettingType = "integer"
	SettingTypeBoolean SettingType = "boolean"
	SettingTypeJSON    SettingType = "json"
)

// SettingItem 是一个公开设置项：唯一 key、声明类型与合法 JSON 值。
// 同一类型下 value 的 JSON 形态必须匹配，所有类型拒绝 null。
type SettingItem struct {
	Key   string      `json:"key"`
	Type  SettingType `json:"type"`
	Value any         `json:"value"`
}

// knownSetting 描述一个已知顶层 key 的固定类型。
type knownSetting struct {
	key string
	typ SettingType
}

// knownSettings 是已知顶层 key 与其固定类型的注册表。
var knownSettings = []knownSetting{
	{key: SettingKeyCommentMode, typ: SettingTypeString},
	{key: SettingKeyModeration, typ: SettingTypeString},
	{key: SettingKeyUserDeleteMode, typ: SettingTypeString},
	{key: SettingKeyMaxReplyDepth, typ: SettingTypeInteger},
	{key: SettingKeyPublicRegistration, typ: SettingTypeBoolean},
	{key: SettingKeyPrivacy, typ: SettingTypeJSON},
	{key: SettingKeyCaptchaPolicy, typ: SettingTypeJSON},
	{key: SettingKeyNotifications, typ: SettingTypeJSON},
	{key: SettingKeyCaptchaProvider, typ: SettingTypeString},
	{key: SettingKeyEmailDomainWhitelist, typ: SettingTypeJSON},
	{key: SettingKeyEmailDomainBlacklist, typ: SettingTypeJSON},
	{key: SettingKeyGravatarBaseURL, typ: SettingTypeString},
	{key: SettingKeyCommentSort, typ: SettingTypeString},
	{key: SettingKeyEmojiCatalogURL, typ: SettingTypeString},
}

// View 是一次 Get 的原子快照：类型化设置与凭证 epoch。
type View struct {
	Settings domain.Settings
	Epoch    int64
}

// TxRunner 是设置用例依赖的事务边界，由 platform/gormtx.Runner 实现。
type TxRunner interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// CaptchaSelectionValidator 校验 captcha_provider 选择指向可用的 CAPTCHA provider。
// 由 ProviderService 实现；在设置 PATCH 事务内调用。
type CaptchaSelectionValidator interface {
	ValidateSelection(ctx context.Context, providerKey string) error
}

// Service 读取并更新按 key 存储的动态实例配置，
// 评论模式实际变化时原子递增内部 credential_epoch。
type Service struct {
	txRunner         TxRunner
	settingsRepo     *repository.SettingsRepo
	captchaValidator CaptchaSelectionValidator
	mu               sync.RWMutex
	cached           *view
}

type view struct {
	settings domain.Settings
	epoch    int64
}

// NewService 构建设置服务，注入事务运行器与设置仓储。
// CAPTCHA 选择校验器可通过 SetCaptchaValidator 安装。
func NewService(txRunner TxRunner, settingsRepo *repository.SettingsRepo) *Service {
	return &Service{txRunner: txRunner, settingsRepo: settingsRepo}
}

// DefaultSettings 返回首次访问时写入的初始实例配置。
func DefaultSettings() domain.Settings {
	return domain.Settings{
		CommentMode:        domain.CommentModeAnonymous,
		Moderation:         domain.ModerationDirect,
		UserDeleteMode:     domain.UserDeleteModeSoft,
		MaxReplyDepth:      3,
		PublicRegistration: true,
		Privacy: domain.PrivacySettings{
			IPMode: "coarse",
			UAMode: "coarse",
		},
		CaptchaPolicy: map[string]bool{},
		Notifications: domain.NotificationSettings{
			Moderation: true,
			Replies:    true,
		},
		CaptchaProvider:      "",
		EmailDomainWhitelist: []string{},
		EmailDomainBlacklist: []string{},
		GravatarBaseURL:      value.DefaultGravatarBaseURL,
		CommentSort:          string(domain.CommentSortAsc),
		EmojiCatalogURL:      "",
	}
}

// Validate 检查跨字段不变量和枚举/限制合法性。
func Validate(s domain.Settings) error {
	if s.CommentMode != domain.CommentModeAnonymous && s.CommentMode != domain.CommentModeAuthenticated {
		return fmt.Errorf("%w: comment mode must be anonymous or authenticated", domain.ErrValidation)
	}
	if s.Moderation != domain.ModerationDirect && s.Moderation != domain.ModerationReview {
		return fmt.Errorf("%w: moderation must be direct or review", domain.ErrValidation)
	}
	if s.UserDeleteMode != domain.UserDeleteModeSoft && s.UserDeleteMode != domain.UserDeleteModeHard {
		return fmt.Errorf("%w: user delete mode must be soft or hard", domain.ErrValidation)
	}
	if s.MaxReplyDepth < 0 || s.MaxReplyDepth > maxReplyDepthLimit {
		return fmt.Errorf("%w: max reply depth must be between 0 and %d", domain.ErrValidation, maxReplyDepthLimit)
	}
	if !validPrivacyMode(s.Privacy.IPMode) {
		return fmt.Errorf("%w: ip mode must be none, coarse or full", domain.ErrValidation)
	}
	if !validPrivacyMode(s.Privacy.UAMode) {
		return fmt.Errorf("%w: ua mode must be none, coarse or full", domain.ErrValidation)
	}
	for action := range s.CaptchaPolicy {
		if action == "" {
			return fmt.Errorf("%w: captcha action keys must not be empty", domain.ErrValidation)
		}
	}
	if _, err := value.NormalizeEmailDomains(s.EmailDomainWhitelist); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	if _, err := value.NormalizeEmailDomains(s.EmailDomainBlacklist); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	if err := value.ValidateGravatarBaseURL(s.GravatarBaseURL); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	if !domain.ValidPublicCommentSort(s.CommentSort) {
		return fmt.Errorf("%w: comment sort must be asc, desc or hot", domain.ErrValidation)
	}
	if err := value.ValidateEmojiCatalogURL(s.EmojiCatalogURL); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	return nil
}

func validPrivacyMode(mode string) bool {
	return mode == "none" || mode == "coarse" || mode == "full"
}

// defaultItems 返回已知设置的默认公开设置项。
func defaultItems() []SettingItem {
	s := DefaultSettings()
	return []SettingItem{
		{Key: SettingKeyCommentMode, Type: SettingTypeString, Value: s.CommentMode},
		{Key: SettingKeyModeration, Type: SettingTypeString, Value: s.Moderation},
		{Key: SettingKeyUserDeleteMode, Type: SettingTypeString, Value: s.UserDeleteMode},
		{Key: SettingKeyMaxReplyDepth, Type: SettingTypeInteger, Value: s.MaxReplyDepth},
		{Key: SettingKeyPublicRegistration, Type: SettingTypeBoolean, Value: s.PublicRegistration},
		{Key: SettingKeyPrivacy, Type: SettingTypeJSON, Value: s.Privacy},
		{Key: SettingKeyCaptchaPolicy, Type: SettingTypeJSON, Value: s.CaptchaPolicy},
		{Key: SettingKeyNotifications, Type: SettingTypeJSON, Value: s.Notifications},
		{Key: SettingKeyCaptchaProvider, Type: SettingTypeString, Value: s.CaptchaProvider},
		{Key: SettingKeyEmailDomainWhitelist, Type: SettingTypeJSON, Value: s.EmailDomainWhitelist},
		{Key: SettingKeyEmailDomainBlacklist, Type: SettingTypeJSON, Value: s.EmailDomainBlacklist},
		{Key: SettingKeyGravatarBaseURL, Type: SettingTypeString, Value: s.GravatarBaseURL},
		{Key: SettingKeyCommentSort, Type: SettingTypeString, Value: s.CommentSort},
		{Key: SettingKeyEmojiCatalogURL, Type: SettingTypeString, Value: s.EmojiCatalogURL},
	}
}

// knownType 返回已知 key 的固定类型；未知 key 返回 false。
func knownType(key string) (SettingType, bool) {
	for _, ks := range knownSettings {
		if ks.key == key {
			return ks.typ, true
		}
	}
	return "", false
}

// isInternalKey 报告 key 是否属于保留的内部前缀。
func isInternalKey(key string) bool {
	return strings.HasPrefix(key, internalKeyPrefix)
}

// validPublicKey 校验公开设置 key 的格式且不属于保留前缀或 provider 后缀。
func validPublicKey(key string) bool {
	return settingKeyPattern.MatchString(key) && !isInternalKey(key) && !repository.IsProviderSettingKey(key)
}

// validateItemType 校验单个设置项的 type 支持且 value 形态匹配。
// json 类型只接受 object/array，标量必须使用对应的 string/integer/boolean。
func validateItemType(item SettingItem) error {
	switch item.Type {
	case SettingTypeString:
		if _, ok := item.Value.(string); !ok {
			return fmt.Errorf("%w: setting %q expects a string value", domain.ErrValidation, item.Key)
		}
	case SettingTypeInteger:
		number, ok := item.Value.(float64)
		if !ok || math.Trunc(number) != number {
			return fmt.Errorf("%w: setting %q expects an integer value", domain.ErrValidation, item.Key)
		}
	case SettingTypeBoolean:
		if _, ok := item.Value.(bool); !ok {
			return fmt.Errorf("%w: setting %q expects a boolean value", domain.ErrValidation, item.Key)
		}
	case SettingTypeJSON:
		switch item.Value.(type) {
		case map[string]any, []any:
		default:
			return fmt.Errorf("%w: setting %q expects a JSON object or array", domain.ErrValidation, item.Key)
		}
	default:
		return fmt.Errorf("%w: unsupported setting type %q", domain.ErrValidation, item.Type)
	}
	return nil
}

// validatePatch 校验 PATCH 请求的结构：非空、key 格式、无重复、无保留前缀、
// type 受支持、value 形态匹配，已知 key 的 type 必须与注册表一致。
func validatePatch(items []SettingItem) error {
	if len(items) == 0 {
		return fmt.Errorf("%w: settings must not be empty", domain.ErrValidation)
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if !validPublicKey(item.Key) {
			return fmt.Errorf("%w: invalid setting key %q", domain.ErrValidation, item.Key)
		}
		if seen[item.Key] {
			return fmt.Errorf("%w: duplicate setting key %q", domain.ErrValidation, item.Key)
		}
		seen[item.Key] = true
		if item.Value == nil {
			return fmt.Errorf("%w: setting %q must not be null", domain.ErrValidation, item.Key)
		}
		if err := validateItemType(item); err != nil {
			return err
		}
		if typ, ok := knownType(item.Key); ok && typ != item.Type {
			return fmt.Errorf("%w: setting %q expects type %s", domain.ErrValidation, item.Key, typ)
		}
	}
	return nil
}

// hasKey 报告 PATCH 项中是否包含指定 key。
func hasKey(items []SettingItem, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

// itemValue 返回 PATCH 项中指定 key 的 value，缺失时返回 nil。
func itemValue(items []SettingItem, key string) any {
	for _, item := range items {
		if item.Key == key {
			return item.Value
		}
	}
	return nil
}

// applyItems 把公开设置项覆盖到类型化快照；未知 key 不进入快照但保留存储。
func applyItems(s *domain.Settings, items []SettingItem) error {
	for _, item := range items {
		switch item.Key {
		case SettingKeyCommentMode:
			s.CommentMode = item.Value.(string)
		case SettingKeyModeration:
			s.Moderation = item.Value.(string)
		case SettingKeyUserDeleteMode:
			s.UserDeleteMode = item.Value.(string)
		case SettingKeyMaxReplyDepth:
			s.MaxReplyDepth = int(item.Value.(float64))
		case SettingKeyPublicRegistration:
			s.PublicRegistration = item.Value.(bool)
		case SettingKeyPrivacy:
			var privacy domain.PrivacySettings
			if err := decodeInto(item.Value, &privacy); err != nil {
				return fmt.Errorf("setting: decode privacy: %w", err)
			}
			s.Privacy = privacy
		case SettingKeyCaptchaPolicy:
			policy := map[string]bool{}
			if err := decodeInto(item.Value, &policy); err != nil {
				return fmt.Errorf("setting: decode captcha policy: %w", err)
			}
			s.CaptchaPolicy = policy
		case SettingKeyNotifications:
			var notifications domain.NotificationSettings
			if err := decodeInto(item.Value, &notifications); err != nil {
				return fmt.Errorf("setting: decode notifications: %w", err)
			}
			s.Notifications = notifications
		case SettingKeyCaptchaProvider:
			s.CaptchaProvider = item.Value.(string)
		case SettingKeyEmailDomainWhitelist:
			var raw []string
			if err := decodeInto(item.Value, &raw); err != nil {
				return fmt.Errorf("setting: decode email domain whitelist: %w", err)
			}
			domains, err := value.NormalizeEmailDomains(raw)
			if err != nil {
				return fmt.Errorf("%w: %v", domain.ErrValidation, err)
			}
			s.EmailDomainWhitelist = domains
		case SettingKeyEmailDomainBlacklist:
			var raw []string
			if err := decodeInto(item.Value, &raw); err != nil {
				return fmt.Errorf("setting: decode email domain blacklist: %w", err)
			}
			domains, err := value.NormalizeEmailDomains(raw)
			if err != nil {
				return fmt.Errorf("%w: %v", domain.ErrValidation, err)
			}
			s.EmailDomainBlacklist = domains
		case SettingKeyGravatarBaseURL:
			s.GravatarBaseURL = strings.TrimSpace(item.Value.(string))
		case SettingKeyCommentSort:
			s.CommentSort = item.Value.(string)
		case SettingKeyEmojiCatalogURL:
			s.EmojiCatalogURL = strings.TrimSpace(item.Value.(string))
		}
	}
	return nil
}

// decodeInto 把任意 JSON 值重新编码后解码到目标结构。
func decodeInto(value any, into any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, into)
}

// settingsFromRows 从存储行构建类型化设置，缺失的已知 key 回落到默认值。
func settingsFromRows(rows []repository.DynamicSettingRow) (domain.Settings, error) {
	s := DefaultSettings()
	items := make([]SettingItem, 0, len(rows))
	for _, row := range rows {
		if isInternalKey(row.Key) || repository.IsProviderSettingKey(row.Key) {
			continue
		}
		var value any
		if err := json.Unmarshal(row.Value, &value); err != nil {
			return domain.Settings{}, fmt.Errorf("setting: decode value of %q: %w", row.Key, err)
		}
		items = append(items, SettingItem{Key: row.Key, Type: SettingType(row.Type), Value: value})
	}
	if err := applyItems(&s, items); err != nil {
		return domain.Settings{}, err
	}
	return s, nil
}

// publicItemsFromRows 把存储行解码为公开设置项列表（不含内部 key），行序即返回序。
func publicItemsFromRows(rows []repository.DynamicSettingRow) ([]SettingItem, error) {
	items := make([]SettingItem, 0, len(rows))
	for _, row := range rows {
		if isInternalKey(row.Key) || repository.IsProviderSettingKey(row.Key) {
			continue
		}
		var value any
		if err := json.Unmarshal(row.Value, &value); err != nil {
			return nil, fmt.Errorf("setting: decode value of %q: %w", row.Key, err)
		}
		items = append(items, SettingItem{Key: row.Key, Type: SettingType(row.Type), Value: value})
	}
	return items, nil
}

// epochFromRows 返回行集合中的内部凭证代次，缺失时返回 0。
func epochFromRows(rows []repository.DynamicSettingRow) int64 {
	for _, row := range rows {
		if row.Key != SettingKeyInternalEpoch {
			continue
		}
		var epoch int64
		if err := json.Unmarshal(row.Value, &epoch); err != nil {
			return 0
		}
		return epoch
	}
	return 0
}

// missingRows 计算缺失的默认设置项与内部 epoch 行。
func missingRows(rows []repository.DynamicSettingRow) []repository.DynamicSettingRow {
	have := make(map[string]bool, len(rows))
	for _, row := range rows {
		have[row.Key] = true
	}
	var missing []repository.DynamicSettingRow
	for _, item := range defaultItems() {
		if have[item.Key] {
			continue
		}
		payload, err := json.Marshal(item.Value)
		if err != nil {
			continue
		}
		missing = append(missing, repository.DynamicSettingRow{
			Key: item.Key, Type: string(item.Type), Value: payload, UpdatedBy: 0,
		})
	}
	if !have[SettingKeyInternalEpoch] {
		missing = append(missing, repository.DynamicSettingRow{
			Key: SettingKeyInternalEpoch, Type: string(SettingTypeInteger), Value: []byte(`0`), UpdatedBy: 0,
		})
	}
	return missing
}

// SetCaptchaValidator 安装 CAPTCHA provider 选择校验器。
func (s *Service) SetCaptchaValidator(v CaptchaSelectionValidator) {
	if v != nil {
		s.captchaValidator = v
	}
}

// Get 返回类型化设置与凭证 epoch 的原子快照，
// 首次访问时在短事务内播种缺失的默认项与内部 epoch 行。
func (s *Service) Get(ctx context.Context) (View, error) {
	s.mu.RLock()
	cached := s.cached
	s.mu.RUnlock()
	if cached != nil {
		return View{Settings: cached.settings, Epoch: cached.epoch}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil {
		return View{Settings: s.cached.settings, Epoch: s.cached.epoch}, nil
	}

	rows, err := s.settingsRepo.List(ctx)
	if err != nil {
		return View{}, err
	}
	if len(missingRows(rows)) > 0 {
		if err := s.seedDefaults(ctx); err != nil {
			return View{}, err
		}
		rows, err = s.settingsRepo.List(ctx)
		if err != nil {
			return View{}, err
		}
	}
	current, err := settingsFromRows(rows)
	if err != nil {
		return View{}, err
	}
	v := &view{settings: current, epoch: epochFromRows(rows)}
	s.cached = v
	return View{Settings: v.settings, Epoch: v.epoch}, nil
}

// seedDefaults 在短事务内播种全部缺失的默认项，重复播种由 ON CONFLICT DO NOTHING 兜底。
func (s *Service) seedDefaults(ctx context.Context) error {
	missing := missingRows(nil)
	if len(missing) == 0 {
		return nil
	}
	return s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		return s.settingsRepo.SeedMissing(ctx, missing)
	})
}

// Patch 校验局部输入后把变更合并到当前完整快照验证，再在单个事务内
// upsert 提交项；comment_mode 实际变化时锁定读取并递增内部凭证代次。
// 成功后返回完整的公开设置项列表，响应按 key 升序。
func (s *Service) Patch(ctx context.Context, items []SettingItem, updatedBy int64) ([]SettingItem, error) {
	if err := validatePatch(items); err != nil {
		return nil, err
	}
	err := s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		rows, err := s.settingsRepo.List(ctx)
		if err != nil {
			return err
		}
		if len(missingRows(rows)) > 0 {
			if err := s.settingsRepo.SeedMissing(ctx, missingRows(rows)); err != nil {
				return err
			}
			rows, err = s.settingsRepo.List(ctx)
			if err != nil {
				return err
			}
		}
		current, err := settingsFromRows(rows)
		if err != nil {
			return err
		}
		if err := applyItems(&current, items); err != nil {
			return err
		}
		if err := Validate(current); err != nil {
			return err
		}
		if hasKey(items, SettingKeyCaptchaProvider) {
			if s.captchaValidator == nil {
				return fmt.Errorf("%w: captcha provider selection validator is not configured", domain.ErrCaptchaUnavailable)
			}
			if err := s.captchaValidator.ValidateSelection(ctx, current.CaptchaProvider); err != nil {
				return err
			}
		}

		writes := make([]repository.DynamicSettingRow, 0, len(items)+1)
		for _, item := range items {
			payload, err := json.Marshal(item.Value)
			if err != nil {
				return err
			}
			writes = append(writes, repository.DynamicSettingRow{
				Key: item.Key, Type: string(item.Type), Value: payload, UpdatedBy: updatedBy,
			})
		}
		if hasKey(items, SettingKeyCommentMode) {
			locked, err := s.settingsRepo.LockRows(ctx, []string{SettingKeyCommentMode, SettingKeyInternalEpoch})
			if err != nil {
				return err
			}
			epoch := epochFromRows(locked)
			if modeOf(locked) != itemValue(items, SettingKeyCommentMode) {
				epoch++
				writes = append(writes, repository.DynamicSettingRow{
					Key: SettingKeyInternalEpoch, Type: string(SettingTypeInteger),
					Value: []byte(strconv.FormatInt(epoch, 10)), UpdatedBy: updatedBy,
				})
			}
		}
		return s.settingsRepo.Upsert(ctx, writes)
	})
	if err != nil {
		return nil, err
	}
	s.invalidate()
	return s.PublicItems(ctx)
}

// PublicItems 返回按 key 升序的公开设置项列表。
func (s *Service) PublicItems(ctx context.Context) ([]SettingItem, error) {
	rows, err := s.settingsRepo.List(ctx)
	if err != nil {
		return nil, err
	}
	return publicItemsFromRows(rows)
}

// modeOf 返回锁定行中的评论模式；行缺失时返回空串。
func modeOf(rows []repository.DynamicSettingRow) string {
	for _, row := range rows {
		if row.Key != SettingKeyCommentMode {
			continue
		}
		var mode string
		if err := json.Unmarshal(row.Value, &mode); err != nil {
			return ""
		}
		return mode
	}
	return ""
}

func (s *Service) invalidate() {
	s.Invalidate()
}

// Invalidate 清空进程内设置快照缓存，下次 Get 从数据库重建。
func (s *Service) Invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}

// Package model 持有跨模块共享的 GORM 持久化行。
// 行只在本包声明，供 repository 层做防腐转换；行不得离开 repository 层。
// 各行的 GORM tag 与原实现一致，保证数据库 schema 不变。
package model

import (
	"time"

	"furtalk/internal/domain"
)

// All 按依赖顺序返回全部持久化模型。
// 稳定顺序让 schema 生成保持确定性：它是 Atlas loader（tools/atlas-loader）的
// 期望 schema 来源，也是测试库 AutoMigrate 的模型集合。
func All() []any {
	return []any{
		&User{},
		&PasskeyCredential{},
		&ExternalIdentity{},
		&NotificationPreferences{},
		&Site{},
		&SiteOrigin{},
		&Thread{},
		&Comment{},
		&DynamicSetting{},
		&BootstrapState{},
	}
}

// User 是 users 表的 GORM 行。
// 密码状态直接落在用户行：password_hash 与 password_changed_at 要么同时为空
// （未配置密码登录），要么同时非空（已配置密码），由 CHECK 约束保证。
type User struct {
	ID                 int64              `gorm:"primaryKey;autoIncrement;generated:identity"`
	Email              string             `gorm:"column:email;type:text;not null"`
	EmailNormalized    string             `gorm:"column:email_normalized;type:text;not null;uniqueIndex:uq_users_email_normalized"`
	Nickname           string             `gorm:"column:nickname;type:text;not null"`
	WebsiteURL         *string            `gorm:"column:website_url;type:text"`
	Role               domain.Role        `gorm:"column:role;type:text;not null;default:user;check:ck_users_role,role IN ('admin','user')"`
	Status             domain.UserStatus  `gorm:"column:status;type:text;not null;default:active;check:ck_users_status,status IN ('active','disabled','deleted')"`
	PasswordHash       *string            `gorm:"column:password_hash;type:text;check:ck_users_password_state,(password_hash IS NULL AND password_changed_at IS NULL) OR (password_hash IS NOT NULL AND password_changed_at IS NOT NULL)"`
	PasswordChangedAt  *time.Time         `gorm:"column:password_changed_at;precision:6"`
	SessionVersion     int64              `gorm:"column:session_version;not null;default:1;check:ck_users_session_version,session_version > 0"`
	EmailVerifiedAt    *time.Time         `gorm:"column:email_verified_at"`
	DeletedAt          *time.Time         `gorm:"column:deleted_at;precision:6"`
	StatusBeforeDelete *domain.UserStatus `gorm:"column:status_before_delete;type:text"`
	CreatedAt          time.Time          `gorm:"column:created_at;precision:6;autoCreateTime"`
	UpdatedAt          time.Time          `gorm:"column:updated_at;precision:6;autoUpdateTime"`
}

// ToUser 把持久化行转换为业务用户。
func (r User) ToUser() domain.User {
	return domain.User{
		ID:                 r.ID,
		Email:              r.Email,
		EmailNormalized:    r.EmailNormalized,
		Nickname:           r.Nickname,
		WebsiteURL:         r.WebsiteURL,
		Role:               r.Role,
		Status:             r.Status,
		SessionVersion:     r.SessionVersion,
		EmailVerifiedAt:    r.EmailVerifiedAt,
		CreatedAt:          r.CreatedAt,
		UpdatedAt:          r.UpdatedAt,
		DeletedAt:          r.DeletedAt,
		StatusBeforeDelete: r.StatusBeforeDelete,
	}
}

// ToSite 把持久化行转换为业务站点。
func (r Site) ToSite() domain.Site {
	return domain.Site{
		ID:           r.ID,
		Name:         r.Name,
		CanonicalURL: r.CanonicalURL,
		Status:       r.Status,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}

// PasskeyCredential 是 passkey_credentials 表的 GORM 行。
// public_key 不写显式 type：gorm 对 []byte 默认映射为 SQLite blob / PostgreSQL bytea，
// 显式 type:blob 会让 PostgreSQL 生成无效的 blob 类型。
type PasskeyCredential struct {
	ID              int64      `gorm:"primaryKey;autoIncrement;generated:identity"`
	UserID          int64      `gorm:"column:user_id;not null"`
	CredentialID    string     `gorm:"column:credential_id;type:text;not null;uniqueIndex:uq_passkey_credentials_credential_id"`
	PublicKey       []byte     `gorm:"column:public_key;not null"`
	AttestationType string     `gorm:"column:attestation_type;type:text"`
	Transports      string     `gorm:"column:transports;type:text"`
	SignCount       uint32     `gorm:"column:sign_count;not null;default:0"`
	BackupEligible  bool       `gorm:"column:backup_eligible;not null;default:false"`
	BackupState     bool       `gorm:"column:backup_state;not null;default:false"`
	Name            string     `gorm:"column:name;type:text;not null"`
	CreatedAt       time.Time  `gorm:"column:created_at;precision:6;autoCreateTime"`
	LastUsedAt      *time.Time `gorm:"column:last_used_at;precision:6"`
	User            User       `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// ToPasskeyCredential 把持久化行转换为业务 passkey 凭证。
func (r PasskeyCredential) ToPasskeyCredential() domain.PasskeyCredential {
	return domain.PasskeyCredential{
		ID:              r.ID,
		UserID:          r.UserID,
		CredentialID:    r.CredentialID,
		PublicKey:       r.PublicKey,
		AttestationType: r.AttestationType,
		Transports:      r.Transports,
		SignCount:       r.SignCount,
		BackupEligible:  r.BackupEligible,
		BackupState:     r.BackupState,
		Name:            r.Name,
		CreatedAt:       r.CreatedAt,
		LastUsedAt:      r.LastUsedAt,
	}
}

// ExternalIdentity 是 external_identities 表的 GORM 行。
type ExternalIdentity struct {
	ID              int64      `gorm:"primaryKey;autoIncrement;generated:identity"`
	UserID          int64      `gorm:"column:user_id;not null;uniqueIndex:uq_external_identities_user_provider,priority:1"`
	ProviderKey     string     `gorm:"column:provider_key;type:text;not null;uniqueIndex:uq_external_identities_provider_subject,priority:1;uniqueIndex:uq_external_identities_user_provider,priority:2"`
	ProviderSubject string     `gorm:"column:provider_subject;type:text;not null;uniqueIndex:uq_external_identities_provider_subject,priority:2;uniqueIndex:uq_external_identities_user_provider,priority:3"`
	VerifiedEmail   string     `gorm:"column:verified_email;type:text;not null"`
	CreatedAt       time.Time  `gorm:"column:created_at;precision:6;autoCreateTime"`
	LastLoginAt     *time.Time `gorm:"column:last_login_at;precision:6"`
	User            User       `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// ToExternalIdentity 把持久化行转换为业务外部身份。
func (r ExternalIdentity) ToExternalIdentity() domain.ExternalIdentity {
	return domain.ExternalIdentity{
		ID:              r.ID,
		UserID:          r.UserID,
		ProviderKey:     r.ProviderKey,
		ProviderSubject: r.ProviderSubject,
		VerifiedEmail:   r.VerifiedEmail,
		CreatedAt:       r.CreatedAt,
		LastLoginAt:     r.LastLoginAt,
	}
}

// NotificationPreferences 是 notification_preferences 表的 GORM 行。
type NotificationPreferences struct {
	ID                int64     `gorm:"primaryKey;autoIncrement;generated:identity"`
	UserID            int64     `gorm:"column:user_id;not null;uniqueIndex:uq_notification_preferences_user"`
	ReplyEnabled      bool      `gorm:"column:reply_enabled;not null;default:true"`
	ModerationEnabled bool      `gorm:"column:moderation_enabled;not null;default:true"`
	UpdatedAt         time.Time `gorm:"column:updated_at;precision:6;autoUpdateTime"`
	User              User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// ToNotificationPreferences 把持久化行转换为业务通知偏好。
func (r NotificationPreferences) ToNotificationPreferences() domain.NotificationPreferences {
	return domain.NotificationPreferences{
		ID:                r.ID,
		UserID:            r.UserID,
		ReplyEnabled:      r.ReplyEnabled,
		ModerationEnabled: r.ModerationEnabled,
		UpdatedAt:         r.UpdatedAt,
	}
}

// Site 是 sites 表的 GORM 行。
type Site struct {
	ID           int64             `gorm:"primaryKey;autoIncrement;generated:identity"`
	Name         string            `gorm:"column:name;type:text;not null"`
	CanonicalURL string            `gorm:"column:canonical_url;type:text;not null"`
	Status       domain.SiteStatus `gorm:"column:status;type:text;not null;default:active;check:ck_sites_status,status IN ('active','disabled')"`
	CreatedAt    time.Time         `gorm:"column:created_at;precision:6;autoCreateTime"`
	UpdatedAt    time.Time         `gorm:"column:updated_at;precision:6;autoUpdateTime"`
}

// SiteOrigin 是 site_origins 表的 GORM 行。
type SiteOrigin struct {
	ID        int64     `gorm:"primaryKey;autoIncrement;generated:identity"`
	SiteID    int64     `gorm:"column:site_id;not null;uniqueIndex:uq_site_origins_site_origin,priority:1"`
	Origin    string    `gorm:"column:origin;type:text;not null;uniqueIndex:uq_site_origins_site_origin,priority:2"`
	CreatedAt time.Time `gorm:"column:created_at;precision:6;autoCreateTime"`
	Site      Site      `gorm:"foreignKey:SiteID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// ToOrigin 把持久化行转换为业务 origin 记录。
func (r SiteOrigin) ToOrigin() domain.Origin {
	return domain.Origin{ID: r.ID, Origin: r.Origin}
}

// Thread 是 threads 表的 GORM 行。
type Thread struct {
	ID              int64     `gorm:"primaryKey;autoIncrement;generated:identity;uniqueIndex:uq_threads_site_id,priority:2"`
	SiteID          int64     `gorm:"column:site_id;not null;uniqueIndex:uq_threads_site_id,priority:1;uniqueIndex:uq_threads_site_page,priority:1"`
	PageKey         string    `gorm:"column:page_key;type:text;not null;uniqueIndex:uq_threads_site_page,priority:2"`
	PageURL         *string   `gorm:"column:page_url;type:text"`
	PageTitle       *string   `gorm:"column:page_title;type:text"`
	CommentsEnabled bool      `gorm:"column:comments_enabled;not null;default:true"`
	CreatedAt       time.Time `gorm:"column:created_at;precision:6;autoCreateTime"`
	UpdatedAt       time.Time `gorm:"column:updated_at;precision:6;autoUpdateTime"`
	Site            Site      `gorm:"foreignKey:SiteID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// ToThread 把持久化行转换为业务线程。
func (r Thread) ToThread() domain.Thread {
	return domain.Thread{
		ID:              r.ID,
		SiteID:          r.SiteID,
		PageKey:         r.PageKey,
		PageURL:         r.PageURL,
		PageTitle:       r.PageTitle,
		CommentsEnabled: r.CommentsEnabled,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

// Comment 是 comments 表的 GORM 行。
// 复合外键 (site_id, thread_id) / (site_id, parent_id) / (site_id, root_id)
// 对 UNIQUE (site_id, id) 的约束语义保持不变。
type Comment struct {
	ID                 int64                 `gorm:"primaryKey;autoIncrement;generated:identity;uniqueIndex:uq_comments_site_id,priority:2;index:idx_comments_public,priority:4;index:idx_comments_site_status,priority:4;index:idx_comments_user,priority:3;index:idx_comments_site_parent,priority:4;index:idx_comments_site_root,priority:4"`
	SiteID             int64                 `gorm:"column:site_id;not null;uniqueIndex:uq_comments_site_id,priority:1;index:idx_comments_public,priority:1;index:idx_comments_site_status,priority:1;index:idx_comments_site_parent,priority:1;index:idx_comments_site_root,priority:1"`
	ThreadID           int64                 `gorm:"column:thread_id;not null;index:idx_comments_public,priority:2"`
	UserID             int64                 `gorm:"column:user_id;not null;index:idx_comments_user,priority:1"`
	ParentID           *int64                `gorm:"column:parent_id;index:idx_comments_site_parent,priority:2"`
	RootID             *int64                `gorm:"column:root_id;index:idx_comments_site_root,priority:2"`
	ReplyToUserID      *int64                `gorm:"column:reply_to_user_id;index:idx_comments_reply_to"`
	Depth              int                   `gorm:"column:depth;not null;default:0;check:ck_comments_depth,depth >= 0"`
	BodyMarkdown       string                `gorm:"column:body_markdown;type:text;not null"`
	Status             domain.CommentStatus  `gorm:"column:status;type:text;not null;default:pending;check:ck_comments_status,status IN ('pending','published','spam','deleted');index:idx_comments_site_status,priority:2"`
	StatusBeforeDelete *domain.CommentStatus `gorm:"column:status_before_delete;type:text"`
	IPMode             domain.PrivacyMode    `gorm:"column:ip_mode;type:text;not null;default:none;check:ck_comments_ip_mode,ip_mode IN ('none','coarse','full')"`
	IPValue            *string               `gorm:"column:ip_value;type:text"`
	UAMode             domain.PrivacyMode    `gorm:"column:ua_mode;type:text;not null;default:none;check:ck_comments_ua_mode,ua_mode IN ('none','coarse','full')"`
	UARaw              *string               `gorm:"column:ua_raw;type:text"`
	UABrowser          *string               `gorm:"column:ua_browser;type:text"`
	UAOS               *string               `gorm:"column:ua_os;type:text"`
	UADevice           *string               `gorm:"column:ua_device;type:text"`
	CreatedAt          time.Time             `gorm:"column:created_at;precision:6;autoCreateTime;index:idx_comments_public,priority:3;index:idx_comments_site_status,priority:3;index:idx_comments_user,priority:2;index:idx_comments_site_parent,priority:3;index:idx_comments_site_root,priority:3"`
	UpdatedAt          time.Time             `gorm:"column:updated_at;precision:6;autoUpdateTime"`
	PublishedAt        *time.Time            `gorm:"column:published_at;precision:6"`
	DeletedAt          *time.Time            `gorm:"column:deleted_at;precision:6"`
	Site               Site                  `gorm:"foreignKey:SiteID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Thread             Thread                `gorm:"foreignKey:SiteID,ThreadID;references:SiteID,ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	User               User                  `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Parent             *Comment              `gorm:"foreignKey:SiteID,ParentID;references:SiteID,ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Root               *Comment              `gorm:"foreignKey:SiteID,RootID;references:SiteID,ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	ReplyToUser        *User                 `gorm:"foreignKey:ReplyToUserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

// ToComment 把持久化行转换为业务评论。
func (r Comment) ToComment() domain.Comment {
	return domain.Comment{
		ID:                 r.ID,
		SiteID:             r.SiteID,
		ThreadID:           r.ThreadID,
		UserID:             r.UserID,
		ParentID:           r.ParentID,
		RootID:             r.RootID,
		ReplyToUserID:      r.ReplyToUserID,
		Depth:              r.Depth,
		BodyMarkdown:       r.BodyMarkdown,
		Status:             r.Status,
		StatusBeforeDelete: r.StatusBeforeDelete,
		IPMode:             r.IPMode,
		IPValue:            r.IPValue,
		UAMode:             r.UAMode,
		UARaw:              r.UARaw,
		UABrowser:          r.UABrowser,
		UAOS:               r.UAOS,
		UADevice:           r.UADevice,
		CreatedAt:          r.CreatedAt,
		UpdatedAt:          r.UpdatedAt,
		PublishedAt:        r.PublishedAt,
		DeletedAt:          r.DeletedAt,
	}
}

// DynamicSetting 是 dynamic_settings 表的 GORM 行。
type DynamicSetting struct {
	ID        int64     `gorm:"primaryKey;autoIncrement;generated:identity"`
	Key       string    `gorm:"column:key;type:text;not null;uniqueIndex:uq_dynamic_settings_key"`
	Type      string    `gorm:"column:type;type:text;not null;check:ck_dynamic_settings_type,type IN ('string','integer','boolean','json')"`
	Value     []byte    `gorm:"column:value;type:json;not null"`
	UpdatedBy int64     `gorm:"column:updated_by;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;precision:6;autoUpdateTime"`
}

// BootstrapState 是 bootstrap_states 单例表的 GORM 行。
type BootstrapState struct {
	ID            int64     `gorm:"primaryKey;autoIncrement;generated:identity"`
	SingletonKey  int       `gorm:"column:singleton_key;not null;default:1;uniqueIndex:uq_bootstrap_state_singleton;check:ck_bootstrap_state_singleton,singleton_key = 1"`
	InitializedAt time.Time `gorm:"column:initialized_at;precision:6;not null"`
	AdminUserID   int64     `gorm:"column:admin_user_id;not null"`
}

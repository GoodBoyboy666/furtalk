-- Create "users" table
CREATE TABLE `users` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `email` text NOT NULL, `email_normalized` text NOT NULL, `nickname` text NOT NULL, `website_url` text NULL, `role` text NOT NULL DEFAULT 'user', `status` text NOT NULL DEFAULT 'active', `password_hash` text NULL, `password_changed_at` datetime NULL, `session_version` integer NOT NULL DEFAULT 1, `email_verified_at` datetime NULL, `deleted_at` datetime NULL, `status_before_delete` text NULL, `created_at` datetime NULL, `updated_at` datetime NULL, CONSTRAINT `ck_users_role` CHECK (role IN ('admin','user')), CONSTRAINT `ck_users_session_version` CHECK (session_version > 0), CONSTRAINT `ck_users_status` CHECK (status IN ('active','disabled','deleted')), CONSTRAINT `ck_users_password_state` CHECK ((password_hash IS NULL AND password_changed_at IS NULL) OR (password_hash IS NOT NULL AND password_changed_at IS NOT NULL)));
-- Create index "uq_users_email_normalized" to table: "users"
CREATE UNIQUE INDEX `uq_users_email_normalized` ON `users` (`email_normalized`);
-- Create "passkey_credentials" table
CREATE TABLE `passkey_credentials` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `user_id` integer NOT NULL, `credential_id` text NOT NULL, `public_key` blob NOT NULL, `attestation_type` text NULL, `transports` text NULL, `sign_count` integer NOT NULL DEFAULT 0, `backup_eligible` numeric NOT NULL DEFAULT false, `backup_state` numeric NOT NULL DEFAULT false, `name` text NOT NULL, `created_at` datetime NULL, `last_used_at` datetime NULL, CONSTRAINT `fk_passkey_credentials_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON UPDATE CASCADE ON DELETE CASCADE);
-- Create index "uq_passkey_credentials_credential_id" to table: "passkey_credentials"
CREATE UNIQUE INDEX `uq_passkey_credentials_credential_id` ON `passkey_credentials` (`credential_id`);
-- Create "external_identities" table
CREATE TABLE `external_identities` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `user_id` integer NOT NULL, `provider_key` text NOT NULL, `provider_subject` text NOT NULL, `verified_email` text NOT NULL, `created_at` datetime NULL, `last_login_at` datetime NULL, CONSTRAINT `fk_external_identities_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON UPDATE CASCADE ON DELETE CASCADE);
-- Create index "uq_external_identities_provider_subject" to table: "external_identities"
CREATE UNIQUE INDEX `uq_external_identities_provider_subject` ON `external_identities` (`provider_key`, `provider_subject`);
-- Create index "uq_external_identities_user_provider" to table: "external_identities"
CREATE UNIQUE INDEX `uq_external_identities_user_provider` ON `external_identities` (`user_id`, `provider_key`, `provider_subject`);
-- Create "notification_preferences" table
CREATE TABLE `notification_preferences` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `user_id` integer NOT NULL, `reply_enabled` numeric NOT NULL DEFAULT true, `moderation_enabled` numeric NOT NULL DEFAULT true, `updated_at` datetime NULL, CONSTRAINT `fk_notification_preferences_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON UPDATE CASCADE ON DELETE CASCADE);
-- Create index "uq_notification_preferences_user" to table: "notification_preferences"
CREATE UNIQUE INDEX `uq_notification_preferences_user` ON `notification_preferences` (`user_id`);
-- Create "sites" table
CREATE TABLE `sites` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `name` text NOT NULL, `canonical_url` text NOT NULL, `status` text NOT NULL DEFAULT 'active', `created_at` datetime NULL, `updated_at` datetime NULL, CONSTRAINT `ck_sites_status` CHECK (status IN ('active','disabled')));
-- Create "site_origins" table
CREATE TABLE `site_origins` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `site_id` integer NOT NULL, `origin` text NOT NULL, `created_at` datetime NULL, CONSTRAINT `fk_site_origins_site` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON UPDATE CASCADE ON DELETE CASCADE);
-- Create index "uq_site_origins_site_origin" to table: "site_origins"
CREATE UNIQUE INDEX `uq_site_origins_site_origin` ON `site_origins` (`site_id`, `origin`);
-- Create "threads" table
CREATE TABLE `threads` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `site_id` integer NOT NULL, `page_key` text NOT NULL, `page_url` text NULL, `page_title` text NULL, `comments_enabled` numeric NOT NULL DEFAULT true, `created_at` datetime NULL, `updated_at` datetime NULL, CONSTRAINT `fk_threads_site` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON UPDATE CASCADE ON DELETE CASCADE);
-- Create index "uq_threads_site_page" to table: "threads"
CREATE UNIQUE INDEX `uq_threads_site_page` ON `threads` (`site_id`, `page_key`);
-- Create index "uq_threads_site_id" to table: "threads"
CREATE UNIQUE INDEX `uq_threads_site_id` ON `threads` (`site_id`, `id`);
-- Create "comments" table
CREATE TABLE `comments` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `site_id` integer NOT NULL, `thread_id` integer NOT NULL, `user_id` integer NOT NULL, `parent_id` integer NULL, `root_id` integer NULL, `reply_to_user_id` integer NULL, `depth` integer NOT NULL DEFAULT 0, `body_markdown` text NOT NULL, `status` text NOT NULL DEFAULT 'pending', `status_before_delete` text NULL, `ip_mode` text NOT NULL DEFAULT 'none', `ip_value` text NULL, `ua_mode` text NOT NULL DEFAULT 'none', `ua_raw` text NULL, `ua_browser` text NULL, `ua_os` text NULL, `ua_device` text NULL, `created_at` datetime NULL, `updated_at` datetime NULL, `published_at` datetime NULL, `deleted_at` datetime NULL, CONSTRAINT `fk_comments_thread` FOREIGN KEY (`site_id`, `thread_id`) REFERENCES `threads` (`site_id`, `id`) ON UPDATE CASCADE ON DELETE CASCADE, CONSTRAINT `fk_comments_site` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON UPDATE CASCADE ON DELETE CASCADE, CONSTRAINT `fk_comments_reply_to_user` FOREIGN KEY (`reply_to_user_id`) REFERENCES `users` (`id`) ON UPDATE CASCADE ON DELETE SET NULL, CONSTRAINT `fk_comments_root` FOREIGN KEY (`site_id`, `root_id`) REFERENCES `comments` (`site_id`, `id`) ON UPDATE CASCADE ON DELETE CASCADE, CONSTRAINT `fk_comments_parent` FOREIGN KEY (`site_id`, `parent_id`) REFERENCES `comments` (`site_id`, `id`) ON UPDATE CASCADE ON DELETE CASCADE, CONSTRAINT `fk_comments_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON UPDATE CASCADE ON DELETE CASCADE, CONSTRAINT `ck_comments_status` CHECK (status IN ('pending','published','spam','deleted')), CONSTRAINT `ck_comments_ip_mode` CHECK (ip_mode IN ('none','coarse','full')), CONSTRAINT `ck_comments_depth` CHECK (depth >= 0), CONSTRAINT `ck_comments_ua_mode` CHECK (ua_mode IN ('none','coarse','full')));
-- Create index "idx_comments_reply_to" to table: "comments"
CREATE INDEX `idx_comments_reply_to` ON `comments` (`reply_to_user_id`);
-- Create index "idx_comments_site_root" to table: "comments"
CREATE INDEX `idx_comments_site_root` ON `comments` (`site_id`, `root_id`, `created_at`, `id`);
-- Create index "idx_comments_site_parent" to table: "comments"
CREATE INDEX `idx_comments_site_parent` ON `comments` (`site_id`, `parent_id`, `created_at`, `id`);
-- Create index "idx_comments_user" to table: "comments"
CREATE INDEX `idx_comments_user` ON `comments` (`user_id`, `created_at`, `id`);
-- Create index "idx_comments_site_status" to table: "comments"
CREATE INDEX `idx_comments_site_status` ON `comments` (`site_id`, `status`, `created_at`, `id`);
-- Create index "idx_comments_public" to table: "comments"
CREATE INDEX `idx_comments_public` ON `comments` (`site_id`, `thread_id`, `created_at`, `id`);
-- Create index "uq_comments_site_id" to table: "comments"
CREATE UNIQUE INDEX `uq_comments_site_id` ON `comments` (`site_id`, `id`);
-- Create "dynamic_settings" table
CREATE TABLE `dynamic_settings` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `key` text NOT NULL, `type` text NOT NULL, `value` json NOT NULL, `updated_by` integer NOT NULL, `updated_at` datetime NULL, CONSTRAINT `ck_dynamic_settings_type` CHECK (type IN ('string','integer','boolean','json')));
-- Create index "uq_dynamic_settings_key" to table: "dynamic_settings"
CREATE UNIQUE INDEX `uq_dynamic_settings_key` ON `dynamic_settings` (`key`);
-- Create "bootstrap_states" table
CREATE TABLE `bootstrap_states` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `singleton_key` integer NOT NULL DEFAULT 1, `initialized_at` datetime NOT NULL, `admin_user_id` integer NOT NULL, CONSTRAINT `ck_bootstrap_state_singleton` CHECK (singleton_key = 1));
-- Create index "uq_bootstrap_state_singleton" to table: "bootstrap_states"
CREATE UNIQUE INDEX `uq_bootstrap_state_singleton` ON `bootstrap_states` (`singleton_key`);

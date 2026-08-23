-- Add the persistent pinned bit. SQLite evaluates the CHECK for existing rows
-- while adding the column; historical comments all receive the false default.
ALTER TABLE `comments` ADD COLUMN `is_pinned` numeric NOT NULL DEFAULT false CONSTRAINT `ck_comments_pinned_root` CHECK (NOT is_pinned OR (parent_id IS NULL AND root_id IS NULL AND depth = 0));
-- Include the pinned group before the public directional keyset columns.
DROP INDEX `idx_comments_public`;
CREATE INDEX `idx_comments_public` ON `comments` (`site_id`, `thread_id`, `is_pinned`, `created_at`, `id`);

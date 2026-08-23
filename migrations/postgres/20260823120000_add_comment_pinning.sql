-- Add the persistent pinned bit. Existing comments remain unpinned.
ALTER TABLE "comments" ADD COLUMN "is_pinned" boolean NOT NULL DEFAULT false;
ALTER TABLE "comments" ADD CONSTRAINT "ck_comments_pinned_root" CHECK (NOT is_pinned OR (parent_id IS NULL AND root_id IS NULL AND depth = 0));
-- Include the pinned group before the public directional keyset columns.
DROP INDEX "idx_comments_public";
CREATE INDEX "idx_comments_public" ON "comments" ("site_id", "thread_id", "is_pinned", "created_at", "id");

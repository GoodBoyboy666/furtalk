-- Create "comment_likes" table
CREATE TABLE `comment_likes` (`id` integer NULL PRIMARY KEY AUTOINCREMENT, `site_id` integer NOT NULL, `comment_id` integer NOT NULL, `user_id` integer NOT NULL, `created_at` datetime NULL, CONSTRAINT `fk_comment_likes_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON UPDATE CASCADE ON DELETE CASCADE, CONSTRAINT `fk_comment_likes_comment` FOREIGN KEY (`site_id`, `comment_id`) REFERENCES `comments` (`site_id`, `id`) ON UPDATE CASCADE ON DELETE CASCADE, CONSTRAINT `fk_comment_likes_site` FOREIGN KEY (`site_id`) REFERENCES `sites` (`id`) ON UPDATE CASCADE ON DELETE CASCADE);
-- Create index "idx_comment_likes_user" to table: "comment_likes"
CREATE INDEX `idx_comment_likes_user` ON `comment_likes` (`user_id`);
-- Create index "idx_comment_likes_site_comment" to table: "comment_likes"
CREATE INDEX `idx_comment_likes_site_comment` ON `comment_likes` (`site_id`, `comment_id`);
-- Create index "uq_comment_likes_site_comment_user" to table: "comment_likes"
CREATE UNIQUE INDEX `uq_comment_likes_site_comment_user` ON `comment_likes` (`site_id`, `comment_id`, `user_id`);

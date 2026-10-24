package repository

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// seedSplitReply 插入保留原始层级与回复作者的测试回复。
func seedSplitReply(t *testing.T, db *gorm.DB, siteID, threadID, parentID, rootID int64, depth int, status domain.CommentStatus, at time.Time) int64 {
	t.Helper()
	parent, err := NewCommentRepo(db).FindBySiteAndID(context.Background(), siteID, parentID)
	if err != nil {
		t.Fatal(err)
	}
	row := &domain.Comment{
		SiteID: siteID, ThreadID: threadID, UserID: parent.UserID, ParentID: &parentID, RootID: &rootID, Depth: depth,
		ReplyToUserID: &parent.UserID, BodyMarkdown: "split reply", Status: status,
		IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone, CreatedAt: at, UpdatedAt: at,
	}
	if status == domain.CommentStatusPublished {
		row.PublishedAt = &at
	}
	if err := NewCommentRepo(db).Create(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	return row.ID
}

// TestPublicRootsBoundedSorting 验证根排序、置顶、根自身热度及逐根分页。
func TestPublicRootsBoundedSorting(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	ctx := context.Background()
	repo := NewCommentRepo(db)
	if _, err := repo.SetPinned(ctx, siteID, ids["a"], true); err != nil {
		t.Fatal(err)
	}
	// 未置顶根也共享时间戳，确保新根查询本身覆盖 ID 决胜边界。
	c, err := repo.FindBySiteAndID(ctx, siteID, ids["c"])
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.Comment{}).Where("site_id = ? AND id = ?", siteID, ids["d"]).Update("created_at", c.CreatedAt).Error; err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 12, 12, 1, 0, 0, time.UTC)
	replyID := seedSplitReply(t, db, siteID, threadID, ids["b"], ids["b"], 1, domain.CommentStatusPublished, base)
	if err := db.Create(&model.CommentLike{SiteID: siteID, CommentID: ids["c"], UserID: 1}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.CommentLike{SiteID: siteID, CommentID: replyID, UserID: 1}).Error; err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		sort domain.CommentSort
		want []int64
	}{
		{domain.CommentSortAsc, []int64{ids["a"], ids["b"], ids["c"], ids["d"]}},
		{domain.CommentSortDesc, []int64{ids["a"], ids["d"], ids["c"], ids["b"]}},
		{domain.CommentSortHot, []int64{ids["a"], ids["c"], ids["d"], ids["b"]}},
	} {
		t.Run(string(tc.sort), func(t *testing.T) {
			var cursor *domain.Cursor
			var got []int64
			for page := 0; page < 10; page++ {
				rows, err := repo.ListPublicRoots(ctx, siteID, threadID, tc.sort, cursor, 1, nil)
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) == 0 {
					break
				}
				if len(rows) != 1 || rows[0].ParentID != nil || rows[0].RootID != nil || rows[0].ID == replyID {
					t.Fatalf("root quota/relationship: %+v", rows)
				}
				row := rows[0]
				if row.HasReplies != (row.ID == ids["b"]) || row.LikedByMe {
					t.Fatalf("root reply/viewer flag: %+v", row)
				}
				got = append(got, row.ID)
				cursor = &domain.Cursor{Pinned: row.IsPinned, LikeCount: row.LikeCount, CreatedAt: row.CreatedAt, ID: row.ID}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("root IDs=%v, want %v", got, tc.want)
			}
		})
	}
	viewer := int64(1)
	rows, err := repo.ListPublicRoots(ctx, siteID, threadID, domain.CommentSortHot, nil, 50, &viewer)
	if err != nil || len(rows) != 4 || !rows[1].LikedByMe || rows[1].LikeCount != 1 {
		t.Fatalf("root viewer state rows=%+v, err=%v", rows, err)
	}
	// 原接口仍按混合行分页，回复的较新时间继续参与旧排序。
	legacy, err := repo.ListPublic(ctx, siteID, threadID, domain.CommentSortDesc, nil, 2, nil)
	if err != nil || len(legacy) != 2 || legacy[0].ID != ids["a"] || legacy[1].ID != replyID {
		t.Fatalf("legacy flat behavior rows=%+v err=%v", legacy, err)
	}
}

// TestPublicRepliesProjectionAndScope 验证隐藏祖先投影、独立回复分页与空根校验。
func TestPublicRepliesProjectionAndScope(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 12, 1, 0, 0, time.UTC)
	first := seedSplitReply(t, db, siteID, threadID, ids["a"], ids["a"], 1, domain.CommentStatusPublished, base)
	hidden := seedSplitReply(t, db, siteID, threadID, first, ids["a"], 2, domain.CommentStatusSpam, base)
	deep := seedSplitReply(t, db, siteID, threadID, hidden, ids["a"], 3, domain.CommentStatusPublished, base)
	last := seedSplitReply(t, db, siteID, threadID, ids["a"], ids["a"], 1, domain.CommentStatusPublished, base.Add(time.Second))
	if err := db.Create(&model.CommentLike{SiteID: siteID, CommentID: deep, UserID: 1}).Error; err != nil {
		t.Fatal(err)
	}
	viewer := int64(1)
	var cursor *domain.Cursor
	var got []int64
	for page := 0; page < 5; page++ {
		rows, err := repo.ListPublicReplies(ctx, siteID, threadID, ids["a"], cursor, 1, &viewer)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		if len(rows) != 1 || rows[0].RootID == nil || *rows[0].RootID != ids["a"] {
			t.Fatalf("reply quota/relationship: %+v", rows)
		}
		row := rows[0]
		if row.ID == deep && (row.ParentID == nil || *row.ParentID != first || row.Depth != 3 || row.ReplyToUserID == nil || row.ReplyToNickname == nil || !row.LikedByMe || row.LikeCount != 1) {
			t.Fatalf("hidden bridge/depth/attribution/viewer: %+v", row)
		}
		got = append(got, row.ID)
		cursor = &domain.Cursor{CreatedAt: row.CreatedAt, ID: row.ID}
	}
	if !reflect.DeepEqual(got, []int64{first, deep, last}) {
		t.Fatalf("reply IDs=%v", got)
	}
	stored, err := repo.FindBySiteAndID(ctx, siteID, deep)
	if err != nil || stored.ParentID == nil || *stored.ParentID != hidden || stored.Depth != 3 {
		t.Fatalf("stored relationship changed: %+v err=%v", stored, err)
	}
	empty, err := repo.ListPublicReplies(ctx, siteID, threadID, ids["b"], nil, 10, &viewer)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("valid empty root rows=%v err=%v", empty, err)
	}
	otherThread, err := NewThreadRepo(db).ResolveOrCreate(ctx, siteID, "other-page", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		site, thread, root int64
	}{
		{"missing", siteID, threadID, 999999},
		{"hidden", siteID, threadID, hidden},
		{"nonroot", siteID, threadID, first},
		{"wrong-thread", siteID, otherThread.ID, ids["a"]},
		{"wrong-site", siteID + 1, threadID, ids["a"]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := repo.ListPublicReplies(ctx, tc.site, tc.thread, tc.root, nil, 10, nil); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("unavailable root err=%v", err)
			}
		})
	}
}

// TestPublicPagesPromotedRoots 验证非零原始深度的可见根与其后代。
func TestPublicPagesPromotedRoots(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 12, 1, 0, 0, time.UTC)
	// 隐藏的原始根可保留历史置顶状态，但其可见后代自身没有置顶。
	if err := db.Model(&model.Comment{}).Where("site_id = ? AND id = ?", siteID, ids["pending"]).Update("is_pinned", true).Error; err != nil {
		t.Fatal(err)
	}
	hidden := seedSplitReply(t, db, siteID, threadID, ids["pending"], ids["pending"], 1, domain.CommentStatusDeleted, base)
	promoted := seedSplitReply(t, db, siteID, threadID, hidden, ids["pending"], 2, domain.CommentStatusPublished, base)
	child := seedSplitReply(t, db, siteID, threadID, promoted, ids["pending"], 3, domain.CommentStatusPublished, base.Add(time.Second))
	rows, err := repo.ListPublicRoots(ctx, siteID, threadID, domain.CommentSortDesc, nil, 50, nil)
	if err != nil || len(rows) != 5 || rows[0].ID != promoted || rows[0].Depth != 2 || rows[0].ParentID != nil || rows[0].RootID != nil || rows[0].IsPinned || !rows[0].HasReplies {
		t.Fatalf("promoted roots=%+v err=%v", rows, err)
	}
	replies, err := repo.ListPublicReplies(ctx, siteID, threadID, promoted, nil, 10, nil)
	if err != nil || len(replies) != 1 || replies[0].ID != child || replies[0].RootID == nil || *replies[0].RootID != promoted || replies[0].Depth != 3 {
		t.Fatalf("promoted replies=%+v err=%v", replies, err)
	}
}

// TestPublicPagesAmbientTransaction 验证新增读取使用调用方事务句柄。
func TestPublicPagesAmbientTransaction(t *testing.T) {
	db := newSortTestDB(t)
	siteID, threadID, ids := seedSortFixture(t, db)
	repo := NewCommentRepo(db)
	err := gormtx.NewRunner(db).RunInTx(context.Background(), func(ctx context.Context) error {
		parent, err := repo.FindBySiteAndID(ctx, siteID, ids["a"])
		if err != nil {
			return err
		}
		rootID := parent.ID
		row := &domain.Comment{SiteID: siteID, ThreadID: threadID, UserID: parent.UserID, ParentID: &rootID, RootID: &rootID, Depth: 1,
			BodyMarkdown: "transaction reply", Status: domain.CommentStatusPublished, IPMode: domain.PrivacyModeNone, UAMode: domain.PrivacyModeNone,
			CreatedAt: time.Now().UTC().Truncate(time.Microsecond), UpdatedAt: time.Now().UTC().Truncate(time.Microsecond)}
		if err := repo.Create(ctx, row); err != nil {
			return err
		}
		roots, err := repo.ListPublicRoots(ctx, siteID, threadID, domain.CommentSortAsc, nil, 10, nil)
		if err != nil || len(roots) != 4 || !roots[0].HasReplies {
			t.Fatalf("transaction roots=%+v err=%v", roots, err)
		}
		replies, err := repo.ListPublicReplies(ctx, siteID, threadID, rootID, nil, 10, nil)
		if err != nil || len(replies) != 1 || replies[0].ID != row.ID {
			t.Fatalf("transaction replies=%+v err=%v", replies, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPublicPagesPostgresSQL 验证两种新增查询的 PostgreSQL 方言、锚点类型和作用域。
func TestPublicPagesPostgresSQL(t *testing.T) {
	sqliteDB := newSortTestDB(t)
	sqlDB, err := sqliteDB.DB()
	if err != nil {
		t.Fatal(err)
	}
	capture := &publicSQLCapture{Interface: logger.Default}
	pg, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{DryRun: true, Logger: capture})
	if err != nil {
		t.Fatal(err)
	}
	repo := NewCommentRepo(pg)
	viewer := int64(44)
	at := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		call func()
		want []string
	}{
		{"roots", func() {
			_, _ = repo.ListPublicRoots(context.Background(), 11, 22, domain.CommentSortHot, &domain.Cursor{Pinned: true, LikeCount: 5, CreatedAt: at, ID: 33}, 3, &viewer)
		},
			[]string{"visible.vis_parent_id IS NULL", "roots.site_id = 11 AND roots.thread_id = 22", "roots.like_count < 5", "ORDER BY CASE WHEN roots.is_pinned THEN 1 ELSE 0 END DESC", "cl2.user_id = 44", "LIMIT 3", "AS has_replies"}},
		{"replies", func() {
			_, _ = repo.ListPublicReplies(context.Background(), 11, 22, 33, &domain.Cursor{CreatedAt: at, ID: 55}, 3, &viewer)
		},
			[]string{"site_id = 11 AND thread_id = 22 AND id = 33", "vis_parent_id IS NULL", "vis_root_id = (SELECT id FROM requested_root)", "visible.id > 55", "LEFT JOIN reply_page", "LEFT JOIN users", "AS requested_root_id", "cl2.user_id = 44", "ORDER BY visible.created_at ASC, visible.id ASC LIMIT 3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture.sql = ""
			tc.call()
			for _, column := range []string{"vis_parent_id", "vis_root_id"} {
				if strings.Count(capture.sql, "CAST(NULL AS BIGINT) AS "+column) != 1 || strings.Contains(capture.sql, "NULL AS "+column) {
					t.Fatalf("invalid recursive anchor: %s", capture.sql)
				}
			}
			for _, fragment := range tc.want {
				if !strings.Contains(capture.sql, fragment) {
					t.Fatalf("missing SQL %q: %s", fragment, capture.sql)
				}
			}
		})
	}
}

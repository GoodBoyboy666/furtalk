package comment

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/repository"
	"furtalk/internal/repository/model"
	"furtalk/internal/service/identity"
	"gorm.io/gorm"
)

// TestCreateReplyRejectsHiddenParents ensures both public reply entry points
// enforce the same status contract and never insert a child of a hidden row.
func TestCreateReplyRejectsHiddenParents(t *testing.T) {
	states := []struct {
		name   string
		status domain.CommentStatus
		want   error
	}{
		{name: "pending", status: domain.CommentStatusPending, want: domain.ErrConflict},
		{name: "spam", status: domain.CommentStatusSpam, want: domain.ErrConflict},
		{name: "deleted", status: domain.CommentStatusDeleted, want: domain.ErrParentDeleted},
	}
	for _, tc := range states {
		t.Run("first-party/"+tc.name, func(t *testing.T) {
			db := newReplyTargetTestDB(t)
			fx := seedReplyTargetFixture(t, db)
			markReplyParent(t, db, fx.SiteID, fx.ParentID, tc.status)
			before := commentCount(t, db)
			_, err := replyTargetService(db).CreateReplyFirstParty(context.Background(), fx.ReplyUser, domain.RoleUser, fx.ParentID, "reply", "", nil, "")
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if got := commentCount(t, db); got != before {
				t.Fatalf("comment count = %d, want unchanged %d", got, before)
			}
		})

		t.Run("widget/"+tc.name, func(t *testing.T) {
			db := newReplyTargetTestDB(t)
			fx := seedReplyTargetFixture(t, db)
			markReplyParent(t, db, fx.SiteID, fx.ParentID, tc.status)
			before := commentCount(t, db)
			_, err := widgetReplyTargetService(db).Create(context.Background(), CreateInput{
				SiteID: fx.SiteID, PageKey: "page-key", ParentID: &fx.ParentID,
				BodyMarkdown: "reply", Origin: "https://example.com",
				Email: fx.ReplyEmail, Nickname: fx.ReplyNick,
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if got := commentCount(t, db); got != before {
				t.Fatalf("comment count = %d, want unchanged %d", got, before)
			}
		})
	}
}

// TestCreateReplyUsesTransactionTimeParentStatus closes the first-party
// pre-check race: a parent becomes hidden during spam evaluation, after the
// early read but before the insert transaction reads it authoritatively.
func TestCreateReplyUsesTransactionTimeParentStatus(t *testing.T) {
	db := newReplyTargetTestDB(t)
	fx := seedReplyTargetFixture(t, db)
	svc := replyTargetService(db)
	svc.spam = newGateway(&transitionParentTransport{db: db, siteID: fx.SiteID, parentID: fx.ParentID}, SpamProviderConfig{
		ProviderKey: "spam.akismet", Enabled: true, Configured: true, Action: "pending", APIKey: "key",
	})
	if _, err := svc.CreateReplyFirstParty(context.Background(), fx.ReplyUser, domain.RoleUser, fx.ParentID, "reply", "", nil, ""); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
	if got := commentCount(t, db); got != 1 {
		t.Fatalf("comment count = %d, want only parent", got)
	}
}

func markReplyParent(t *testing.T, db *gorm.DB, siteID, id int64, status domain.CommentStatus) {
	t.Helper()
	commentRepo := repository.NewCommentRepo(db)
	if status == domain.CommentStatusDeleted {
		before := domain.CommentStatusPublished
		deletedAt := time.Now().UTC()
		if err := commentRepo.UpdateStatus(context.Background(), siteID, id, status, &before, nil, &deletedAt); err != nil {
			t.Fatalf("mark parent deleted: %v", err)
		}
		return
	}
	if err := commentRepo.UpdateStatus(context.Background(), siteID, id, status, nil, nil, nil); err != nil {
		t.Fatalf("mark parent %s: %v", status, err)
	}
}

type transitionParentTransport struct {
	db       *gorm.DB
	siteID   int64
	parentID int64
}

func (t *transitionParentTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if err := repository.NewCommentRepo(t.db).UpdateStatus(context.Background(), t.siteID, t.parentID, domain.CommentStatusPending, nil, nil, nil); err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("false")),
	}, nil
}

func commentCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var count int64
	if err := db.Model(&model.Comment{}).Count(&count).Error; err != nil {
		t.Fatalf("count comments: %v", err)
	}
	return count
}

// widgetReplyTargetService creates the anonymous Widget path used by the
// status tests while keeping production composition unchanged.
func widgetReplyTargetService(db *gorm.DB) *Service {
	return &Service{
		txRunner: gormtx.NewRunner(db),
		threads:  repository.NewThreadRepo(db),
		comments: repository.NewCommentRepo(db),
		sites:    repository.NewSiteRepo(db),
		users:    repository.NewUserRepo(db),
		settings: &staticCommentPolicyReader{policy: domain.CommentPolicy{
			Mode: domain.CommentModeAnonymous, Moderation: domain.ModerationDirect,
			UserDeleteMode: domain.UserDeleteModeSoft, MaxReplyDepth: 5,
			CaptchaPolicy: map[string]bool{}, GravatarBaseURL: "https://www.gravatar.com/avatar",
			Privacy:     domain.PrivacyPolicy{IPMode: string(domain.PrivacyModeNone), UAMode: string(domain.PrivacyModeNone)},
			CommentSort: string(domain.CommentSortAsc),
		}},
		captcha: &replyCaptchaVerifier{},
		userW: identity.NewService(identity.Dependencies{
			TxRunner: gormtx.NewRunner(db), Users: repository.NewUserRepo(db),
		}),
		bus: &recordingEventBus{},
		now: func() time.Time { return time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC) },
	}
}

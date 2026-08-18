package handler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
)

// TestCommentResponseJSONHasAvatarWithoutEmail 证明公开评论 DTO 携带 avatar_url
// 与 author_role，且不序列化邮箱、规范化邮箱或独立哈希字段。
func TestCommentResponseJSONHasAvatarWithoutEmail(t *testing.T) {
	view := comment.CommentView{
		ID:              1,
		SiteID:          2,
		ThreadID:        3,
		UserID:          4,
		Depth:           0,
		BodyMarkdown:    "hello",
		Status:          domain.CommentStatusPublished,
		AuthorNickname:  "nick",
		AuthorWebsite:   nil,
		AuthorRole:      domain.RoleAdmin,
		AuthorAvatarURL: "https://www.gravatar.com/avatar/84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee",
		CreatedAt:       time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
	}
	resp := toCommentResponse(view)
	payload, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal comment response: %v", err)
	}
	raw := string(payload)
	if !strings.Contains(raw, `"avatar_url":"https://www.gravatar.com/avatar/84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee"`) {
		t.Fatalf("response must expose avatar_url: %s", raw)
	}
	if !strings.Contains(raw, `"author_role":"admin"`) {
		t.Fatalf("response must expose author_role: %s", raw)
	}
	for _, forbidden := range []string{"email", "normalized", "hash", "author_email"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("response leaks %q: %s", forbidden, raw)
		}
	}
}

// TestAdminCommentResponseCarriesAvatar 证明管理评论 DTO 通过现有映射携带头像 URL。
func TestAdminCommentResponseCarriesAvatar(t *testing.T) {
	view := comment.AdminCommentView{
		CommentView: comment.CommentView{
			ID:              9,
			BodyMarkdown:    "body",
			Status:          domain.CommentStatusPending,
			AuthorNickname:  "nick",
			AuthorAvatarURL: "https://www.gravatar.com/avatar/abc",
			CreatedAt:       time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
		},
		Email:  "owner@example.com",
		IPMode: domain.PrivacyModeNone,
		UAMode: domain.PrivacyModeNone,
	}
	resp := toAdminCommentResponse(view)
	if resp.AvatarURL != "https://www.gravatar.com/avatar/abc" {
		t.Fatalf("admin avatar = %q, want abc url", resp.AvatarURL)
	}
	if resp.AuthorEmail != "owner@example.com" {
		t.Fatalf("admin email = %q, want owner@example.com", resp.AuthorEmail)
	}
}

// TestMeAndAdminUserResponsesCarryAvatar 证明用户资料 DTO 携带头像 URL。
func TestMeAndAdminUserResponsesCarryAvatar(t *testing.T) {
	profile := identity.Profile{
		ID:            1,
		Email:         "owner@example.com",
		Nickname:      "nick",
		Role:          domain.RoleAdmin,
		Status:        domain.UserStatusActive,
		EmailVerified: true,
		AvatarURL:     "https://www.gravatar.com/avatar/hash",
		CreatedAt:     time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
		UpdatedAt:     time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
	}
	if got := toMeResponse(profile).AvatarURL; got != "https://www.gravatar.com/avatar/hash" {
		t.Fatalf("me avatar = %q", got)
	}
	if got := toAdminUserResponse(profile).AvatarURL; got != "https://www.gravatar.com/avatar/hash" {
		t.Fatalf("admin user avatar = %q", got)
	}
}

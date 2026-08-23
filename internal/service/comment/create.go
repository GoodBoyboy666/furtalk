package comment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/clientip"
	"furtalk/internal/platform/markdown"
	"furtalk/internal/platform/value"
)

// Create 在单个事务内解析或创建作者与线程，并创建根评论或回复。
// 普通匿名邮箱走公开提交路径；管理员邮箱与认证模式必须携带有效凭据，
// 请求邮箱只用于一致性校验，绝不选择或替换凭据主体。
func (s *Service) Create(ctx context.Context, input CreateInput) (*CommentView, error) {
	if err := s.validateSiteAndOrigin(ctx, input.SiteID, input.Origin); err != nil {
		return nil, err
	}
	if err := validateBody(input.BodyMarkdown); err != nil {
		return nil, err
	}
	if err := validatePageKey(input.PageKey); err != nil {
		return nil, err
	}
	input.PageURL = normalizeOptionalString(input.PageURL)
	input.PageTitle = normalizeOptionalString(input.PageTitle)
	if err := validatePageURL(input.PageURL); err != nil {
		return nil, err
	}
	if err := validatePageTitle(input.PageTitle); err != nil {
		return nil, err
	}
	original, normalized, err := value.NormalizeEmail(input.Email)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	nickname := strings.TrimSpace(input.Nickname)
	if nickname == "" {
		return nil, fmt.Errorf("%w: nickname is required", domain.ErrValidation)
	}
	if len(nickname) > maxNicknameLength {
		return nil, fmt.Errorf("%w: nickname must not exceed %d characters", domain.ErrValidation, maxNicknameLength)
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if thread, err := s.threads.GetBySiteAndKey(ctx, input.SiteID, input.PageKey); err == nil {
		if !thread.CommentsEnabled {
			return nil, domain.ErrThreadClosed
		}
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}

	// 凭证/模式规则的实时判定与 actor 解析发生在 CAPTCHA 之前，
	// 使管理员授权路径与注册关闭路径不消耗 CAPTCHA、零写入。
	// 同时保留 actor 角色与作者网址，供事务外的垃圾检测使用。
	var credentialActor *int64
	actorIsAdmin := false
	var authorWebsite *string
	if input.Credential != nil {
		cred := input.Credential
		if cred.Epoch() != pol.Epoch {
			return nil, domain.ErrCredentialStale
		}
		if cred.SiteID() != input.SiteID {
			return nil, domain.ErrForbidden
		}
		principal, err := s.authz.Resolve(ctx, cred.UserID())
		if err != nil || principal.Status != domain.UserStatusActive || !WidgetRoleAllowed(pol.Mode, principal.Role) {
			return nil, domain.ErrInvalidCredentials
		}
		subject, err := s.users.FindByID(ctx, cred.UserID())
		if err != nil {
			return nil, err
		}
		if subject.EmailNormalized != normalized {
			return nil, domain.ErrInvalidCredentials
		}
		actorIsAdmin = principal.Role == domain.RoleAdmin
		authorWebsite = subject.WebsiteURL
		actor := cred.UserID()
		credentialActor = &actor
	} else {
		if pol.Mode != domain.CommentModeAnonymous {
			return nil, domain.ErrInvalidCredentials
		}
		user, err := s.users.FindByEmailNormalized(ctx, normalized)
		if err == nil {
			if user.Role == domain.RoleAdmin {
				return nil, domain.ErrAuthorizationRequired
			}
			if user.Status != domain.UserStatusActive {
				return nil, domain.ErrInvalidCredentials
			}
			authorWebsite = user.WebsiteURL
		} else if !errors.Is(err, domain.ErrNotFound) {
			return nil, err
		} else if !pol.PublicRegistration {
			return nil, domain.ErrInvalidCredentials
		}
	}

	if err := s.checkCaptcha(ctx, pol.CaptchaPolicy, CommentAction, input.CaptchaToken); err != nil {
		return nil, err
	}

	// 垃圾检测：管理员作者跳过全部检测器；普通作者在事务外串行执行固定检测链，
	// 得到显式初始状态作为本次创建命令的输入。
	initialStatus := commentInitialStatus(pol.Moderation, nil)
	if s.spam != nil && !actorIsAdmin {
		override := s.spam.Check(ctx, SpamInput{
			BlogURL:     s.siteCanonicalURL(ctx, input.SiteID),
			Permalink:   optionalString(input.PageURL),
			CommentType: "comment",
			Body:        input.BodyMarkdown,
			Nickname:    nickname,
			Email:       input.Email,
			AuthorURL:   optionalString(authorWebsite),
			IP:          input.IP,
			UserAgent:   input.UA,
		})
		initialStatus = commentInitialStatus(pol.Moderation, override)
	}

	var created *domain.Comment
	err = s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		thread, err := s.threads.ResolveOrCreate(ctx, input.SiteID, input.PageKey, input.PageURL, input.PageTitle)
		if err != nil {
			return err
		}
		current, err := s.threads.GetBySiteAndKeyLocked(ctx, input.SiteID, input.PageKey)
		if err != nil {
			return err
		}
		if !current.CommentsEnabled {
			return domain.ErrThreadClosed
		}
		actorID, err := s.resolveAndSyncActor(ctx, pol, normalized, original, nickname, input.WebsiteURL, credentialActor)
		if err != nil {
			return err
		}
		comment, err := s.createComment(ctx, pol, input.SiteID, thread.ID, actorID, input.ParentID, input.BodyMarkdown, input.IP, input.UA, initialStatus)
		if err != nil {
			return err
		}
		created = comment
		return nil
	})
	if err != nil {
		return nil, err
	}

	// direct 策略下评论创建后即 published，只发布创建事件；
	// 发布确认与回复通知由通知消费者按状态与审核策略分发。
	s.publishCommentCreated(ctx, created, pol.Mode)
	return s.viewFor(ctx, created)
}

// resolveAndSyncActor 在事务内解析作者用户并同步资料：
// 凭据路径使用凭据主体并只校验一致性；匿名路径按规范化邮箱查找或创建
// 普通用户，处理 normalized-email 唯一竞争。资料与评论同事务提交。
func (s *Service) resolveAndSyncActor(ctx context.Context, pol domain.CommentPolicy, normalized, original, nickname string, websiteOp WebsiteOperation, credentialActor *int64) (int64, error) {
	var (
		user *domain.User
		err  error
	)
	if credentialActor != nil {
		user, err = s.users.FindByID(ctx, *credentialActor)
		if err != nil {
			return 0, err
		}
		if user.EmailNormalized != normalized {
			return 0, domain.ErrInvalidCredentials
		}
		if user.Status != domain.UserStatusActive || !WidgetRoleAllowed(pol.Mode, user.Role) {
			return 0, domain.ErrInvalidCredentials
		}
	} else {
		user, err = s.users.FindByEmailNormalized(ctx, normalized)
		if errors.Is(err, domain.ErrNotFound) {
			emailDomain, derr := value.EmailDomain(normalized)
			if derr != nil {
				return 0, fmt.Errorf("%w: %v", domain.ErrValidation, derr)
			}
			if !value.EmailDomainAllowed(emailDomain, pol.EmailDomainWhitelist, pol.EmailDomainBlacklist) {
				return 0, domain.ErrEmailDomainNotAllowed
			}
			created := &domain.User{
				Email:           original,
				EmailNormalized: normalized,
				Nickname:        nickname,
				Role:            domain.RoleUser,
				Status:          domain.UserStatusActive,
			}
			if createErr := s.userW.CreateUser(ctx, created); createErr != nil {
				if !errors.Is(createErr, domain.ErrConflict) {
					return 0, createErr
				}
				user, err = s.users.FindByEmailNormalized(ctx, normalized)
				if err != nil {
					return 0, err
				}
			} else {
				user = created
			}
		} else if err != nil {
			return 0, err
		}
		if user.Role == domain.RoleAdmin {
			return 0, domain.ErrAuthorizationRequired
		}
		if user.Status != domain.UserStatusActive {
			return 0, domain.ErrInvalidCredentials
		}
	}
	nextWebsite, err := applyWebsiteOperation(user.WebsiteURL, websiteOp)
	if err != nil {
		return 0, err
	}
	if err := s.userW.UpdateUserProfile(ctx, user.ID, nickname, nextWebsite); err != nil {
		return 0, err
	}
	return user.ID, nil
}

// applyWebsiteOperation 应用网址三态操作：缺省保持当前值，null/空串清空，
// 合法非空 URL 覆盖。
func applyWebsiteOperation(current *string, op WebsiteOperation) (*string, error) {
	if !op.Set {
		return current, nil
	}
	if op.Value == nil {
		return nil, nil
	}
	raw := strings.TrimSpace(*op.Value)
	if raw == "" {
		return nil, nil
	}
	normalized, err := value.NormalizeWebsite(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	return &normalized, nil
}

// CreateReplyFirstParty 从第一方页面创建回复。
func (s *Service) CreateReplyFirstParty(ctx context.Context, actorID int64, actorRole domain.Role, parentCommentID int64, body, captchaToken string, ip net.IP, rawUA string) (*CommentView, error) {
	if err := validateBody(body); err != nil {
		return nil, err
	}
	pol, err := s.settings.CommentPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if pol.Mode != domain.CommentModeAuthenticated && actorRole != domain.RoleAdmin {
		return nil, domain.ErrForbidden
	}
	if err := s.checkCaptcha(ctx, pol.CaptchaPolicy, CommentAction, captchaToken); err != nil {
		return nil, err
	}
	parent, err := s.comments.FindGlobalByID(ctx, parentCommentID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrParentNotFound
		}
		return nil, err
	}
	if parent.Status != domain.CommentStatusPublished {
		if parent.Status == domain.CommentStatusDeleted {
			return nil, domain.ErrParentDeleted
		}
		return nil, domain.ErrConflict
	}
	if parent.Depth >= pol.MaxReplyDepth {
		return nil, domain.ErrDepthExceeded
	}

	// 垃圾检测：管理员作者跳过全部检测器；普通用户在事务外执行同一固定检测链。
	// 补齐全套送检上下文：站点 CanonicalURL、线程 permalink 与作者网址。
	initialStatus := commentInitialStatus(pol.Moderation, nil)
	if s.spam != nil && actorRole != domain.RoleAdmin {
		var permalink string
		if thread, err := s.threads.GetBySiteAndID(ctx, parent.SiteID, parent.ThreadID); err == nil && thread.PageURL != nil {
			permalink = *thread.PageURL
		}
		author := &domain.User{}
		if user, err := s.users.FindByID(ctx, actorID); err == nil {
			author = user
		}
		override := s.spam.Check(ctx, SpamInput{
			BlogURL:     s.siteCanonicalURL(ctx, parent.SiteID),
			Permalink:   permalink,
			CommentType: "comment",
			Body:        body,
			Nickname:    author.Nickname,
			Email:       author.Email,
			AuthorURL:   optionalString(author.WebsiteURL),
			IP:          ip,
			UserAgent:   rawUA,
		})
		initialStatus = commentInitialStatus(pol.Moderation, override)
	}

	var created *domain.Comment
	err = s.txRunner.RunInTx(ctx, func(ctx context.Context) error {
		thread, err := s.threads.GetBySiteAndIDLocked(ctx, parent.SiteID, parent.ThreadID)
		if err != nil {
			return err
		}
		if !thread.CommentsEnabled {
			return domain.ErrThreadClosed
		}
		comment, err := s.createComment(ctx, pol, parent.SiteID, parent.ThreadID, actorID, &parent.ID, body, ip, rawUA, initialStatus)
		if err != nil {
			return err
		}
		created = comment
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.publishCommentCreated(ctx, created, pol.Mode)
	return s.viewFor(ctx, created)
}

// createComment 在打开的事务内插入评论。
// initialStatus 是调用方在事务外按“垃圾检测覆盖 → 全局审核策略”计算好的显式初始状态；
// published_at 只在状态为 published 时写入。
func (s *Service) createComment(ctx context.Context, cfg domain.CommentPolicy, siteID, threadID, actorID int64, parentID *int64, body string, ip net.IP, rawUA string, initialStatus domain.CommentStatus) (*domain.Comment, error) {
	var parentRef, rootID *int64
	var replyToUserID *int64
	depth := 0
	if parentID != nil {
		parent, err := s.comments.FindBySiteAndID(ctx, siteID, *parentID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return nil, domain.ErrParentNotFound
			}
			return nil, err
		}
		if parent.ThreadID != threadID {
			return nil, domain.ErrCrossThreadReply
		}
		if parent.Status == domain.CommentStatusDeleted {
			return nil, domain.ErrParentDeleted
		}
		if parent.Depth >= cfg.MaxReplyDepth {
			return nil, domain.ErrDepthExceeded
		}
		depth = parent.Depth + 1
		parentRef = parentID
		replyToUserID = &parent.UserID
		if parent.RootID != nil {
			rootID = parent.RootID
		} else {
			rootID = &parent.ID
		}
	}

	status := initialStatus
	now := s.now().UTC()
	var publishedAt *time.Time
	if status == domain.CommentStatusPublished {
		publishedAt = &now
	}
	ipMode, ipValue, uaMode, uaRec, err := capturePrivacy(cfg.Privacy, ip, rawUA)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}

	comment := &domain.Comment{
		SiteID:        siteID,
		ThreadID:      threadID,
		UserID:        actorID,
		ParentID:      parentRef,
		RootID:        rootID,
		ReplyToUserID: replyToUserID,
		Depth:         depth,
		BodyMarkdown:  body,
		Status:        status,
		IPMode:        ipMode,
		IPValue:       ipValue,
		UAMode:        uaMode,
		UARaw:         uaRec.Raw,
		UABrowser:     uaRec.Browser,
		UAOS:          uaRec.OS,
		UADevice:      uaRec.Device,
		CreatedAt:     now,
		UpdatedAt:     now,
		PublishedAt:   publishedAt,
	}
	if err := s.comments.Create(ctx, comment); err != nil {
		return nil, err
	}
	return comment, nil
}

// capturePrivacy 按当前设置模式把原始 IP/UA 转为持久化的隐私列。
func capturePrivacy(p domain.PrivacyPolicy, ip net.IP, rawUA string) (domain.PrivacyMode, *string, domain.PrivacyMode, *clientip.UARecord, error) {
	ipMode := domain.PrivacyMode(p.IPMode)
	uaMode := domain.PrivacyMode(p.UAMode)
	var ipValue *string
	if p.IPMode != "none" && ip != nil {
		coarsened, err := clientip.CoarsenIP(ip, p.IPMode)
		if err != nil {
			return "", nil, "", nil, err
		}
		value := coarsened.String()
		ipValue = &value
	}
	uaRec, err := clientip.ParseUA(rawUA, p.UAMode)
	if err != nil {
		return "", nil, "", nil, err
	}
	return ipMode, ipValue, uaMode, uaRec, nil
}

// validateSiteActive 校验站点活跃。
func (s *Service) validateSiteActive(ctx context.Context, siteID int64) error {
	site, err := s.sites.Get(ctx, siteID)
	if err != nil {
		return err
	}
	if site.Status != domain.SiteStatusActive {
		return domain.ErrSiteInactive
	}
	return nil
}

// viewFor 加载作者资料并构建公共评论视图。
func (s *Service) viewFor(ctx context.Context, comment *domain.Comment) (*CommentView, error) {
	user, err := s.users.FindByID(ctx, comment.UserID)
	if err != nil {
		return nil, err
	}
	gravatarBase, err := s.avatarBaseURL(ctx)
	if err != nil {
		return nil, err
	}
	view := toCommentView(comment, user.Nickname, user.WebsiteURL, user.Role, value.GravatarURL(user.EmailNormalized, gravatarBase))
	nickname, err := s.replyToNickname(ctx, comment)
	if err != nil {
		return nil, err
	}
	view.ReplyToNickname = nickname
	return &view, nil
}

// replyToNickname 加载回复目标作者的当前昵称；目标缺失或已注销时返回 nil。
func (s *Service) replyToNickname(ctx context.Context, comment *domain.Comment) (*string, error) {
	if comment == nil || comment.ReplyToUserID == nil {
		return nil, nil
	}
	replyUser, err := s.users.FindByID(ctx, *comment.ReplyToUserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &replyUser.Nickname, nil
}

func validateBody(body string) error {
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("%w: body is required", domain.ErrValidation)
	}
	if len(body) > maxBodyLength {
		return fmt.Errorf("%w: body is too long", domain.ErrValidation)
	}
	if err := markdown.Validate(body); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrValidation, err)
	}
	return nil
}

func validatePageKey(pageKey string) error {
	if strings.TrimSpace(pageKey) == "" {
		return fmt.Errorf("%w: page_key is required", domain.ErrValidation)
	}
	if len(pageKey) > maxPageKeyLength {
		return fmt.Errorf("%w: page_key is too long", domain.ErrValidation)
	}
	return nil
}

func validatePageURL(pageURL *string) error {
	if pageURL == nil || strings.TrimSpace(*pageURL) == "" {
		return nil
	}
	raw := strings.TrimSpace(*pageURL)
	if len(raw) > maxPageURLLength {
		return fmt.Errorf("%w: page_url is too long", domain.ErrValidation)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: page_url must be an absolute http(s) url", domain.ErrValidation)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: page_url must be an absolute http(s) url", domain.ErrValidation)
	}
	return nil
}

func validatePageTitle(pageTitle *string) error {
	if pageTitle != nil && len(*pageTitle) > maxPageTitleLength {
		return fmt.Errorf("%w: page_title is too long", domain.ErrValidation)
	}
	return nil
}

// normalizeOptionalString 把空的可选字符串转为 nil。
func normalizeOptionalString(value *string) *string {
	if value != nil && strings.TrimSpace(*value) == "" {
		return nil
	}
	return value
}

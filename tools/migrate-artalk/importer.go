package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/clientip"
	"furtalk/internal/platform/gormtx"
	"furtalk/internal/platform/value"
	"furtalk/internal/repository"
)

var errDryRunRollback = errors.New("artalk migration dry-run rollback")

// Options controls a migration. TargetSiteID merges every source site into an
// existing Furtalk site. Without it, source sites are resolved by canonical
// origin and created when absent.
type Options struct {
	TargetSiteID   int64
	DefaultSiteURL string
	SourceLocation *time.Location
	IPMode         domain.PrivacyMode
	UAMode         domain.PrivacyMode
	DryRun         bool
}

// Report summarizes both committed imports and dry runs.
type Report struct {
	InputComments       int
	ImportedComments    int
	PublishedComments   int
	PendingComments     int
	CreatedUsers        int
	ReusedUsers         int
	CreatedSites        int
	ReusedSites         int
	CreatedThreads      int
	ReusedThreads       int
	SyntheticEmails     int
	InvalidWebsites     int
	OmittedIPs          int
	InvalidIPs          int
	OmittedUAs          int
	IgnoredCollapsed    int
	IgnoredPinned       int
	IgnoredVotes        int
	IgnoredBadges       int
	IgnoredPagePolicies int
	DryRun              bool
}

type Importer struct {
	tx       *gormtx.Runner
	users    *repository.UserRepo
	sites    *repository.SiteRepo
	threads  *repository.ThreadRepo
	comments *repository.CommentRepo
}

// NewImporter constructs an importer from the same repository boundary used
// by the application.
func NewImporter(
	tx *gormtx.Runner,
	users *repository.UserRepo,
	sites *repository.SiteRepo,
	threads *repository.ThreadRepo,
	comments *repository.CommentRepo,
) *Importer {
	return &Importer{tx: tx, users: users, sites: sites, threads: threads, comments: comments}
}

type preparedComment struct {
	source      Artran
	id          string
	parentID    string
	createdAt   time.Time
	updatedAt   time.Time
	pending     bool
	siteKey     string
	pageKey     string
	authorKey   string
	targetSite  int64
	targetUser  int64
	targetID    int64
	targetDepth int
	targetRoot  *int64
}

type sourceSite struct {
	name      string
	origins   []string
	canonical string
	targetID  int64
}

type sourceUser struct {
	email      string
	normalized string
	nickname   string
	website    *string
	createdAt  time.Time
	updatedAt  time.Time
	targetID   int64
	synthetic  bool
	badWebsite bool
}

type sourceThread struct {
	siteID    int64
	pageKey   string
	pageURL   *string
	pageTitle *string
	updatedAt time.Time
	targetID  int64
}

// Import validates the entire source before opening one target transaction.
// A dry run performs the same writes and constraints checks, then rolls the
// transaction back deliberately.
func (i *Importer) Import(ctx context.Context, records []Artran, options Options) (Report, error) {
	report := Report{InputComments: len(records), DryRun: options.DryRun}
	if options.TargetSiteID < 0 {
		return report, fmt.Errorf("target site id must not be negative")
	}
	if !validPrivacyMode(options.IPMode) {
		return report, fmt.Errorf("invalid IP privacy mode %q", options.IPMode)
	}
	if !validPrivacyMode(options.UAMode) {
		return report, fmt.Errorf("invalid UA privacy mode %q", options.UAMode)
	}
	prepared, byID, err := prepare(records, options)
	if err != nil {
		return report, err
	}
	err = i.tx.RunInTx(ctx, func(txCtx context.Context) error {
		if err := i.importPrepared(txCtx, prepared, byID, options, &report); err != nil {
			return err
		}
		if options.DryRun {
			return errDryRunRollback
		}
		return nil
	})
	if errors.Is(err, errDryRunRollback) {
		return report, nil
	}
	return report, err
}

func prepare(records []Artran, options Options) ([]*preparedComment, map[string]*preparedComment, error) {
	if len(records) == 0 {
		return nil, nil, fmt.Errorf("Artrans contains no comments")
	}
	location := options.SourceLocation
	if location == nil {
		location = time.UTC
	}
	byID := make(map[string]*preparedComment, len(records))
	inputOrder := make([]*preparedComment, 0, len(records))
	for idx, record := range records {
		row := idx + 1
		id := record.id()
		if id == "" || id == "0" {
			return nil, nil, fmt.Errorf("Artrans row %d has an empty or zero id", row)
		}
		if _, duplicate := byID[id]; duplicate {
			return nil, nil, fmt.Errorf("Artrans row %d duplicates comment id %q", row, id)
		}
		pageKey := record.pageKey()
		if pageKey == "" {
			return nil, nil, fmt.Errorf("Artrans comment %s has an empty page_key", id)
		}
		createdAt, err := parseTime(record.createdAt(), location)
		if err != nil {
			return nil, nil, fmt.Errorf("Artrans comment %s created_at: %w", id, err)
		}
		updatedAt := createdAt
		if record.updatedAt() != "" {
			updatedAt, err = parseTime(record.updatedAt(), location)
			if err != nil {
				return nil, nil, fmt.Errorf("Artrans comment %s updated_at: %w", id, err)
			}
		}
		pending, err := record.isPending()
		if err != nil {
			return nil, nil, fmt.Errorf("Artrans comment %s: %w", id, err)
		}
		for _, parse := range []func() (bool, error){record.isCollapsed, record.isPinned, record.pageAdminOnly} {
			if _, err := parse(); err != nil {
				return nil, nil, fmt.Errorf("Artrans comment %s: %w", id, err)
			}
		}
		siteKey := record.siteName()
		if siteKey == "" {
			siteKey = strings.TrimSpace(record.siteURLs())
		}
		if siteKey == "" {
			siteKey = "Artalk"
		}
		comment := &preparedComment{
			source:    record,
			id:        id,
			parentID:  normalizeParentID(record.rid()),
			createdAt: createdAt,
			updatedAt: updatedAt,
			pending:   pending,
			siteKey:   siteKey,
			pageKey:   pageKey,
		}
		byID[id] = comment
		inputOrder = append(inputOrder, comment)
	}

	ordered := make([]*preparedComment, 0, len(records))
	state := make(map[string]uint8, len(records))
	var visit func(*preparedComment) error
	visit = func(comment *preparedComment) error {
		switch state[comment.id] {
		case 1:
			return fmt.Errorf("Artrans reply graph contains a cycle at comment %s", comment.id)
		case 2:
			return nil
		}
		state[comment.id] = 1
		if comment.parentID != "" {
			parent, ok := byID[comment.parentID]
			if !ok {
				return fmt.Errorf("Artrans comment %s references missing parent %s", comment.id, comment.parentID)
			}
			if parent.siteKey != comment.siteKey || parent.pageKey != comment.pageKey {
				return fmt.Errorf("Artrans comment %s and parent %s belong to different sites or pages", comment.id, parent.id)
			}
			if err := visit(parent); err != nil {
				return err
			}
		}
		state[comment.id] = 2
		ordered = append(ordered, comment)
		return nil
	}
	for _, comment := range inputOrder {
		if err := visit(comment); err != nil {
			return nil, nil, err
		}
	}
	return ordered, byID, nil
}

func (i *Importer) importPrepared(
	ctx context.Context,
	comments []*preparedComment,
	byID map[string]*preparedComment,
	options Options,
	report *Report,
) error {
	sites, err := i.resolveSites(ctx, comments, options, report)
	if err != nil {
		return err
	}
	users, err := i.resolveUsers(ctx, comments, report)
	if err != nil {
		return err
	}
	threads, err := i.resolveThreads(ctx, comments, sites, report)
	if err != nil {
		return err
	}
	for _, comment := range comments {
		comment.targetSite = sites[comment.siteKey].targetID
		comment.targetUser = users[comment.authorKey].targetID
		thread := threads[threadKey(comment.targetSite, comment.pageKey)]
		var parentID, rootID, replyToUserID *int64
		depth := 0
		if comment.parentID != "" {
			parent := byID[comment.parentID]
			parentID = int64Ptr(parent.targetID)
			replyToUserID = int64Ptr(parent.targetUser)
			depth = parent.targetDepth + 1
			if parent.targetRoot != nil {
				rootID = int64Ptr(*parent.targetRoot)
			} else {
				rootID = int64Ptr(parent.targetID)
			}
		}
		status := domain.CommentStatusPublished
		var publishedAt *time.Time
		if comment.pending {
			status = domain.CommentStatusPending
			report.PendingComments++
		} else {
			publishedAt = timePtr(comment.createdAt)
			report.PublishedComments++
		}
		ipMode, ipValue := migrateIP(comment.source.ip(), options.IPMode, report)
		uaMode, uaRecord, err := migrateUA(comment.source.ua(), options.UAMode, report)
		if err != nil {
			return fmt.Errorf("migrate comment %s user agent: %w", comment.id, err)
		}
		row := &domain.Comment{
			SiteID:        comment.targetSite,
			ThreadID:      thread.targetID,
			UserID:        comment.targetUser,
			ParentID:      parentID,
			RootID:        rootID,
			ReplyToUserID: replyToUserID,
			Depth:         depth,
			BodyMarkdown:  comment.source.content(),
			Status:        status,
			IPMode:        ipMode,
			IPValue:       ipValue,
			UAMode:        uaMode,
			UARaw:         uaRecord.Raw,
			UABrowser:     uaRecord.Browser,
			UAOS:          uaRecord.OS,
			UADevice:      uaRecord.Device,
			CreatedAt:     comment.createdAt,
			UpdatedAt:     comment.updatedAt,
			PublishedAt:   publishedAt,
		}
		if err := i.comments.Create(ctx, row); err != nil {
			return fmt.Errorf("migrate Artalk comment %s: %w", comment.id, err)
		}
		comment.targetID = row.ID
		comment.targetDepth = depth
		comment.targetRoot = rootID
		report.ImportedComments++
		countUnsupported(comment.source, report)
	}
	return nil
}

func (i *Importer) resolveSites(ctx context.Context, comments []*preparedComment, options Options, report *Report) (map[string]*sourceSite, error) {
	result := make(map[string]*sourceSite)
	if options.TargetSiteID > 0 {
		if _, err := i.sites.Get(ctx, options.TargetSiteID); err != nil {
			return nil, fmt.Errorf("target site %d: %w", options.TargetSiteID, err)
		}
		count, err := i.comments.CountAdmin(ctx, domain.AdminFilter{SiteID: &options.TargetSiteID})
		if err != nil {
			return nil, fmt.Errorf("count existing comments for target site %d: %w", options.TargetSiteID, err)
		}
		if count != 0 {
			return nil, fmt.Errorf("target site %d already contains %d comments; refusing a duplicate-prone import", options.TargetSiteID, count)
		}
		for _, comment := range comments {
			if _, ok := result[comment.siteKey]; !ok {
				result[comment.siteKey] = &sourceSite{targetID: options.TargetSiteID}
			}
		}
		report.ReusedSites = 1
		return result, nil
	}

	for _, comment := range comments {
		site, ok := result[comment.siteKey]
		if !ok {
			name := comment.source.siteName()
			if name == "" {
				name = "Artalk"
			}
			site = &sourceSite{name: name}
			result[comment.siteKey] = site
		}
		site.origins = appendUnique(site.origins, originsFromArtran(comment.source)...)
	}
	fallback, fallbackErr := normalizeOrigin(options.DefaultSiteURL)
	if strings.TrimSpace(options.DefaultSiteURL) == "" {
		fallbackErr = nil
	}
	if fallbackErr != nil {
		return nil, fmt.Errorf("default site URL: %w", fallbackErr)
	}
	existing, err := i.sites.List(ctx)
	if err != nil {
		return nil, err
	}
	keys := sortedSiteKeys(result)
	touched := make(map[int64]bool)
	for _, key := range keys {
		site := result[key]
		if len(site.origins) == 0 && fallback != "" {
			site.origins = append(site.origins, fallback)
		}
		if len(site.origins) == 0 {
			return nil, fmt.Errorf("Artalk site %q has no Furtalk-compatible HTTPS origin; provide --default-site-url or --target-site-id", site.name)
		}
		site.canonical = preferredCanonical(site.origins)
		matches := make([]domain.Site, 0, 1)
		for _, candidate := range existing {
			if candidate.CanonicalURL == site.canonical {
				matches = append(matches, candidate)
			}
		}
		if len(matches) > 1 {
			return nil, fmt.Errorf("canonical URL %q matches multiple Furtalk sites; use --target-site-id", site.canonical)
		}
		if len(matches) == 1 {
			site.targetID = matches[0].ID
			report.ReusedSites++
		} else {
			created := &domain.Site{Name: site.name, CanonicalURL: site.canonical, Status: domain.SiteStatusActive}
			if err := i.sites.Create(ctx, created); err != nil {
				return nil, fmt.Errorf("create target site for %q: %w", site.name, err)
			}
			site.targetID = created.ID
			report.CreatedSites++
			existing = append(existing, *created)
		}
		if !touched[site.targetID] {
			count, err := i.comments.CountAdmin(ctx, domain.AdminFilter{SiteID: &site.targetID})
			if err != nil {
				return nil, fmt.Errorf("count existing comments for target site %d: %w", site.targetID, err)
			}
			if count != 0 {
				return nil, fmt.Errorf("target site %d (%s) already contains %d comments; refusing a duplicate-prone import", site.targetID, site.canonical, count)
			}
			touched[site.targetID] = true
		}
		existingOrigins, err := i.sites.ListOrigins(ctx, site.targetID)
		if err != nil {
			return nil, err
		}
		known := make(map[string]bool, len(existingOrigins))
		for _, origin := range existingOrigins {
			known[origin.Origin] = true
		}
		for _, origin := range site.origins {
			if known[origin] {
				continue
			}
			if _, err := i.sites.AddOrigin(ctx, site.targetID, origin); err != nil {
				return nil, fmt.Errorf("add origin %q to target site %d: %w", origin, site.targetID, err)
			}
			known[origin] = true
		}
	}
	return result, nil
}

func (i *Importer) resolveUsers(ctx context.Context, comments []*preparedComment, report *Report) (map[string]*sourceUser, error) {
	users := make(map[string]*sourceUser)
	for _, comment := range comments {
		email, normalized, err := value.NormalizeEmail(comment.source.email())
		synthetic := false
		if err != nil {
			synthetic = true
			identity := strings.ToLower(comment.source.email())
			if identity == "" {
				identity = "\x00" + comment.source.nick()
			}
			hash := sha256.Sum256([]byte(identity))
			email = fmt.Sprintf("artalk-%x@artalk.invalid", hash[:8])
			normalized = email
		}
		key := normalized
		comment.authorKey = key
		user, ok := users[key]
		if !ok {
			nickname := comment.source.nick()
			if nickname == "" {
				nickname = fallbackNickname(normalized)
			}
			user = &sourceUser{
				email:      email,
				normalized: normalized,
				nickname:   nickname,
				createdAt:  comment.createdAt,
				updatedAt:  comment.updatedAt,
				synthetic:  synthetic,
			}
			users[key] = user
		}
		if comment.createdAt.Before(user.createdAt) {
			user.createdAt = comment.createdAt
		}
		if comment.updatedAt.After(user.updatedAt) {
			user.updatedAt = comment.updatedAt
			if comment.source.nick() != "" {
				user.nickname = comment.source.nick()
			}
		}
		if rawWebsite := comment.source.link(); rawWebsite != "" {
			website, err := value.NormalizeWebsite(rawWebsite)
			if err != nil {
				user.badWebsite = true
			} else if user.website == nil || comment.updatedAt.Equal(user.updatedAt) {
				user.website = stringPtr(website)
			}
		}
	}
	keys := make([]string, 0, len(users))
	for key := range users {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		user := users[key]
		existing, err := i.users.FindByEmailNormalized(ctx, user.normalized)
		if err == nil {
			user.targetID = existing.ID
			report.ReusedUsers++
		} else if !errors.Is(err, domain.ErrNotFound) {
			return nil, err
		} else {
			created := &domain.User{
				Email:           user.email,
				EmailNormalized: user.normalized,
				Nickname:        user.nickname,
				WebsiteURL:      user.website,
				Role:            domain.RoleUser,
				Status:          domain.UserStatusActive,
				SessionVersion:  1,
				CreatedAt:       user.createdAt,
				UpdatedAt:       user.updatedAt,
			}
			if err := i.users.Create(ctx, created); err != nil {
				return nil, fmt.Errorf("create migrated user %q: %w", user.normalized, err)
			}
			user.targetID = created.ID
			report.CreatedUsers++
		}
		if user.synthetic {
			report.SyntheticEmails++
		}
		if user.badWebsite {
			report.InvalidWebsites++
		}
	}
	return users, nil
}

func fallbackNickname(normalizedEmail string) string {
	local := strings.SplitN(normalizedEmail, "@", 2)[0]
	if strings.TrimSpace(local) == "" {
		return "user"
	}
	return local
}

func (i *Importer) resolveThreads(ctx context.Context, comments []*preparedComment, sites map[string]*sourceSite, report *Report) (map[string]*sourceThread, error) {
	threads := make(map[string]*sourceThread)
	for _, comment := range comments {
		siteID := sites[comment.siteKey].targetID
		key := threadKey(siteID, comment.pageKey)
		thread, ok := threads[key]
		if !ok {
			thread = &sourceThread{siteID: siteID, pageKey: comment.pageKey, updatedAt: comment.updatedAt}
			threads[key] = thread
		}
		if title := comment.source.pageTitle(); title != "" && (thread.pageTitle == nil || !comment.updatedAt.Before(thread.updatedAt)) {
			thread.pageTitle = stringPtr(title)
			thread.updatedAt = comment.updatedAt
		}
		if pageURL := absoluteHTTPURL(comment.pageKey); pageURL != "" {
			thread.pageURL = stringPtr(pageURL)
		}
	}
	keys := make([]string, 0, len(threads))
	for key := range threads {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		thread := threads[key]
		_, findErr := i.threads.GetBySiteAndKey(ctx, thread.siteID, thread.pageKey)
		if findErr == nil {
			report.ReusedThreads++
		} else if !errors.Is(findErr, domain.ErrNotFound) {
			return nil, findErr
		} else {
			report.CreatedThreads++
		}
		resolved, err := i.threads.ResolveOrCreate(ctx, thread.siteID, thread.pageKey, thread.pageURL, thread.pageTitle)
		if err != nil {
			return nil, err
		}
		thread.targetID = resolved.ID
	}
	return threads, nil
}

func parseTime(raw string, location *time.Location) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("value is empty")
	}
	layoutsWithZone := []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999 -0700",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05.999999999 -07:00",
		"2006-01-02 15:04:05 -07:00",
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02T15:04:05.999999999-0700",
		"2006-01-02T15:04:05-0700",
	}
	for _, layout := range layoutsWithZone {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC().Truncate(time.Microsecond), nil
		}
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", time.DateTime, time.DateOnly} {
		if parsed, err := time.ParseInLocation(layout, raw, location); err == nil {
			return parsed.UTC().Truncate(time.Microsecond), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time %q", raw)
}

func normalizeParentID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" || strings.EqualFold(raw, "null") {
		return ""
	}
	return raw
}

func normalizeOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("origin is empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("%q is not an absolute HTTP(S) URL", raw)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("%q does not use HTTP(S)", raw)
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || strings.Contains(hostname, "*") {
		return "", fmt.Errorf("%q has an invalid host", raw)
	}
	if u.Scheme == "http" && hostname != "localhost" && hostname != "127.0.0.1" && hostname != "::1" {
		return "", fmt.Errorf("%q uses insecure HTTP for a non-local host", raw)
	}
	port := u.Port()
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("%q has an invalid port", raw)
		}
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return u.Scheme + "://" + host, nil
}

func originsFromArtran(record Artran) []string {
	var origins []string
	for _, raw := range strings.Split(record.siteURLs(), ",") {
		if normalized, err := normalizeOrigin(raw); err == nil {
			origins = appendUnique(origins, normalized)
		}
	}
	if pageURL := absoluteHTTPURL(record.pageKey()); pageURL != "" {
		if normalized, err := normalizeOrigin(pageURL); err == nil {
			origins = appendUnique(origins, normalized)
		}
	}
	return origins
}

func preferredCanonical(origins []string) string {
	best := origins[0]
	bestScore := originScore(best)
	for _, origin := range origins[1:] {
		if score := originScore(origin); score > bestScore {
			best = origin
			bestScore = score
		}
	}
	return best
}

func originScore(origin string) int {
	u, _ := url.Parse(origin)
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme == "https" && !local {
		return 3
	}
	if u.Scheme == "https" {
		return 2
	}
	return 1
}

func absoluteHTTPURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.String()
}

func migrateIP(raw string, mode domain.PrivacyMode, report *Report) (domain.PrivacyMode, *string) {
	if raw == "" {
		return mode, nil
	}
	if mode == domain.PrivacyModeNone {
		report.OmittedIPs++
		return mode, nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		report.InvalidIPs++
		return mode, nil
	}
	value, err := clientip.CoarsenIP(ip, string(mode))
	if err != nil || value == nil {
		report.InvalidIPs++
		return mode, nil
	}
	return mode, stringPtr(value.String())
}

func migrateUA(raw string, mode domain.PrivacyMode, report *Report) (domain.PrivacyMode, *clientip.UARecord, error) {
	if raw == "" {
		return mode, &clientip.UARecord{}, nil
	}
	if mode == domain.PrivacyModeNone {
		report.OmittedUAs++
	}
	record, err := clientip.ParseUA(raw, string(mode))
	return mode, record, err
}

func validPrivacyMode(mode domain.PrivacyMode) bool {
	return mode == domain.PrivacyModeNone || mode == domain.PrivacyModeCoarse || mode == domain.PrivacyModeFull
}

func countUnsupported(record Artran, report *Report) {
	if value, err := record.isCollapsed(); err == nil && value {
		report.IgnoredCollapsed++
	}
	if value, err := record.isPinned(); err == nil && value {
		report.IgnoredPinned++
	}
	if nonZero(record.VoteUp) || nonZero(record.VoteDown) {
		report.IgnoredVotes++
	}
	if strings.TrimSpace(string(record.BadgeName)) != "" || strings.TrimSpace(string(record.BadgeColor)) != "" {
		report.IgnoredBadges++
	}
	if value, err := record.pageAdminOnly(); err == nil && value {
		report.IgnoredPagePolicies++
	}
}

func sortedSiteKeys(sites map[string]*sourceSite) []string {
	keys := make([]string, 0, len(sites))
	for key := range sites {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

func threadKey(siteID int64, pageKey string) string {
	return fmt.Sprintf("%d\x00%s", siteID, pageKey)
}

func stringPtr(value string) *string { return &value }
func int64Ptr(value int64) *int64    { return &value }
func timePtr(value time.Time) *time.Time {
	return &value
}

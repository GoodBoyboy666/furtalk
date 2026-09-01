package comment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/logging"
	"furtalk/internal/platform/spam"
)

// spamTimeout 限定单个外部垃圾检测渠道的请求耗时。
const spamTimeout = 3 * time.Second

// spamProviderOrder 固定的垃圾检测执行顺序。
var spamProviderOrder = []string{"spam.local", "spam.akismet", "spam.aliyun", "spam.tencent"}

// SpamInput 评论创建阶段传给垃圾检测网关的送检数据。
type SpamInput struct {
	// BlogURL 站点 CanonicalURL。
	BlogURL string
	// Permalink 评论所在页面链接。
	Permalink string
	// CommentType 评论类型，例如 comment。
	CommentType string
	// Body 评论 Markdown 原文。
	Body string
	// Nickname 作者昵称。
	Nickname string
	// Email 作者邮箱。
	Email string
	// AuthorURL 作者网址。
	AuthorURL string
	// IP 原始客户端 IP。
	IP net.IP
	// UserAgent 原始 UA。
	UserAgent string
}

// SpamProviderConfig 解密后的垃圾检测 provider 配置（含机密）。
type SpamProviderConfig struct {
	ProviderKey     string
	Enabled         bool
	Configured      bool
	CheckNickname   bool
	Action          string
	APIKey          string
	Region          string
	BizType         string
	AccessKeyID     string
	AccessKeySecret string
	SecretID        string
	SecretKey       string
}

// SpamProviderReader 读取已启用的垃圾检测 provider 解密配置。
type SpamProviderReader interface {
	EnabledSpamProviders(ctx context.Context) ([]SpamProviderConfig, error)
}

// SpamGateway 按固定顺序“本地 → Akismet → 阿里云 → 腾讯云”串行执行已启用的
// 垃圾检测渠道，首个 pending/spam 结果立即短路。
type SpamGateway struct {
	reader SpamProviderReader
	log    *slog.Logger
	mu     sync.Mutex
	cache  map[string]spam.Detector
	// httpClient 供外部渠道构建检测器；nil 时各渠道使用默认有界客户端。
	httpClient *http.Client
}

// NewSpamGateway 构建垃圾检测网关。
func NewSpamGateway(reader SpamProviderReader, logger *slog.Logger) *SpamGateway {
	return &SpamGateway{
		reader: reader,
		log:    logging.Normalize(logger),
		cache:  make(map[string]spam.Detector),
	}
}

// Check 串行检测并返回状态覆盖：
// 首个 pending/spam 结果返回对应状态且后续渠道不再调用；
// 全部渠道通过或 unknown 时返回 nil。渠道故障一律按 unknown 降级，绝不阻断评论提交。
// 执行顺序始终遍历固定 key 数组，不依赖 reader 返回顺序。
func (g *SpamGateway) Check(ctx context.Context, input SpamInput) *domain.CommentStatus {
	providers, err := g.reader.EnabledSpamProviders(ctx)
	if err != nil {
		logging.FromContext(ctx, g.log).WarnContext(ctx, "spam: read enabled providers failed", logging.Error(err))
		return nil
	}
	byKey := make(map[string]SpamProviderConfig, len(providers))
	for _, cfg := range providers {
		byKey[cfg.ProviderKey] = cfg
	}
	ipString := ""
	if input.IP != nil {
		ipString = input.IP.String()
	}
	detectorInput := spam.Input{
		BlogURL:     input.BlogURL,
		Permalink:   input.Permalink,
		CommentType: input.CommentType,
		Body:        input.Body,
		Nickname:    input.Nickname,
		Email:       input.Email,
		AuthorURL:   input.AuthorURL,
		IP:          ipString,
		UserAgent:   input.UserAgent,
	}
	for _, key := range spamProviderOrder {
		cfg, ok := byKey[key]
		if !ok {
			continue
		}
		detector, err := g.detectorFor(cfg)
		if err != nil {
			logging.FromContext(ctx, g.log).WarnContext(ctx, "spam: build detector failed",
				"provider", cfg.ProviderKey, logging.Error(err))
			continue
		}
		start := time.Now()
		detectCtx, cancel := context.WithTimeout(ctx, spamTimeout)
		result, err := detector.Check(detectCtx, detectorInput)
		cancel()
		if err != nil {
			logging.FromContext(ctx, g.log).WarnContext(ctx, "spam: detector check failed",
				"provider", cfg.ProviderKey,
				"category", spamErrorCategory(err),
				logging.Duration(time.Since(start)),
				logging.Error(err))
			continue
		}
		if isBinarySpamProvider(cfg.ProviderKey) {
			if result == spam.ResultBlock {
				return statusForSpamAction(cfg.Action)
			}
			continue
		}
		switch result {
		case spam.ResultReview:
			return spamStatus(domain.CommentStatusPending)
		case spam.ResultBlock:
			return spamStatus(domain.CommentStatusSpam)
		}
	}
	return nil
}

// detectorFor 返回与配置指纹匹配的检测器并按指纹缓存。
// 配置变化（含凭据变更）会产生新指纹，不会复用旧检测器。
func (g *SpamGateway) detectorFor(cfg SpamProviderConfig) (spam.Detector, error) {
	fingerprint := spamFingerprint(cfg)
	g.mu.Lock()
	defer g.mu.Unlock()
	if detector, ok := g.cache[fingerprint]; ok {
		return detector, nil
	}
	var detector spam.Detector
	switch cfg.ProviderKey {
	case "spam.local":
		detector = spam.NewLocal(spam.LocalConfig{
			CheckNickname: cfg.CheckNickname,
		}, g.log)
	case "spam.akismet":
		detector = spam.NewAkismet(g.httpClient, spam.AkismetConfig{APIKey: cfg.APIKey})
	case "spam.aliyun":
		detector = spam.NewAlibaba(g.httpClient, spam.AlibabaConfig{
			Region:          cfg.Region,
			AccessKeyID:     cfg.AccessKeyID,
			AccessKeySecret: cfg.AccessKeySecret,
			BizType:         cfg.BizType,
		})
	case "spam.tencent":
		detector = spam.NewTencent(g.httpClient, spam.TencentConfig{
			Region:    cfg.Region,
			SecretID:  cfg.SecretID,
			SecretKey: cfg.SecretKey,
			BizType:   cfg.BizType,
		})
	default:
		return nil, fmt.Errorf("%w: unknown spam provider %q", spam.ErrUnavailable, cfg.ProviderKey)
	}
	g.cache[fingerprint] = detector
	return detector, nil
}

// spamFingerprint 生成不可逆的配置指纹，覆盖全部渠道相关字段。
func spamFingerprint(cfg SpamProviderConfig) string {
	return fmt.Sprintf("%s\x00%t\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		cfg.ProviderKey, cfg.CheckNickname, cfg.Action,
		cfg.APIKey, cfg.Region, cfg.BizType,
		cfg.AccessKeyID, cfg.AccessKeySecret, cfg.SecretID, cfg.SecretKey)
}

// isBinarySpamProvider 报告渠道是否为二元检测器（本地/Akismet）。
func isBinarySpamProvider(providerKey string) bool {
	return providerKey == "spam.local" || providerKey == "spam.akismet"
}

// statusForSpamAction 把二元渠道的命中动作投影为评论状态。
func statusForSpamAction(action string) *domain.CommentStatus {
	if strings.TrimSpace(action) == "spam" {
		return spamStatus(domain.CommentStatusSpam)
	}
	return spamStatus(domain.CommentStatusPending)
}

// spamStatus 返回指向给定状态的指针副本。
func spamStatus(status domain.CommentStatus) *domain.CommentStatus {
	return &status
}

// spamErrorCategory 把检测器错误粗分为日志类别，便于告警聚合。
func spamErrorCategory(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, spam.ErrUnavailable):
		return "unavailable"
	default:
		return "invalid"
	}
}

// commentInitialStatus 按优先级计算评论初始状态：
// 垃圾检测覆盖 pending/spam 优先，其次全局审核策略 review → pending，其余 published。
func commentInitialStatus(moderation string, override *domain.CommentStatus) domain.CommentStatus {
	if override != nil {
		return *override
	}
	if moderation == domain.ModerationReview {
		return domain.CommentStatusPending
	}
	return domain.CommentStatusPublished
}

// optionalString 展开可选字符串指针，nil 返回空串。
func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// siteCanonicalURL 返回站点 CanonicalURL；读取失败时返回空串，
// 垃圾检测不因站点元数据读取失败而阻断评论提交。
func (s *Service) siteCanonicalURL(ctx context.Context, siteID int64) string {
	site, err := s.sites.Get(ctx, siteID)
	if err != nil {
		return ""
	}
	return site.CanonicalURL
}

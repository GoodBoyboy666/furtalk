package comment

import (
	"context"
	"fmt"
	"strings"
	"time"
	_ "time/tzdata"

	"furtalk/internal/domain"
)

const maxCommentTrendDays = 30

// AdminCommentTrend 返回管理概览使用的按日新建评论趋势。
// timezone 必须是有效的 IANA 时区名，统计包含当天并按本地午夜划分区间。
func (s *Service) AdminCommentTrend(ctx context.Context, days int, timezone string) (*domain.CommentTrend, error) {
	if days != 7 && days != 30 {
		return nil, fmt.Errorf("%w: trend days must be 7 or 30", domain.ErrValidation)
	}
	timezone = strings.TrimSpace(timezone)
	if timezone == "" {
		return nil, fmt.Errorf("%w: trend timezone is required", domain.ErrValidation)
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("%w: unsupported trend timezone", domain.ErrValidation)
	}

	localNow := s.now().UTC().In(location)
	today := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, location)
	ranges := make([]domain.CommentTrendRange, 0, maxCommentTrendDays)
	for i := 0; i < days; i++ {
		date := today.AddDate(0, 0, i-(days-1))
		ranges = append(ranges, domain.CommentTrendRange{
			Start: date,
			End:   date.AddDate(0, 0, 1),
		})
	}
	counts, err := s.comments.CountCreatedByRanges(ctx, ranges)
	if err != nil {
		return nil, err
	}
	points := make([]domain.CommentTrendPoint, 0, maxCommentTrendDays)
	for i := 0; i < days; i++ {
		date := today.AddDate(0, 0, i-(days-1))
		points = append(points, domain.CommentTrendPoint{
			Date:  date.Format("2006-01-02"),
			Count: counts[i],
		})
	}
	return &domain.CommentTrend{Days: days, Timezone: timezone, Points: points}, nil
}

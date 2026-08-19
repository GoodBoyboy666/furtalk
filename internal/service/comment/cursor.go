package comment

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"furtalk/internal/domain"
)

// encodeCursor 把 (created_at, id) 位置序列化为不透明的 base64url 游标。
func encodeCursor(createdAt time.Time, id int64) string {
	raw := fmt.Sprintf("%d:%d", createdAt.UTC().UnixMicro(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor 把不透明游标解析回 keyset 位置。
func decodeCursor(raw string) (*domain.Cursor, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, domain.ErrValidation
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, domain.ErrValidation
	}
	micros, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, domain.ErrValidation
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, domain.ErrValidation
	}
	return &domain.Cursor{CreatedAt: time.UnixMicro(micros).UTC(), ID: id}, nil
}

// normalizeLimit 把请求的页面大小限制在允许范围内。
func normalizeLimit(limit int) int {
	if limit <= 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

// normalizeLatestLimit 把站点最新评论请求的返回数量限制在允许范围内（默认 25，最大 25）。
func normalizeLatestLimit(limit int) int {
	if limit <= 0 {
		return defaultLatestLimit
	}
	if limit > maxLatestLimit {
		return maxLatestLimit
	}
	return limit
}

package comment

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"furtalk/internal/domain"
)

// encodeCursor 编码公开排序位置游标。
func encodeCursor(pinned bool, createdAt time.Time, id int64) string {
	group := 0
	if pinned {
		group = 1
	}
	raw := fmt.Sprintf("v2:%d:%d:%d", group, createdAt.UTC().UnixMicro(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// encodeHotCursor 编码热度排序游标。
func encodeHotCursor(pinned bool, likeCount int64, createdAt time.Time, id int64) string {
	group := 0
	if pinned {
		group = 1
	}
	raw := fmt.Sprintf("hot:v2:%d:%d:%d:%d", group, likeCount, createdAt.UTC().UnixMicro(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor 按排序模式解析公开游标。
func decodeCursor(raw string, sort domain.CommentSort) (*domain.Cursor, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, domain.ErrValidation
	}
	text := string(decoded)
	if sort == domain.CommentSortHot {
		return decodeHotCursor(text)
	}
	if strings.HasPrefix(text, "hot:") {
		return nil, domain.ErrValidation
	}
	return decodeDirectionalCursor(text)
}

// decodeDirectionalCursor 解析方向排序游标。
func decodeDirectionalCursor(text string) (*domain.Cursor, error) {
	if strings.HasPrefix(text, "v2:") {
		parts := strings.Split(text, ":")
		if len(parts) != 4 || (parts[1] != "0" && parts[1] != "1") {
			return nil, domain.ErrValidation
		}
		micros, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return nil, domain.ErrValidation
		}
		id, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil {
			return nil, domain.ErrValidation
		}
		return &domain.Cursor{Pinned: parts[1] == "1", CreatedAt: time.UnixMicro(micros).UTC(), ID: id}, nil
	}
	parts := strings.SplitN(text, ":", 2)
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

// decodeHotCursor 解析热度排序游标。
func decodeHotCursor(text string) (*domain.Cursor, error) {
	parts := strings.Split(text, ":")
	if len(parts) == 6 && parts[0] == "hot" && parts[1] == "v2" {
		if parts[2] != "0" && parts[2] != "1" {
			return nil, domain.ErrValidation
		}
		likeCount, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil {
			return nil, domain.ErrValidation
		}
		micros, err := strconv.ParseInt(parts[4], 10, 64)
		if err != nil {
			return nil, domain.ErrValidation
		}
		id, err := strconv.ParseInt(parts[5], 10, 64)
		if err != nil {
			return nil, domain.ErrValidation
		}
		return &domain.Cursor{Pinned: parts[2] == "1", LikeCount: likeCount, CreatedAt: time.UnixMicro(micros).UTC(), ID: id, Hot: true}, nil
	}
	if len(parts) != 4 || parts[0] != "hot" {
		return nil, domain.ErrValidation
	}
	likeCount, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, domain.ErrValidation
	}
	micros, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, domain.ErrValidation
	}
	id, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, domain.ErrValidation
	}
	return &domain.Cursor{LikeCount: likeCount, CreatedAt: time.UnixMicro(micros).UTC(), ID: id, Hot: true}, nil
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

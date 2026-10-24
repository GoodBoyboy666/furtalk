package comment

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"furtalk/internal/domain"
)

// encodeRootCursor 编码站点、线程和排序绑定的根评论游标。
func encodeRootCursor(siteID, threadID int64, sort domain.CommentSort, row domain.PublicRootComment) string {
	pinned := 0
	if row.IsPinned {
		pinned = 1
	}
	likes := int64(0)
	if sort == domain.CommentSortHot {
		likes = row.LikeCount
	}
	payload := fmt.Sprintf("roots:v1:%d:%d:%s:%d:%d:%d:%d", siteID, threadID, sort, pinned, likes, row.CreatedAt.UTC().UnixMicro(), row.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

// encodeReplyCursor 编码站点、线程和可见根绑定的回复游标。
func encodeReplyCursor(siteID, threadID, rootID int64, row domain.PublicComment) string {
	payload := fmt.Sprintf("replies:v1:%d:%d:%d:%d:%d", siteID, threadID, rootID, row.CreatedAt.UTC().UnixMicro(), row.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

// decodePageCursorFields 解码固定命名空间和字段数的分页游标。
func decodePageCursorFields(raw, namespace string, count int) ([]string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, domain.ErrValidation
	}
	fields := strings.Split(string(decoded), ":")
	if len(fields) != count || fields[0] != namespace || fields[1] != "v1" {
		return nil, domain.ErrValidation
	}
	return fields, nil
}

// parsePageCursorNumber 校验游标中的非负数字字段。
func parsePageCursorNumber(raw string) (int64, error) {
	// 仅接收十进制数字，避免符号或空白形成另一种游标表示。
	if raw == "" || strings.IndexFunc(raw, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, domain.ErrValidation
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, domain.ErrValidation
	}
	return n, nil
}

// decodeRootCursor 校验根评论游标的请求作用域并恢复排序位置。
func decodeRootCursor(raw string, siteID, threadID int64, sort domain.CommentSort) (*domain.Cursor, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	fields, err := decodePageCursorFields(raw, "roots", 9)
	if err != nil {
		return nil, err
	}
	if fields[4] != string(sort) || !domain.ValidPublicCommentSort(fields[4]) || (fields[5] != "0" && fields[5] != "1") {
		return nil, domain.ErrValidation
	}
	numbers := make([]int64, 0, 5)
	for _, i := range []int{2, 3, 6, 7, 8} {
		n, err := parsePageCursorNumber(fields[i])
		if err != nil {
			return nil, err
		}
		numbers = append(numbers, n)
	}
	if numbers[0] != siteID || numbers[0] <= 0 || numbers[1] != threadID || numbers[1] <= 0 || numbers[4] <= 0 || (sort != domain.CommentSortHot && numbers[2] != 0) {
		return nil, domain.ErrValidation
	}
	return &domain.Cursor{Pinned: fields[5] == "1", LikeCount: numbers[2], CreatedAt: time.UnixMicro(numbers[3]).UTC(), ID: numbers[4], Hot: sort == domain.CommentSortHot}, nil
}

// decodeReplyCursor 校验回复游标的站点、线程和可见根作用域。
func decodeReplyCursor(raw string, siteID, threadID, rootID int64) (*domain.Cursor, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	fields, err := decodePageCursorFields(raw, "replies", 7)
	if err != nil {
		return nil, err
	}
	numbers := make([]int64, 0, 5)
	for _, field := range fields[2:] {
		n, err := parsePageCursorNumber(field)
		if err != nil {
			return nil, err
		}
		numbers = append(numbers, n)
	}
	if numbers[0] != siteID || numbers[0] <= 0 || numbers[1] != threadID || numbers[1] <= 0 || numbers[2] != rootID || numbers[2] <= 0 || numbers[4] <= 0 {
		return nil, domain.ErrValidation
	}
	return &domain.Cursor{CreatedAt: time.UnixMicro(numbers[3]).UTC(), ID: numbers[4]}, nil
}

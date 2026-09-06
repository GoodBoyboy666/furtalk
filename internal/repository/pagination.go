package repository

import "furtalk/internal/domain"

// applyCursorOrder 返回与 keyset 谓词同向的 ORDER BY 片段。
func applyCursorOrder(qualifier string, sort domain.CommentSort) string {
	prefix := ""
	if qualifier != "" {
		prefix = qualifier + "."
	}
	if sort == domain.CommentSortDesc {
		return prefix + "created_at DESC, " + prefix + "id DESC"
	}
	return prefix + "created_at ASC, " + prefix + "id ASC"
}

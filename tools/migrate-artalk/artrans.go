package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Artran 表示 Artalk Artrans 交换格式中的一条记录。
// 各字段使用 flexibleString 兼容字符串、数字和布尔值输入。
type Artran struct {
	ID            flexibleString `json:"id"`
	RID           flexibleString `json:"rid"`
	Content       flexibleString `json:"content"`
	UA            flexibleString `json:"ua"`
	IP            flexibleString `json:"ip"`
	CreatedAt     flexibleString `json:"created_at"`
	UpdatedAt     flexibleString `json:"updated_at"`
	IsCollapsed   flexibleString `json:"is_collapsed"`
	IsPending     flexibleString `json:"is_pending"`
	IsPinned      flexibleString `json:"is_pinned"`
	VoteUp        flexibleString `json:"vote_up"`
	VoteDown      flexibleString `json:"vote_down"`
	Nick          flexibleString `json:"nick"`
	Email         flexibleString `json:"email"`
	Link          flexibleString `json:"link"`
	BadgeName     flexibleString `json:"badge_name"`
	BadgeColor    flexibleString `json:"badge_color"`
	PageKey       flexibleString `json:"page_key"`
	PageTitle     flexibleString `json:"page_title"`
	PageAdminOnly flexibleString `json:"page_admin_only"`
	SiteName      flexibleString `json:"site_name"`
	SiteURLs      flexibleString `json:"site_urls"`
}

// id 返回去除首尾空白的记录标识。
func (a Artran) id() string { return strings.TrimSpace(string(a.ID)) }

// rid 返回去除首尾空白的父记录标识。
func (a Artran) rid() string { return strings.TrimSpace(string(a.RID)) }

// content 返回评论正文。
func (a Artran) content() string { return string(a.Content) }

// ua 返回原始 User-Agent。
func (a Artran) ua() string { return string(a.UA) }

// ip 返回去除首尾空白的 IP 地址。
func (a Artran) ip() string { return strings.TrimSpace(string(a.IP)) }

// createdAt 返回去除首尾空白的创建时间文本。
func (a Artran) createdAt() string { return strings.TrimSpace(string(a.CreatedAt)) }

// updatedAt 返回去除首尾空白的更新时间文本。
func (a Artran) updatedAt() string { return strings.TrimSpace(string(a.UpdatedAt)) }

// nick 返回去除首尾空白的昵称。
func (a Artran) nick() string { return strings.TrimSpace(string(a.Nick)) }

// email 返回去除首尾空白的邮箱。
func (a Artran) email() string { return strings.TrimSpace(string(a.Email)) }

// link 返回去除首尾空白的网站链接。
func (a Artran) link() string { return strings.TrimSpace(string(a.Link)) }

// pageKey 返回去除首尾空白的页面标识。
func (a Artran) pageKey() string { return strings.TrimSpace(string(a.PageKey)) }

// pageTitle 返回去除首尾空白的页面标题。
func (a Artran) pageTitle() string { return strings.TrimSpace(string(a.PageTitle)) }

// siteName 返回去除首尾空白的站点名称。
func (a Artran) siteName() string { return strings.TrimSpace(string(a.SiteName)) }

// siteURLs 返回原始站点 URL 列表文本。
func (a Artran) siteURLs() string { return string(a.SiteURLs) }

// isPending 解析记录的待审核标记。
func (a Artran) isPending() (bool, error) {
	return parseFlexibleBool("is_pending", string(a.IsPending))
}

// isCollapsed 解析记录的折叠标记。
func (a Artran) isCollapsed() (bool, error) {
	return parseFlexibleBool("is_collapsed", string(a.IsCollapsed))
}

// isPinned 解析记录的置顶标记。
func (a Artran) isPinned() (bool, error) {
	return parseFlexibleBool("is_pinned", string(a.IsPinned))
}

// pageAdminOnly 解析页面的管理员可见标记。
func (a Artran) pageAdminOnly() (bool, error) {
	return parseFlexibleBool("page_admin_only", string(a.PageAdminOnly))
}

type flexibleString string

// UnmarshalJSON 将 JSON 标量转换为兼容字符串。
func (s *flexibleString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if bytes.Equal(data, []byte("null")) {
		*s = ""
		return nil
	}
	if len(data) > 0 && data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		*s = flexibleString(value)
		return nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	switch typed := value.(type) {
	case json.Number:
		*s = flexibleString(typed.String())
	case bool:
		*s = flexibleString(strconv.FormatBool(typed))
	default:
		return fmt.Errorf("expected string, number, boolean, or null")
	}
	return nil
}

// Parse 读取并解码 Artalk Artrans 数据。
func Parse(reader io.Reader) ([]Artran, error) {
	// 输入可以是 gzip 数据，也可以是带 artrans 字段的 JSON 包装。
	buffered := bufio.NewReader(reader)
	header, err := buffered.Peek(2)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read Artrans header: %w", err)
	}
	var input io.Reader = buffered
	if len(header) == 2 && header[0] == 0x1f && header[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, fmt.Errorf("open gzip Artrans: %w", err)
		}
		defer gz.Close()
		input = gz
	}
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("read Artrans: %w", err)
	}
	data = bytes.TrimPrefix(bytes.TrimSpace(data), []byte{0xef, 0xbb, 0xbf})
	if len(data) == 0 {
		return nil, fmt.Errorf("Artrans input is empty")
	}
	var records []Artran
	if data[0] == '[' {
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, fmt.Errorf("decode Artrans array: %w", err)
		}
		return records, nil
	}
	var envelope struct {
		Artrans json.RawMessage `json:"artrans"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode Artrans input: %w", err)
	}
	if len(envelope.Artrans) == 0 {
		return nil, fmt.Errorf("JSON object does not contain an artrans field")
	}
	var encoded string
	if err := json.Unmarshal(envelope.Artrans, &encoded); err == nil {
		if err := json.Unmarshal([]byte(encoded), &records); err != nil {
			return nil, fmt.Errorf("decode wrapped Artrans array: %w", err)
		}
		return records, nil
	}
	if err := json.Unmarshal(envelope.Artrans, &records); err != nil {
		return nil, fmt.Errorf("decode wrapped Artrans array: %w", err)
	}
	return records, nil
}

// parseFlexibleBool 将常见布尔文本解析为布尔值。
func parseFlexibleBool(field, raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("%s has invalid boolean value %q", field, raw)
	}
}

// nonZero 判断数值文本是否非零或无法解析。
func nonZero(raw flexibleString) bool {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return err != nil || n != 0
}

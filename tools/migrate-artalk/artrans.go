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

// Artran is one record in Artalk's Artrans interchange format. Artalk defines
// every field as a string, but older converters sometimes emit JSON numbers or
// booleans; flexibleString accepts both representations.
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

func (a Artran) id() string        { return strings.TrimSpace(string(a.ID)) }
func (a Artran) rid() string       { return strings.TrimSpace(string(a.RID)) }
func (a Artran) content() string   { return string(a.Content) }
func (a Artran) ua() string        { return string(a.UA) }
func (a Artran) ip() string        { return strings.TrimSpace(string(a.IP)) }
func (a Artran) createdAt() string { return strings.TrimSpace(string(a.CreatedAt)) }
func (a Artran) updatedAt() string { return strings.TrimSpace(string(a.UpdatedAt)) }
func (a Artran) nick() string      { return strings.TrimSpace(string(a.Nick)) }
func (a Artran) email() string     { return strings.TrimSpace(string(a.Email)) }
func (a Artran) link() string      { return strings.TrimSpace(string(a.Link)) }
func (a Artran) pageKey() string   { return strings.TrimSpace(string(a.PageKey)) }
func (a Artran) pageTitle() string { return strings.TrimSpace(string(a.PageTitle)) }
func (a Artran) siteName() string  { return strings.TrimSpace(string(a.SiteName)) }
func (a Artran) siteURLs() string  { return string(a.SiteURLs) }
func (a Artran) isPending() (bool, error) {
	return parseFlexibleBool("is_pending", string(a.IsPending))
}
func (a Artran) isCollapsed() (bool, error) {
	return parseFlexibleBool("is_collapsed", string(a.IsCollapsed))
}
func (a Artran) isPinned() (bool, error) {
	return parseFlexibleBool("is_pinned", string(a.IsPinned))
}
func (a Artran) pageAdminOnly() (bool, error) {
	return parseFlexibleBool("page_admin_only", string(a.PageAdminOnly))
}

type flexibleString string

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

// Parse reads a raw Artrans array. It also accepts gzip input and the
// {"artrans":"[...]"} envelope returned by Artalk's export HTTP API.
func Parse(reader io.Reader) ([]Artran, error) {
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

func nonZero(raw flexibleString) bool {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return err != nil || n != 0
}

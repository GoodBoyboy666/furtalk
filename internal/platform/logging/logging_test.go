package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// decode 把缓冲区的单行 JSON 记录解码为 map。
func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode log JSON: %v\nraw: %s", err, buf.String())
	}
	return record
}

// TestNewEmitsTextInfo 验证默认 New 输出 INFO 级别的 text 记录。
func TestNewEmitsTextInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	logger.Info("hello", "key", "value")
	line := buf.String()
	if !strings.Contains(line, "level=INFO") {
		t.Fatalf("level = %q, want text INFO", line)
	}
	if !strings.Contains(line, "msg=hello") {
		t.Fatalf("msg = %q, want text hello", line)
	}
	if !strings.Contains(line, "key=value") {
		t.Fatalf("key = %q, want text value", line)
	}
}

// TestNewWithFormatJSONEmitsInfo 验证显式 json 构造输出 INFO 级别的 JSON 记录。
func TestNewWithFormatJSONEmitsInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON)
	logger.Info("hello", "key", "value")
	record := decode(t, &buf)
	if record["msg"] != "hello" {
		t.Fatalf("msg = %v, want hello", record["msg"])
	}
	if record["level"] != "INFO" {
		t.Fatalf("level = %v, want INFO", record["level"])
	}
	if record["key"] != "value" {
		t.Fatalf("key = %v, want value", record["key"])
	}
}

// TestNewWithFormatEmptyFallsBackToText 验证空格式回退为 text 构造。
func TestNewWithFormatEmptyFallsBackToText(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, "")
	logger.Info("hello", "key", "value")
	if !strings.Contains(buf.String(), "level=INFO") {
		t.Fatalf("empty format must produce text, got %q", buf.String())
	}
}

// TestNewDropsDebug 验证 INFO 阈值会丢弃 debug 记录。
func TestNewDropsDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	logger.Debug("should be dropped")
	if buf.Len() != 0 {
		t.Fatalf("debug record emitted: %s", buf.String())
	}
}

// TestAttrHelpers 验证公共属性 helper 的字段名与类型约定。
func TestAttrHelpers(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON)
	logger.Info("attrs",
		Error(errors.New("boom")),
		RequestID("req-1"),
		ID("user_id", 42),
		ID("comment_id", 7),
		Duration(1500*time.Millisecond),
	)
	record := decode(t, &buf)
	if record["error"] != "boom" {
		t.Fatalf("error = %v, want boom", record["error"])
	}
	if record["request_id"] != "req-1" {
		t.Fatalf("request_id = %v, want req-1", record["request_id"])
	}
	if record["user_id"] != "42" {
		t.Fatalf("user_id = %#v, want string 42", record["user_id"])
	}
	if _, ok := record["user_id"].(string); !ok {
		t.Fatalf("user_id must be a decimal string, got %T", record["user_id"])
	}
	if record["comment_id"] != "7" {
		t.Fatalf("comment_id = %v, want 7", record["comment_id"])
	}
	if record["duration_ms"] != float64(1500) {
		t.Fatalf("duration_ms = %v, want 1500", record["duration_ms"])
	}
	if _, ok := record["duration_ms"].(float64); !ok {
		t.Fatalf("duration_ms must stay a JSON number, got %T", record["duration_ms"])
	}
}

// TestNormalizeAndDiscard 验证 nil 规范化与 discard logger 行为。
func TestNormalizeAndDiscard(t *testing.T) {
	if Normalize(nil) == nil {
		t.Fatal("Normalize(nil) must return a non-nil logger")
	}
	base := New(io.Discard)
	if Normalize(base) != base {
		t.Fatal("Normalize must return the given logger when non-nil")
	}
	var buf bytes.Buffer
	Discard().Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("discard logger emitted: %s", buf.String())
	}
}

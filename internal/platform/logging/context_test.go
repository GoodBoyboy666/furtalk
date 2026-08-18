package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestWithAttrsMergesAndIsolates 验证属性追加不可变：父子 context 互不影响。
func TestWithAttrsMergesAndIsolates(t *testing.T) {
	ctx := context.Background()
	parent := WithAttrs(ctx, RequestID("req-1"))
	child := WithAttrs(parent, ID("user_id", 42))

	if got := AttrsFrom(ctx); len(got) != 0 {
		t.Fatalf("background attrs = %v, want none", got)
	}
	parentAttrs := AttrsFrom(parent)
	if len(parentAttrs) != 1 || parentAttrs[0].Key != "request_id" {
		t.Fatalf("parent attrs = %v, want [request_id]", parentAttrs)
	}
	childAttrs := AttrsFrom(child)
	if len(childAttrs) != 2 {
		t.Fatalf("child attrs = %d, want 2", len(childAttrs))
	}
	if childAttrs[0].Key != "request_id" || childAttrs[1].Key != "user_id" {
		t.Fatalf("child attrs = %v, want [request_id user_id]", childAttrs)
	}
}

// TestFromContext 验证从 context 派生 logger：无属性返回 base，有属性附加。
func TestFromContext(t *testing.T) {
	base := Discard()
	if got := FromContext(context.Background(), base); got != base {
		t.Fatal("FromContext without attrs must return the base logger")
	}
	if got := FromContext(context.Background(), nil); got == nil {
		t.Fatal("FromContext with nil base must not return nil")
	}

	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON)
	ctx := WithAttrs(context.Background(), RequestID("req-1"))
	FromContext(ctx, logger).Info("with request")
	record := decode(t, &buf)
	if record["request_id"] != "req-1" {
		t.Fatalf("request_id = %v, want req-1", record["request_id"])
	}
}

// TestRequestsDoNotLeakAttrs 验证连续请求的关联属性互不串用。
func TestRequestsDoNotLeakAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWithFormat(&buf, FormatJSON)
	reqA := WithAttrs(context.Background(), RequestID("req-a"), ID("user_id", 1))
	reqB := WithAttrs(context.Background(), RequestID("req-b"), ID("user_id", 2))
	FromContext(reqA, logger).Info("request a")
	FromContext(reqB, logger).Info("request b")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("records = %d, want 2", len(lines))
	}
	var a, b map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &b); err != nil {
		t.Fatal(err)
	}
	if a["user_id"] != "1" || a["request_id"] != "req-a" {
		t.Fatalf("record a = %v", a)
	}
	if b["user_id"] != "2" || b["request_id"] != "req-b" {
		t.Fatalf("record b = %v", b)
	}
}

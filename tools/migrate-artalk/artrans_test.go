package main

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestParseAcceptsFlexibleFieldsAndAPIEnvelope(t *testing.T) {
	payload := `{"artrans":"[{\"id\":12,\"rid\":0,\"content\":\"hello\",\"is_pending\":false,\"page_key\":\"/post\",\"site_name\":\"Blog\"}]"}`
	records, err := Parse(bytes.NewBufferString(payload))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if records[0].id() != "12" || records[0].rid() != "0" || records[0].content() != "hello" {
		t.Fatalf("record = %+v", records[0])
	}
	pending, err := records[0].isPending()
	if err != nil || pending {
		t.Fatalf("is_pending = %v, err = %v", pending, err)
	}
}

func TestParseAcceptsGzip(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`[{"id":"1"}]`)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	records, err := Parse(&compressed)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(records) != 1 || records[0].id() != "1" {
		t.Fatalf("records = %+v", records)
	}
}

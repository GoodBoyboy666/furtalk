package handler

import (
	"errors"
	"testing"

	"furtalk/internal/platform/httpx"
)

func TestParseBatchIDsAcceptsUniqueDecimalIDs(t *testing.T) {
	ids, err := parseBatchIDs([]string{"12", "18"})
	if err != nil {
		t.Fatalf("parseBatchIDs: %v", err)
	}
	if len(ids) != 2 || ids[0] != 12 || ids[1] != 18 {
		t.Fatalf("ids = %#v, want [12 18]", ids)
	}
}

func TestParseBatchIDsRejectsEmptyDuplicateAndOversizedInput(t *testing.T) {
	for name, raw := range map[string][]string{
		"empty":     {},
		"duplicate": {"12", "12"},
		"oversized": make([]string, 101),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBatchIDs(raw); !errors.Is(err, httpx.ErrInvalidID) {
				t.Fatalf("error = %v, want ErrInvalidID", err)
			}
		})
	}
}

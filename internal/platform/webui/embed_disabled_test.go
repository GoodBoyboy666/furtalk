//go:build !embed

package webui

import (
	"errors"
	"testing"
)

func TestFSRequiresEmbedBuild(t *testing.T) {
	_, err := FS()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("FS() error = %v, want ErrUnavailable", err)
	}
}

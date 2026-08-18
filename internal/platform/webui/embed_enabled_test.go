//go:build embed

package webui

import (
	"io/fs"
	"testing"
)

func TestFSContainsIndex(t *testing.T) {
	assets, err := FS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		t.Fatalf("embedded index.html: %v", err)
	}
}

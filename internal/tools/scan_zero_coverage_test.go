package tools_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanZeroFilesIsNotClean: an empty or unreadable scope must not be
// described as clean. The text has to point at coverage instead.
func TestScanZeroFilesIsNotClean(t *testing.T) {
	h := newHarness(t)
	empty := filepath.Join(h.repo, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatalf("create empty dir: %v", err)
	}

	res := callTool(t, h.client, "vigil_scan", map[string]any{"path": "empty", "mode": "quick"})
	if res.IsError {
		t.Fatalf("scan failed: %+v", res.Content)
	}
	text := textOf(t, res)
	if !strings.Contains(text, "not a clean result") {
		t.Errorf("zero-file scan claims a clean result:\n%s", text)
	}
	if strings.Contains(text, "scope is clean") {
		t.Errorf("zero-file scan still says the scope is clean:\n%s", text)
	}
}

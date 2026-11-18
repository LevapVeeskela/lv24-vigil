package tools_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCoverageSkipReasonsOverMCP: the coverage block names why files were
// skipped and states that no network channel was used in the harness.
func TestCoverageSkipReasonsOverMCP(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(filepath.Join(h.repo, "blob.dat"), []byte("abc\x00def"), 0o644); err != nil {
		t.Fatalf("write binary fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.repo, "app.min.js"), []byte("var x = 1\n"), 0o644); err != nil {
		t.Fatalf("write ignored fixture: %v", err)
	}

	payload := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_scan", map[string]any{"mode": "quick"}))
	if payload.Coverage == nil {
		t.Fatal("scan payload has no coverage block")
	}
	cov := payload.Coverage
	if cov.SkipReasons["binary"] != 1 || cov.SkipReasons["ignored"] != 1 {
		t.Errorf("skipReasons = %v, want binary 1 and ignored 1", cov.SkipReasons)
	}
	sum := 0
	for _, count := range cov.SkipReasons {
		sum += count
	}
	if sum != cov.FilesSkipped {
		t.Errorf("sum(skipReasons) = %d, filesSkipped = %d (reasons: %v)", sum, cov.FilesSkipped, cov.SkipReasons)
	}
	if cov.NetworkUsed || cov.LLMUsed {
		t.Errorf("coverage claims network/model use in a deterministic scan: %+v", cov)
	}

	text := textOf(t, h.client.mustTool("vigil_scan", map[string]any{"mode": "quick"}))
	for _, want := range []string{"skipped: binary 1, ignored 1", "network not used"} {
		if !strings.Contains(text, want) {
			t.Errorf("coverage text missing %q:\n%s", want, text)
		}
	}
}

// TestCoverageNoSkipReasonsOverMCP: a scan with nothing skipped omits the map
// and keeps the coverage line clean.
func TestCoverageNoSkipReasonsOverMCP(t *testing.T) {
	h := newHarness(t)

	payload := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_scan", map[string]any{"mode": "quick"}))
	if payload.Coverage == nil {
		t.Fatal("scan payload has no coverage block")
	}
	if payload.Coverage.SkipReasons != nil {
		t.Errorf("skipReasons = %v, want nil when nothing was skipped", payload.Coverage.SkipReasons)
	}
	if payload.Coverage.FilesSkipped != 0 {
		t.Errorf("filesSkipped = %d, want 0", payload.Coverage.FilesSkipped)
	}
	text := textOf(t, h.client.mustTool("vigil_scan", map[string]any{"mode": "quick"}))
	if strings.Contains(text, "skipped: ") {
		t.Errorf("coverage text invents skip reasons:\n%s", text)
	}
	if !strings.Contains(text, "network not used") {
		t.Errorf("coverage text does not state the network posture:\n%s", text)
	}
}

package tools_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/store"
)

// pageJSON mirrors the page object every list tool returns.
type pageJSON struct {
	Offset     int  `json:"offset"`
	Limit      int  `json:"limit"`
	Total      int  `json:"total"`
	HasMore    bool `json:"hasMore"`
	NextOffset *int `json:"nextOffset"`
}

type coverageJSON struct {
	FilesScanned int            `json:"filesScanned"`
	FilesSkipped int            `json:"filesSkipped"`
	BytesScanned int64          `json:"bytesScanned"`
	Errors       []string       `json:"errors"`
	LLMUsed      bool           `json:"llmUsed"`
	SkipReasons  map[string]int `json:"skipReasons"`
	NetworkUsed  bool           `json:"networkUsed"`
}

// scanWindowPayload decodes a scan result together with its pagination and
// coverage blocks; the embedded pointer keeps the model.ScanResult shape.
type scanWindowPayload struct {
	*model.ScanResult
	Page     *pageJSON     `json:"page"`
	Coverage *coverageJSON `json:"coverage"`
}

type rulesWindowPayload struct {
	Count   int              `json:"count"`
	Total   int              `json:"total"`
	Matched int              `json:"matched"`
	Page    pageJSON         `json:"page"`
	Rules   []model.RuleMeta `json:"rules"`
}

type historyWindowPayload struct {
	Count      int             `json:"count"`
	Total      int             `json:"total"`
	HasMore    bool            `json:"hasMore"`
	NextOffset *int            `json:"nextOffset"`
	Page       pageJSON        `json:"page"`
	Scans      []store.Summary `json:"scans"`
}

// writeDistinctKeys writes n unique hardcoded AWS keys, one per line, so each
// line produces its own finding.
func writeDistinctKeys(t *testing.T, path string, n int) {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("aws_access_key_id = \"AKIA")
		for j := 0; j < 16; j++ {
			b.WriteByte(alphabet[(i*7+j*11)%len(alphabet)])
		}
		b.WriteString("\"\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestScanPaginationWindow covers the scan page envelope: the window is
// sliced, total is the honest pre-cap count, and nextOffset resumes exactly.
func TestScanPaginationWindow(t *testing.T) {
	h := newHarness(t)
	writeDistinctKeys(t, filepath.Join(h.repo, "many.py"), 9)

	full := h.scan()
	want := full.Stats.FindingsTotal
	if want < len(full.Findings) {
		want = len(full.Findings)
	}
	if want < 10 {
		t.Fatalf("fixture produced %d findings, want at least 10", want)
	}

	first := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_scan", map[string]any{
		"mode": "quick", "maxFindings": 4,
	}))
	if first.Page == nil || first.Coverage == nil {
		t.Fatalf("scan payload has no page/coverage: %+v", first)
	}
	if len(first.Findings) != 4 {
		t.Errorf("first window has %d findings, want 4", len(first.Findings))
	}
	if first.Page.Offset != 0 || first.Page.Limit != 4 || first.Page.Total != want || !first.Page.HasMore {
		t.Errorf("first page = %+v, want offset 0 limit 4 total %d hasMore", first.Page, want)
	}
	if first.Page.NextOffset == nil || *first.Page.NextOffset != 4 {
		t.Errorf("first nextOffset = %v, want 4", first.Page.NextOffset)
	}
	if first.Stats.FindingsTotal != want {
		t.Errorf("stats.findingsTotal = %d, want %d", first.Stats.FindingsTotal, want)
	}
	if first.Coverage.FilesScanned < 2 || first.Coverage.BytesScanned <= 0 {
		t.Errorf("coverage does not describe the scan: %+v", first.Coverage)
	}
	if first.Coverage.LLMUsed {
		t.Errorf("coverage claims a model was used without one configured")
	}
	if len(first.Coverage.Errors) != 0 {
		t.Errorf("coverage errors = %v, want none", first.Coverage.Errors)
	}
	firstText := textOf(t, h.client.mustTool("vigil_scan", map[string]any{"mode": "quick", "maxFindings": 4}))
	for _, wantLine := range []string{"Page: Showing 1-4 of", "pass offset=4 to continue", "Coverage:", "network not used"} {
		if !strings.Contains(firstText, wantLine) {
			t.Errorf("scan text missing %q:\n%s", wantLine, firstText)
		}
	}

	second := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_scan", map[string]any{
		"mode": "quick", "maxFindings": 4, "offset": 4,
	}))
	if len(second.Findings) != 4 || second.Page.Offset != 4 {
		t.Errorf("second window = %d findings at offset %d, want 4 at 4", len(second.Findings), second.Page.Offset)
	}
	if second.Page.NextOffset == nil || *second.Page.NextOffset != 8 {
		t.Errorf("second nextOffset = %v, want 8", second.Page.NextOffset)
	}

	last := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_scan", map[string]any{
		"mode": "quick", "maxFindings": 4, "offset": want - 2,
	}))
	if last.Page.Total != want || last.Page.HasMore || last.Page.NextOffset != nil {
		t.Errorf("last page = %+v, want total %d with no next page", last.Page, want)
	}
	if got := len(last.Findings); got != 2 {
		t.Errorf("last window has %d findings, want 2", got)
	}
	lastText := textOf(t, h.client.mustTool("vigil_scan", map[string]any{
		"mode": "quick", "maxFindings": 4, "offset": want - 2,
	}))
	if !strings.Contains(lastText, fmt.Sprintf("Showing %d-%d of %d.", want-1, want, want)) || strings.Contains(lastText, "pass offset=") {
		t.Errorf("last page text does not close the range:\n%s", lastText)
	}
}

// TestScanPaginationEdges: an offset beyond the total is an empty window, a
// negative offset is an argument error, and a full window says so.
func TestScanPaginationEdges(t *testing.T) {
	h := newHarness(t)
	full := h.scan()
	want := full.Stats.FindingsTotal
	if want < len(full.Findings) {
		want = len(full.Findings)
	}

	beyond := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_scan", map[string]any{
		"mode": "quick", "maxFindings": 5, "offset": 100,
	}))
	if len(beyond.Findings) != 0 {
		t.Errorf("offset beyond total returned %d findings, want 0", len(beyond.Findings))
	}
	if beyond.Page == nil || beyond.Page.HasMore || beyond.Page.NextOffset != nil {
		t.Errorf("beyond page = %+v, want an exhausted page", beyond.Page)
	}
	if text := textOf(t, h.client.mustTool("vigil_scan", map[string]any{"mode": "quick", "maxFindings": 5, "offset": 100})); !strings.Contains(text, "past the end") {
		t.Errorf("past-the-end text does not say so:\n%s", text)
	}

	neg := callTool(t, h.client, "vigil_scan", map[string]any{"mode": "quick", "offset": -1})
	if code := toolErrorCode(t, neg); code != "VGL-ARGS" {
		t.Errorf("negative offset code = %q, want VGL-ARGS", code)
	}

	all := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_scan", map[string]any{
		"mode": "quick", "maxFindings": 500,
	}))
	if all.Page.HasMore || all.Page.Total != want {
		t.Errorf("full page = %+v, want total %d and no more", all.Page, want)
	}
	if text := textOf(t, h.client.mustTool("vigil_scan", map[string]any{"mode": "quick", "maxFindings": 500})); !strings.Contains(text, "Showing all") {
		t.Errorf("full window text does not say all:\n%s", text)
	}
}

// TestReviewPaginationWindow: review wraps the same page/coverage envelope.
func TestReviewPaginationWindow(t *testing.T) {
	h := newHarness(t)
	var diff strings.Builder
	diff.WriteString("--- a/example.py\n+++ b/example.py\n@@ -0,0 +1,3 @@\n")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	for i := 0; i < 4; i++ {
		var key strings.Builder
		key.WriteString("+aws_access_key_id = \"AKIA")
		for j := 0; j < 16; j++ {
			key.WriteByte(alphabet[(i*7+j*11)%len(alphabet)])
		}
		key.WriteString("\"\n")
		diff.WriteString(key.String())
	}

	full := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_review", map[string]any{"diff": diff.String()}))
	want := len(full.Findings)
	if want < 3 {
		t.Fatalf("review fixture produced %d findings, want at least 3", want)
	}

	page := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_review", map[string]any{
		"diff": diff.String(), "maxFindings": 2,
	}))
	if len(page.Findings) != 2 || page.Page.Total != want || !page.Page.HasMore {
		t.Errorf("review window = %d findings, page %+v, want 2 of %d", len(page.Findings), page.Page, want)
	}
	if page.Page.NextOffset == nil || *page.Page.NextOffset != 2 {
		t.Errorf("review nextOffset = %v, want 2", page.Page.NextOffset)
	}
	if page.Coverage == nil || page.Coverage.LLMUsed {
		t.Errorf("review coverage = %+v, want deterministic coverage", page.Coverage)
	}
	text := textOf(t, h.client.mustTool("vigil_review", map[string]any{"diff": diff.String(), "maxFindings": 2}))
	if !strings.Contains(text, "pass offset=2 to continue") {
		t.Errorf("review text does not state how to resume:\n%s", text)
	}

	neg := callTool(t, h.client, "vigil_review", map[string]any{"diff": diff.String(), "offset": -1})
	if code := toolErrorCode(t, neg); code != "VGL-ARGS" {
		t.Errorf("review negative offset code = %q, want VGL-ARGS", code)
	}
}

// TestHardeningPaginationEnvelope: an empty and an overshot hardening page are
// both valid, with a page object and no error.
func TestHardeningPaginationEnvelope(t *testing.T) {
	h := newHarness(t)

	page := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_hardening", map[string]any{"offset": 50}))
	if page.Page == nil || page.Page.Total != 0 || page.Page.HasMore || page.Page.NextOffset != nil {
		t.Errorf("empty hardening page = %+v, want an exhausted empty page", page.Page)
	}
	if page.Coverage == nil {
		t.Errorf("hardening payload has no coverage block")
	}
	text := textOf(t, h.client.mustTool("vigil_hardening", map[string]any{}))
	if !strings.Contains(text, "Page: ") || !strings.Contains(text, "Coverage:") {
		t.Errorf("hardening text has no page/coverage lines:\n%s", text)
	}
}

// TestRulesPagination: the catalog is windowed after filtering. total is the
// full catalog, matched is the filtered count and page.total is the windowed
// one.
func TestRulesPagination(t *testing.T) {
	h := newHarness(t)

	first := structuredInto[rulesWindowPayload](t, h.client.mustTool("vigil_rules", map[string]any{"limit": 5}))
	if first.Total < 10 {
		t.Fatalf("rule catalog total = %d, want a realistic catalog", first.Total)
	}
	if first.Count != 5 || len(first.Rules) != 5 {
		t.Errorf("first page has count %d and %d rules, want 5", first.Count, len(first.Rules))
	}
	if first.Matched != first.Total {
		t.Errorf("unfiltered matched = %d, total = %d", first.Matched, first.Total)
	}
	if first.Page.Total != first.Total || !first.Page.HasMore || first.Page.NextOffset == nil || *first.Page.NextOffset != 5 {
		t.Errorf("first rules page = %+v, total %d", first.Page, first.Total)
	}

	filtered := structuredInto[rulesWindowPayload](t, h.client.mustTool("vigil_rules", map[string]any{
		"category": "secrets", "limit": 5,
	}))
	if filtered.Total != first.Total {
		t.Errorf("filtered total = %d, want the catalog total %d", filtered.Total, first.Total)
	}
	if filtered.Matched == 0 || filtered.Matched >= filtered.Total {
		t.Errorf("filtered matched = %d, catalog total = %d, want a strict subset", filtered.Matched, filtered.Total)
	}
	if filtered.Page.Total != filtered.Matched {
		t.Errorf("filtered page.total = %d, want %d", filtered.Page.Total, filtered.Matched)
	}

	last := structuredInto[rulesWindowPayload](t, h.client.mustTool("vigil_rules", map[string]any{
		"limit": 5, "offset": first.Total - 2,
	}))
	if last.Count != 2 || len(last.Rules) != 2 || last.Page.HasMore || last.Page.NextOffset != nil {
		t.Errorf("last rules page = count %d, page %+v, want 2 exhausted", last.Count, last.Page)
	}
	if text := textOf(t, h.client.mustTool("vigil_rules", map[string]any{"limit": 5})); !strings.Contains(text, "pass offset=5 to continue") {
		t.Errorf("rules text does not state the window:\n%s", text)
	}

	neg := callTool(t, h.client, "vigil_rules", map[string]any{"offset": -1})
	if code := toolErrorCode(t, neg); code != "VGL-ARGS" {
		t.Errorf("rules negative offset code = %q, want VGL-ARGS", code)
	}
}

// TestHistoryPagination: history states the stored total, not the window size.
func TestHistoryPagination(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 3; i++ {
		h.scan()
	}

	first := structuredInto[historyWindowPayload](t, h.client.mustTool("vigil_history", map[string]any{"limit": 2}))
	if first.Total != 3 || first.Count != 2 || len(first.Scans) != 2 {
		t.Errorf("history first page = count %d total %d scans %d, want 2 of 3", first.Count, first.Total, len(first.Scans))
	}
	if !first.HasMore || first.NextOffset == nil || *first.NextOffset != 2 {
		t.Errorf("history nextOffset = %v, want 2", first.NextOffset)
	}
	if first.Page.Total != 3 || first.Page.Limit != 2 {
		t.Errorf("history page = %+v, want limit 2 total 3", first.Page)
	}
	if text := textOf(t, h.client.mustTool("vigil_history", map[string]any{"limit": 2})); !strings.Contains(text, "pass offset=2 to continue") {
		t.Errorf("history text does not state the window:\n%s", text)
	}

	last := structuredInto[historyWindowPayload](t, h.client.mustTool("vigil_history", map[string]any{"offset": 2, "limit": 2}))
	if last.Count != 1 || last.HasMore || last.NextOffset != nil {
		t.Errorf("history last page = count %d hasMore %v next %v, want 1 exhausted", last.Count, last.HasMore, last.NextOffset)
	}

	neg := callTool(t, h.client, "vigil_history", map[string]any{"offset": -1})
	if code := toolErrorCode(t, neg); code != "VGL-ARGS" {
		t.Errorf("history negative offset code = %q, want VGL-ARGS", code)
	}
}

// TestMCPAuditPagination: the audit windows findings and reports the pool.
func TestMCPAuditPagination(t *testing.T) {
	h := newHarness(t)
	writeMCPAuditConfig(t, h.repo, ".mcp.json", mcpAuditConfig)

	full := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_mcp_audit", map[string]any{"path": "."}))
	want := len(full.Findings)
	if want < 2 {
		t.Fatalf("audit fixture produced %d findings, want at least 2", want)
	}

	first := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_mcp_audit", map[string]any{
		"path": ".", "maxFindings": 1,
	}))
	if len(first.Findings) != 1 || first.Page.Total != want || !first.Page.HasMore {
		t.Errorf("audit window = %d findings, page %+v, want 1 of %d", len(first.Findings), first.Page, want)
	}
	if first.Page.NextOffset == nil || *first.Page.NextOffset != 1 {
		t.Errorf("audit nextOffset = %v, want 1", first.Page.NextOffset)
	}
	if first.Coverage == nil || first.Coverage.LLMUsed || first.Coverage.FilesScanned < 1 {
		t.Errorf("audit coverage = %+v, want a deterministic one-config read", first.Coverage)
	}

	second := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_mcp_audit", map[string]any{
		"path": ".", "maxFindings": 1, "offset": 1,
	}))
	if len(second.Findings) != 1 || second.Findings[0].ID == first.Findings[0].ID {
		t.Errorf("audit second window repeats or misses a finding: %q vs %q",
			second.Findings[0].ID, first.Findings[0].ID)
	}
	if text := textOf(t, h.client.mustTool("vigil_mcp_audit", map[string]any{"path": ".", "maxFindings": 1})); !strings.Contains(text, "pass offset=1 to continue") {
		t.Errorf("audit text does not state the window:\n%s", text)
	}

	beyond := structuredInto[scanWindowPayload](t, h.client.mustTool("vigil_mcp_audit", map[string]any{
		"path": ".", "offset": 100,
	}))
	if len(beyond.Findings) != 0 || beyond.Page.HasMore || beyond.Page.NextOffset != nil {
		t.Errorf("audit beyond page = %d findings, %+v, want exhausted empty", len(beyond.Findings), beyond.Page)
	}

	neg := callTool(t, h.client, "vigil_mcp_audit", map[string]any{"path": ".", "offset": -1})
	if code := toolErrorCode(t, neg); code != "VGL-ARGS" {
		t.Errorf("audit negative offset code = %q, want VGL-ARGS", code)
	}
}

package tools_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
	"github.com/levapveeskela/lv24-vigil/internal/tools"
)

type baselineFileEntry struct {
	ID          string `json:"id"`
	Reason      string `json:"reason"`
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"ruleId"`
	Path        string `json:"path"`
	Ticket      string `json:"ticket"`
	Expires     string `json:"expires"`
	Disposition string `json:"disposition"`
}

type baselineFile struct {
	Version      int                 `json:"version"`
	Fingerprints []string            `json:"fingerprints"`
	Findings     []baselineFileEntry `json:"findings"`
}

type baselineSuppressionPreview struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type baselineItemOutcome struct {
	FindingID string `json:"findingId"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

type baselineParityPayload struct {
	Path          string                     `json:"path"`
	Version       int                        `json:"version"`
	DryRun        bool                       `json:"dryRun"`
	Saved         bool                       `json:"saved"`
	Added         bool                       `json:"added"`
	FindingID     string                     `json:"findingId"`
	Fingerprint   string                     `json:"fingerprint"`
	Ticket        string                     `json:"ticket"`
	Expires       string                     `json:"expires"`
	Disposition   string                     `json:"disposition"`
	WouldSuppress baselineSuppressionPreview `json:"wouldSuppress"`
	Until         string                     `json:"until"`
	Warnings      []string                   `json:"warnings"`
	Results       []baselineItemOutcome      `json:"results"`
	Pruned        int                        `json:"pruned"`
	Remaining     int                        `json:"remaining"`
}

// baselineListPayload is separate because list reports the entries in
// "findings", while change results report a count under the same name.
type baselineListPayload struct {
	Path         string              `json:"path"`
	Version      int                 `json:"version"`
	Fingerprints []string            `json:"fingerprints"`
	Findings     []baselineFileEntry `json:"findings"`
	Expired      []string            `json:"expired"`
}

func baselineFilePath(h *harness) string {
	return filepath.Join(h.repo, ".vigil-baseline.json")
}

func readBaselineFile(t *testing.T, path string) baselineFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var doc baselineFile
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode baseline: %v", err)
	}
	return doc
}

func writeBaselineFile(t *testing.T, path string, doc map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("encode baseline: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
}

func hasFindingID(findings []model.Finding, id string) bool {
	for _, f := range findings {
		if strings.EqualFold(f.ID, id) {
			return true
		}
	}
	return false
}

func TestBaselineAddWithMetadataOverMCP(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	f := scan.Findings[0]
	expires := scanner.BaselineToday().AddDate(0, 0, 30).Format(scanner.BaselineDateLayout)

	res := h.client.mustTool("vigil_baseline", map[string]any{
		"action":      "add",
		"findingId":   f.ID,
		"reason":      "accepted for the parity test",
		"ticket":      "SEC-\n42\t" + strings.Repeat("9", 200),
		"expires":     expires,
		"disposition": "accepted_risk",
	})
	payload := structuredInto[baselineParityPayload](t, res)
	if !payload.Saved || payload.DryRun {
		t.Fatalf("add payload saved/dryRun = %v/%v, want true/false", payload.Saved, payload.DryRun)
	}
	if payload.FindingID != f.ID || payload.Fingerprint == "" {
		t.Errorf("add payload finding = %q fingerprint = %q", payload.FindingID, payload.Fingerprint)
	}
	if payload.Disposition != scanner.BaselineDispositionAcceptedRisk || payload.Expires != expires {
		t.Errorf("add payload metadata = %+v", payload)
	}
	if payload.WouldSuppress.Total < 1 {
		t.Errorf("wouldSuppress.total = %d, want at least 1", payload.WouldSuppress.Total)
	}
	if payload.Until != expires {
		t.Errorf("until = %q, want %q", payload.Until, expires)
	}

	doc := readBaselineFile(t, baselineFilePath(h))
	if doc.Version != 2 {
		t.Fatalf("on-disk version = %d, want 2", doc.Version)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("on-disk findings = %d, want 1: %+v", len(doc.Findings), doc.Findings)
	}
	entry := doc.Findings[0]
	if entry.ID != f.ID || entry.Fingerprint == "" || entry.RuleID != f.RuleID || entry.Path != f.Location.Path {
		t.Errorf("stored entry lost identity: %+v", entry)
	}
	if entry.Disposition != scanner.BaselineDispositionAcceptedRisk || entry.Expires != expires || entry.Ticket == "" {
		t.Errorf("stored entry lost metadata: %+v", entry)
	}
	if len([]rune(entry.Ticket)) != 128 {
		t.Errorf("ticket length = %d, want the 128-rune cap", len([]rune(entry.Ticket)))
	}
	if strings.ContainsAny(entry.Ticket, "\n\t") {
		t.Errorf("ticket kept control characters: %q", entry.Ticket)
	}

	listText := textOf(t, h.client.mustTool("vigil_baseline", map[string]any{"action": "list"}))
	for _, want := range []string{"ticket=SEC-42", "expires=" + expires, "disposition=accepted_risk"} {
		if !strings.Contains(listText, want) {
			t.Errorf("baseline list missing %q:\n%s", want, listText)
		}
	}
}

func TestBaselineExpiredEntryStopsSuppressingAndIsListed(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	f := scan.Findings[0]
	past := scanner.BaselineToday().AddDate(0, 0, -1).Format(scanner.BaselineDateLayout)
	writeBaselineFile(t, baselineFilePath(h), map[string]any{
		"version":      2,
		"fingerprints": []string{},
		"findings": []map[string]any{{
			"id":          f.ID,
			"reason":      "expired acceptance",
			"fingerprint": f.Fingerprint,
			"ruleId":      f.RuleID,
			"path":        f.Location.Path,
			"ticket":      "SEC-9",
			"expires":     past,
			"disposition": "wont_fix",
		}},
	})

	rescan := h.scan()
	if !hasFindingID(rescan.Findings, f.ID) {
		t.Fatalf("expired acceptance still suppresses %s", f.ID)
	}
	if hasFindingID(rescan.Suppressed, f.ID) {
		t.Fatalf("expired acceptance produced a suppression for %s", f.ID)
	}

	res := h.client.mustTool("vigil_baseline", map[string]any{"action": "list"})
	payload := structuredInto[baselineListPayload](t, res)
	if payload.Version != 2 {
		t.Errorf("list version = %d, want 2", payload.Version)
	}
	if len(payload.Expired) != 1 || payload.Expired[0] != f.ID {
		t.Errorf("expired = %v, want [%s]", payload.Expired, f.ID)
	}
	listText := textOf(t, res)
	if !strings.Contains(listText, "(expired)") {
		t.Errorf("list does not mark the entry expired:\n%s", listText)
	}
}

func TestBaselineDryRunWritesNothing(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	f := scan.Findings[0]
	expires := scanner.BaselineToday().AddDate(0, 0, 5).Format(scanner.BaselineDateLayout)

	res := h.client.mustTool("vigil_baseline", map[string]any{
		"action":    "add",
		"findingId": f.ID,
		"reason":    "preview only",
		"expires":   expires,
		"dryRun":    true,
	})
	payload := structuredInto[baselineParityPayload](t, res)
	if payload.Saved || !payload.DryRun {
		t.Errorf("dry-run payload saved/dryRun = %v/%v, want false/true", payload.Saved, payload.DryRun)
	}
	if payload.WouldSuppress.Total < 1 {
		t.Errorf("dry-run wouldSuppress.total = %d, want at least 1", payload.WouldSuppress.Total)
	}
	if payload.Until != expires {
		t.Errorf("dry-run until = %q, want %q", payload.Until, expires)
	}
	if _, err := os.Stat(baselineFilePath(h)); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote the baseline: %v", err)
	}
}

func TestBaselineAddRejectsPastExpiryAndRemediated(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	id := scan.Findings[0].ID

	past := h.client.tool("vigil_baseline", map[string]any{
		"action": "add", "findingId": id, "reason": "expired", "expires": "2020-01-01",
	})
	if code := toolErrorCode(t, past); code != tools.CodeArgs {
		t.Errorf("past expiry code = %q, want %q", code, tools.CodeArgs)
	}
	if !strings.Contains(textOf(t, past), "past") {
		t.Errorf("past expiry text = %s", textOf(t, past))
	}

	remediated := h.client.tool("vigil_baseline", map[string]any{
		"action": "add", "findingId": id, "reason": "fixed", "disposition": "remediated",
	})
	if code := toolErrorCode(t, remediated); code != tools.CodeArgs {
		t.Errorf("remediated code = %q, want %q", code, tools.CodeArgs)
	}
	if !strings.Contains(textOf(t, remediated), "must be removed from the baseline") {
		t.Errorf("remediated text = %s", textOf(t, remediated))
	}

	unknown := h.client.tool("vigil_baseline", map[string]any{
		"action": "add", "findingId": id, "reason": "x", "disposition": "maybe",
	})
	if code := toolErrorCode(t, unknown); code != tools.CodeArgs {
		t.Errorf("unknown disposition code = %q, want %q", code, tools.CodeArgs)
	}
	if _, err := os.Stat(baselineFilePath(h)); !os.IsNotExist(err) {
		t.Fatalf("a rejected add wrote the baseline: %v", err)
	}
}

func TestBaselineBatchDefaultsToDryRun(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	f := scan.Findings[0]

	preview := h.client.mustTool("vigil_baseline", map[string]any{
		"action": "batch",
		"items": []map[string]any{{
			"action": "add", "findingId": f.ID, "reason": "batch acceptance",
		}},
	})
	payload := structuredInto[baselineParityPayload](t, preview)
	if !payload.DryRun || payload.Saved {
		t.Errorf("batch defaults dryRun/saved = %v/%v, want true/false", payload.DryRun, payload.Saved)
	}
	if len(payload.Results) != 1 || payload.Results[0].Status != "added" {
		t.Errorf("batch preview results = %+v", payload.Results)
	}
	if _, err := os.Stat(baselineFilePath(h)); !os.IsNotExist(err) {
		t.Fatalf("batch dry run wrote the baseline: %v", err)
	}

	write := h.client.mustTool("vigil_baseline", map[string]any{
		"action": "batch",
		"dryRun": false,
		"items": []map[string]any{{
			"action": "add", "findingId": f.ID, "reason": "batch acceptance",
		}},
	})
	written := structuredInto[baselineParityPayload](t, write)
	if written.DryRun || !written.Saved {
		t.Errorf("batch write dryRun/saved = %v/%v, want false/true", written.DryRun, written.Saved)
	}
	if len(written.Results) != 1 || written.Results[0].Status != "added" {
		t.Errorf("batch write results = %+v", written.Results)
	}
	doc := readBaselineFile(t, baselineFilePath(h))
	if doc.Version != 2 || len(doc.Findings) != 1 || doc.Findings[0].ID != f.ID {
		t.Errorf("batch write stored %+v", doc)
	}
}

func TestBaselineBatchItemErrorDoesNotPartiallySave(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	f := scan.Findings[0]

	res := h.client.tool("vigil_baseline", map[string]any{
		"action": "batch",
		"dryRun": false,
		"items": []map[string]any{
			{"action": "add", "findingId": f.ID, "reason": "would be valid"},
			{"action": "add", "findingId": "VGL-NOPE000000", "reason": "unknown finding"},
		},
	})
	if res.IsError {
		t.Fatalf("batch item failure should be per-item, got a tool error: %s", textOf(t, res))
	}
	payload := structuredInto[baselineParityPayload](t, res)
	if payload.Saved {
		t.Errorf("batch saved despite an item failure")
	}
	if len(payload.Results) != 2 {
		t.Fatalf("batch results = %+v", payload.Results)
	}
	for _, item := range payload.Results {
		if item.Status != "error" {
			t.Errorf("item %s status = %q, want error", item.FindingID, item.Status)
		}
	}
	if _, err := os.Stat(baselineFilePath(h)); !os.IsNotExist(err) {
		t.Fatalf("a failed batch wrote the baseline: %v", err)
	}

	// A shape/argument error is a request-level typed error and also writes
	// nothing, even when other items would have been valid.
	invalid := h.client.tool("vigil_baseline", map[string]any{
		"action": "batch",
		"dryRun": false,
		"items": []map[string]any{
			{"action": "add", "findingId": f.ID, "reason": "valid"},
			{"action": "add", "findingId": f.ID},
		},
	})
	if code := toolErrorCode(t, invalid); code != tools.CodeArgs {
		t.Errorf("invalid batch code = %q, want %q", code, tools.CodeArgs)
	}
	if _, err := os.Stat(baselineFilePath(h)); !os.IsNotExist(err) {
		t.Fatalf("an invalid batch wrote the baseline: %v", err)
	}
}

func TestBaselinePruneDryRunAndWrite(t *testing.T) {
	h := newHarness(t)
	path := baselineFilePath(h)
	today := scanner.BaselineToday()
	expired := today.AddDate(0, 0, -1).Format(scanner.BaselineDateLayout)
	valid := today.AddDate(0, 0, 10).Format(scanner.BaselineDateLayout)
	writeBaselineFile(t, path, map[string]any{
		"version":      2,
		"fingerprints": []string{},
		"findings": []map[string]any{
			{"id": "VGL-OLD", "reason": "expired", "fingerprint": "fp_old", "expires": expired},
			{"id": "VGL-NEW", "reason": "valid", "fingerprint": "fp_new", "expires": valid},
		},
	})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	preview := h.client.mustTool("vigil_baseline", map[string]any{"action": "prune"})
	payload := structuredInto[baselineParityPayload](t, preview)
	if !payload.DryRun || payload.Saved || payload.Pruned != 1 || payload.Remaining != 1 {
		t.Errorf("prune preview = dryRun %v saved %v pruned %d remaining %d",
			payload.DryRun, payload.Saved, payload.Pruned, payload.Remaining)
	}
	afterPreview, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(afterPreview) {
		t.Fatal("prune dry run rewrote the baseline")
	}

	pruned := h.client.mustTool("vigil_baseline", map[string]any{"action": "prune", "dryRun": false})
	written := structuredInto[baselineParityPayload](t, pruned)
	if written.DryRun || !written.Saved || written.Pruned != 1 || written.Remaining != 1 {
		t.Errorf("prune write = dryRun %v saved %v pruned %d remaining %d",
			written.DryRun, written.Saved, written.Pruned, written.Remaining)
	}
	loaded, err := scanner.LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline after prune: %v", err)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].ID != "VGL-NEW" {
		t.Fatalf("after prune findings = %+v, want only VGL-NEW", loaded.Findings)
	}
	if len(loaded.Fingerprints) != 0 {
		t.Fatalf("after prune fingerprints = %v, want none", loaded.Fingerprints)
	}
}

func TestBaselineRemoveByPrefixRemovesEntryAndFingerprint(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	f := scan.Findings[0]

	h.client.mustTool("vigil_baseline", map[string]any{
		"action": "add", "findingId": f.ID, "reason": "remove by prefix",
	})
	doc := readBaselineFile(t, baselineFilePath(h))
	if len(doc.Findings) != 1 || len(doc.Fingerprints) != 1 {
		t.Fatalf("setup baseline = %+v", doc)
	}

	prefix := f.ID[:9]
	removed := h.client.mustTool("vigil_baseline", map[string]any{"action": "remove", "findingId": prefix})
	if !strings.Contains(textOf(t, removed), "Removed") {
		t.Errorf("remove text = %s", textOf(t, removed))
	}
	after := readBaselineFile(t, baselineFilePath(h))
	if len(after.Findings) != 0 || len(after.Fingerprints) != 0 {
		t.Fatalf("prefix remove left acceptance behind: findings=%+v fingerprints=%v", after.Findings, after.Fingerprints)
	}

	rescan := h.scan()
	if !hasFindingID(rescan.Findings, f.ID) {
		t.Fatalf("removed finding %s is still suppressed", f.ID)
	}
}

func TestBaselineReadOnlyAllowsListOnly(t *testing.T) {
	h := newHarness(t)
	c := newModeClient(t, h.app, true, false)

	if res := callTool(t, c, "vigil_baseline", map[string]any{"action": "list"}); res.IsError {
		t.Fatalf("read-only list failed: %s", textOf(t, res))
	}
	cases := []map[string]any{
		{"action": "add", "findingId": "VGL-ANY", "reason": "read-only"},
		{"action": "remove", "findingId": "VGL-ANY"},
		{"action": "prune"},
		{"action": "batch", "items": []map[string]any{{"action": "add", "findingId": "VGL-ANY", "reason": "read-only"}}},
		{"action": "clear"},
	}
	for _, args := range cases {
		res := callTool(t, c, "vigil_baseline", args)
		if code := toolErrorCode(t, res); code != tools.CodeReadOnly {
			t.Errorf("%v code = %q, want %q", args["action"], code, tools.CodeReadOnly)
		}
	}
}

func TestBaselineLegacyFilesOverMCP(t *testing.T) {
	h := newHarness(t)
	path := baselineFilePath(h)

	writeBaselineFile(t, path, map[string]any{
		"version":      1,
		"fingerprints": []string{"fp_legacy"},
		"findings":     []map[string]any{{"id": "VGL-LEGACY", "reason": "legacy acceptance"}},
	})
	list := h.client.mustTool("vigil_baseline", map[string]any{"action": "list"})
	payload := structuredInto[baselineListPayload](t, list)
	if payload.Version != 2 {
		t.Errorf("v1 list version = %d, want 2", payload.Version)
	}
	if !strings.Contains(textOf(t, list), "VGL-LEGACY") || !strings.Contains(textOf(t, list), "fp_legacy") {
		t.Errorf("v1 list lost entries:\n%s", textOf(t, list))
	}

	scan := h.scan()
	f := scan.Findings[0]
	future := scanner.BaselineToday().AddDate(0, 0, 7).Format(scanner.BaselineDateLayout)
	writeBaselineFile(t, path, map[string]any{
		"version": 2,
		"findings": []map[string]any{{
			"id": f.ID, "reason": "v2 acceptance", "fingerprint": f.Fingerprint,
			"ruleId": f.RuleID, "path": f.Location.Path, "ticket": "SEC-2", "expires": future,
		}},
	})
	// The finding is expected to be suppressed, so do not use h.scan(), which
	// requires at least one active finding.
	rescan := structuredInto[model.ScanResult](t, h.client.mustTool("vigil_scan", map[string]any{"mode": "quick"}))
	if !hasFindingID(rescan.Suppressed, f.ID) {
		t.Fatalf("v2 acceptance did not suppress %s", f.ID)
	}
	listText := textOf(t, h.client.mustTool("vigil_baseline", map[string]any{"action": "list"}))
	if !strings.Contains(listText, "ticket=SEC-2") || !strings.Contains(listText, "expires="+future) {
		t.Errorf("v2 list lost metadata:\n%s", listText)
	}
}

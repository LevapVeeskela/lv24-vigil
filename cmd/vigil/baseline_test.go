package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaselineRoundTrip(t *testing.T) {
	dir := newTestRepo(t)
	path := filepath.Join(dir, ".vigil-baseline.json")

	out, stderr, err := runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("initial scan: %v\nstderr:\n%s", err, stderr)
	}
	scanned := decodeScan(t, out)
	findingID := findingIDForRule(t, scanned, "VGL-SEC-003")

	out, stderr, err = runCLI(t, "baseline", "add", findingID, "--reason=test fixture")
	if err != nil {
		t.Fatalf("baseline add: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(out, "added "+findingID) {
		t.Errorf("unexpected add output: %s", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("baseline file was not written: %v", err)
	}

	var file struct {
		Fingerprints []string `json:"fingerprints"`
		Findings     []struct {
			ID     string `json:"id"`
			Reason string `json:"reason"`
		} `json:"findings"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("baseline JSON invalid: %v", err)
	}
	if len(file.Fingerprints) != 1 {
		t.Errorf("fingerprints = %d, want 1 (enriched from the stored scan)", len(file.Fingerprints))
	}
	if len(file.Findings) != 1 || file.Findings[0].ID != findingID || file.Findings[0].Reason != "test fixture" {
		t.Errorf("unexpected baseline entries: %+v", file.Findings)
	}

	out, _, err = runCLI(t, "baseline", "list")
	if err != nil {
		t.Fatalf("baseline list: %v", err)
	}
	for _, want := range []string{path, findingID, "test fixture"} {
		if !strings.Contains(out, want) {
			t.Errorf("baseline list missing %q\n%s", want, out)
		}
	}

	// The accepted finding must be suppressed, not silently dropped.
	out, stderr, err = runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("scan after baseline add: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if findRule(res, "VGL-SEC-003") {
		t.Error("baselined finding still reported as active")
	}
	if len(res.Suppressed) != 1 {
		t.Errorf("suppressed = %d, want 1", len(res.Suppressed))
	}
	if !findRule(res, "VGL-SEC-001") {
		t.Error("non-baselined finding disappeared")
	}

	out, _, err = runCLI(t, "baseline", "remove", findingID)
	if err != nil {
		t.Fatalf("baseline remove: %v", err)
	}
	if !strings.Contains(out, "removed "+findingID) {
		t.Errorf("unexpected remove output: %s", out)
	}

	out, _, err = runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("scan after baseline remove: %v", err)
	}
	if !findRule(decodeScan(t, out), "VGL-SEC-003") {
		t.Error("finding did not return after baseline removal")
	}

	if _, _, err := runCLI(t, "baseline", "clear"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("clear without --yes = %v, want a confirmation error", err)
	}
	if _, _, err := runCLI(t, "baseline", "clear", "--yes"); err != nil {
		t.Fatalf("baseline clear --yes: %v", err)
	}
	out, _, err = runCLI(t, "baseline", "list")
	if err != nil {
		t.Fatalf("baseline list after clear: %v", err)
	}
	if !strings.Contains(out, "empty") {
		t.Errorf("baseline not empty after clear:\n%s", out)
	}
}

func TestBaselineRemoveUnknown(t *testing.T) {
	newTestRepo(t)
	_, _, err := runCLI(t, "baseline", "remove", "VGL-DOESNOTEXIST")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want a not-found error", err)
	}
}

func TestBaselineAddMetadata(t *testing.T) {
	dir := newTestRepo(t)
	path := filepath.Join(dir, ".vigil-baseline.json")

	out, stderr, err := runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("initial scan: %v\nstderr:\n%s", err, stderr)
	}
	scanned := decodeScan(t, out)
	findingID, findingPath := "", ""
	for _, f := range scanned.Findings {
		if f.RuleID == "VGL-SEC-003" {
			findingID, findingPath = f.ID, f.Location.Path
			break
		}
	}
	if findingID == "" {
		t.Fatal("scan has no VGL-SEC-003 finding")
	}
	expires := time.Now().UTC().AddDate(0, 0, 7).Format("2006-01-02")

	out, stderr, err = runCLI(t, "baseline", "add", findingID,
		"--reason=tracked acceptance", "--ticket=SEC-42", "--expires", expires, "--path", findingPath,
		"--disposition", "wont_fix")
	if err != nil {
		t.Fatalf("baseline add: %v\nstderr:\n%s", err, stderr)
	}
	for _, want := range []string{findingID, "SEC-42", expires, "disposition: wont_fix"} {
		if !strings.Contains(out, want) {
			t.Errorf("baseline add output missing %q:\n%s", want, out)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var file struct {
		Version  int `json:"version"`
		Findings []struct {
			ID          string `json:"id"`
			Reason      string `json:"reason"`
			Fingerprint string `json:"fingerprint"`
			RuleID      string `json:"ruleId"`
			Path        string `json:"path"`
			Ticket      string `json:"ticket"`
			Expires     string `json:"expires"`
			Disposition string `json:"disposition"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("baseline JSON invalid: %v", err)
	}
	if file.Version != 3 {
		t.Errorf("baseline version = %d, want 3", file.Version)
	}
	if len(file.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(file.Findings))
	}
	entry := file.Findings[0]
	if entry.ID != findingID || entry.Reason != "tracked acceptance" || entry.Ticket != "SEC-42" ||
		entry.Expires != expires || entry.Path != findingPath || entry.Fingerprint == "" ||
		entry.RuleID != "VGL-SEC-003" || entry.Disposition != "wont_fix" {
		t.Errorf("unexpected entry: %+v", entry)
	}

	out, _, err = runCLI(t, "baseline", "list")
	if err != nil {
		t.Fatalf("baseline list: %v", err)
	}
	for _, want := range []string{"ticket=SEC-42", "expires=" + expires, "path=" + findingPath, "disposition=wont_fix"} {
		if !strings.Contains(out, want) {
			t.Errorf("baseline list missing %q:\n%s", want, out)
		}
	}

	out, stderr, err = runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("scan after baseline add: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if findRule(res, "VGL-SEC-003") {
		t.Error("accepted finding is still active")
	}
	if len(res.Suppressed) != 1 {
		t.Errorf("suppressed = %d, want 1", len(res.Suppressed))
	}

	out, _, err = runCLI(t, "baseline", "prune")
	if err != nil {
		t.Fatalf("baseline prune: %v", err)
	}
	if !strings.Contains(out, "pruned 0") {
		t.Errorf("prune removed a future entry:\n%s", out)
	}
}

func TestBaselineAddFlagValidation(t *testing.T) {
	newTestRepo(t)
	out, stderr, err := runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("initial scan: %v\nstderr:\n%s", err, stderr)
	}
	findingID := findingIDForRule(t, decodeScan(t, out), "VGL-SEC-003")

	for _, value := range []string{"not-a-date", "2026-13-01"} {
		_, _, err := runCLI(t, "baseline", "add", findingID, "--expires", value)
		if err == nil || !strings.Contains(err.Error(), "YYYY-MM-DD") {
			t.Errorf("--expires %q error = %v, want a date format error", value, err)
		}
	}
	_, _, err = runCLI(t, "baseline", "add", findingID, "--expires", "2020-01-01")
	if err == nil || !strings.Contains(err.Error(), "past") {
		t.Errorf("past --expires error = %v, want a past-date error", err)
	}
	_, _, err = runCLI(t, "baseline", "add", findingID, "--path", "not/config.go")
	if err == nil || !strings.Contains(err.Error(), "is at") {
		t.Errorf("mismatched --path error = %v, want a path mismatch error", err)
	}
	_, _, err = runCLI(t, "baseline", "add", findingID, "--disposition", "remediated")
	if err == nil || !strings.Contains(err.Error(), "must be removed from the baseline") {
		t.Errorf("remediated --disposition error = %v, want a removal hint", err)
	}
}

func TestBaselinePruneExpired(t *testing.T) {
	dir := newTestRepo(t)
	path := filepath.Join(dir, ".vigil-baseline.json")
	today := time.Now().UTC()
	expired := today.AddDate(0, 0, -1).Format("2006-01-02")
	valid := today.AddDate(0, 0, 7).Format("2006-01-02")

	doc := map[string]any{
		"version":      2,
		"fingerprints": []string{"fp_expired", "fp_valid"},
		"findings": []map[string]any{
			{"id": "VGL-OLD", "reason": "expired", "fingerprint": "fp_expired", "expires": expired},
			{"id": "VGL-NEW", "reason": "valid", "fingerprint": "fp_valid", "expires": valid},
		},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCLI(t, "baseline", "prune", "--dry-run")
	if err != nil {
		t.Fatalf("prune --dry-run: %v", err)
	}
	if !strings.Contains(out, "would prune 1") {
		t.Errorf("dry-run output = %q, want a count of 1", out)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), "VGL-OLD") || !strings.Contains(string(before), "fp_expired") {
		t.Error("dry-run modified the baseline file")
	}

	out, _, err = runCLI(t, "baseline", "prune")
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if !strings.Contains(out, "pruned 1") {
		t.Errorf("prune output = %q, want a count of 1", out)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "VGL-OLD") || strings.Contains(string(after), "fp_expired") {
		t.Error("prune left an expired entry or fingerprint in the baseline")
	}
	if !strings.Contains(string(after), "VGL-NEW") || !strings.Contains(string(after), "fp_valid") {
		t.Error("prune removed a valid entry")
	}

	out, _, err = runCLI(t, "baseline", "prune")
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if !strings.Contains(out, "pruned 0") {
		t.Errorf("second prune output = %q, want a count of 0", out)
	}
}

func TestBaselineLegacyFingerprintListAndRemove(t *testing.T) {
	dir := newTestRepo(t)
	path := filepath.Join(dir, ".vigil-baseline.json")

	out, stderr, err := runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("initial scan: %v\nstderr:\n%s", err, stderr)
	}
	findingID := findingIDForRule(t, decodeScan(t, out), "VGL-SEC-003")

	// Enrich once so the finding fingerprint is known, then replace the file
	// with a version-1 shape: an ID-only entry plus the top-level fingerprint.
	if _, stderr, err := runCLI(t, "baseline", "add", findingID, "--reason=legacy acceptance"); err != nil {
		t.Fatalf("baseline add: %v\nstderr:\n%s", err, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var stored struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("baseline JSON invalid: %v", err)
	}
	if len(stored.Findings) != 1 || stored.Findings[0].Fingerprint == "" {
		t.Fatalf("baseline add recorded no fingerprint: %+v", stored.Findings)
	}
	fingerprint := stored.Findings[0].Fingerprint

	legacy := map[string]any{
		"version":      1,
		"fingerprints": []string{fingerprint},
		"findings":     []map[string]any{{"id": "VGL-SHIFTED", "reason": "legacy acceptance"}},
	}
	legacyData, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacyData, 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, err = runCLI(t, "baseline", "list")
	if err != nil {
		t.Fatalf("baseline list: %v", err)
	}
	for _, want := range []string{fingerprint, "legacy fingerprint"} {
		if !strings.Contains(out, want) {
			t.Errorf("baseline list missing %q:\n%s", want, out)
		}
	}

	out, _, err = runCLI(t, "baseline", "remove", fingerprint)
	if err != nil {
		t.Fatalf("baseline remove fingerprint: %v", err)
	}
	if !strings.Contains(out, "removed "+fingerprint) {
		t.Errorf("unexpected remove output: %s", out)
	}

	// The shifted ID does not match the finding, so removing the materialized
	// fingerprint must return it to the report.
	out, _, err = runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("scan after fingerprint remove: %v", err)
	}
	if !findRule(decodeScan(t, out), "VGL-SEC-003") {
		t.Error("finding stayed suppressed after removing its legacy fingerprint")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	if strings.Contains(string(after), fingerprint) {
		t.Errorf("removed fingerprint is still in the baseline:\n%s", after)
	}
}

// Regression: removing the ID entry of a version-1 baseline left the
// materialized `legacy fingerprint` entry suppressing the finding while the
// command printed success.
func TestBaselineRemoveIDDropsLegacyFingerprint(t *testing.T) {
	dir := newTestRepo(t)
	path := filepath.Join(dir, ".vigil-baseline.json")

	out, stderr, err := runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("initial scan: %v\nstderr:\n%s", err, stderr)
	}
	findingID := findingIDForRule(t, decodeScan(t, out), "VGL-SEC-003")

	// Enrich once to learn the fingerprint, then store the version-1 shape: an
	// ID-only entry plus the top-level fingerprint.
	if _, stderr, err := runCLI(t, "baseline", "add", findingID, "--reason=legacy acceptance"); err != nil {
		t.Fatalf("baseline add: %v\nstderr:\n%s", err, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var stored struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("baseline JSON invalid: %v", err)
	}
	if len(stored.Findings) != 1 || stored.Findings[0].Fingerprint == "" {
		t.Fatalf("baseline add recorded no fingerprint: %+v", stored.Findings)
	}
	fingerprint := stored.Findings[0].Fingerprint

	legacy := map[string]any{
		"version":      1,
		"fingerprints": []string{fingerprint},
		"findings":     []map[string]any{{"id": "VGL-SHIFTED", "reason": "legacy acceptance"}},
	}
	legacyData, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacyData, 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, err = runCLI(t, "baseline", "remove", "VGL-SHIFTED")
	if err != nil {
		t.Fatalf("baseline remove ID: %v", err)
	}
	if !strings.Contains(out, "removed VGL-SHIFTED") || !strings.Contains(out, "legacy fingerprint "+fingerprint) {
		t.Errorf("remove output does not name both entries:\n%s", out)
	}

	// The ID does not resolve in scan history, so the mirror fingerprint must
	// have been dropped too; otherwise the finding stays accepted.
	out, _, err = runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("scan after remove: %v", err)
	}
	if !findRule(decodeScan(t, out), "VGL-SEC-003") {
		t.Error("finding stayed suppressed after `baseline remove ID`")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	if strings.Contains(string(after), fingerprint) {
		t.Errorf("removed fingerprint is still in the baseline:\n%s", after)
	}
}

func findingIDForRule(t *testing.T, res scanJSON, ruleID string) string {
	t.Helper()
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			return f.ID
		}
	}
	t.Fatalf("scan has no finding for rule %s", ruleID)
	return ""
}

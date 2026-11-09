package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

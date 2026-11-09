package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanMarkdownSummaryAndReport(t *testing.T) {
	newTestRepo(t)

	out, stderr, err := runCLI(t, "scan", ".")
	if err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr)
	}
	for _, want := range []string{
		"vigil scan",
		"mode      standard",
		"findings  1 critical, 1 high",
		"VGL-SEC-003",
		"config.go:3",
		"VGL-SEC-001",
		"config.go:4",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, testGitHubToken) || strings.Contains(out, testAWSKeyID) {
		t.Error("scan output leaked a raw secret")
	}
}

func TestScanJSONIsValidAndMasksSecrets(t *testing.T) {
	newTestRepo(t)

	out, stderr, err := runCLI(t, "scan", ".", "--format=json")
	if err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if res.SchemaVersion != "1" {
		t.Errorf("schemaVersion = %q, want 1", res.SchemaVersion)
	}
	if !findRule(res, "VGL-SEC-003") {
		t.Errorf("missing VGL-SEC-003 in %s", out)
	}
	if !findRule(res, "VGL-SEC-001") {
		t.Errorf("missing VGL-SEC-001 in %s", out)
	}
	if strings.Contains(out, testGitHubToken) || strings.Contains(out, testAWSKeyID) {
		t.Error("JSON report leaked a raw secret")
	}
	if res.ID == "" {
		t.Error("scan result has no ID")
	}
}

func TestScanQuietSkipsSummary(t *testing.T) {
	newTestRepo(t)

	out, stderr, err := runCLI(t, "scan", ".", "--quiet")
	if err != nil {
		t.Fatalf("scan --quiet: %v\nstderr:\n%s", err, stderr)
	}
	if strings.Contains(out, "vigil scan ·") {
		t.Errorf("--quiet still printed the summary:\n%s", out)
	}
	if !strings.Contains(out, "# Vigil security report") {
		t.Errorf("--quiet suppressed the report too:\n%s", out)
	}
}

func TestScanFailOnReturnsErrFindings(t *testing.T) {
	newTestRepo(t)

	_, _, err := runCLI(t, "scan", ".", "--format", "json", "--fail-on", "high")
	if !errors.Is(err, ErrFindings) {
		t.Fatalf("err = %v, want ErrFindings", err)
	}

	// Disabling both known rules must leave the run clean.
	_, stderr, err := runCLI(t, "scan", ".", "--format", "json", "--fail-on", "high",
		"--disable", "VGL-SEC-001,VGL-SEC-003")
	if err != nil {
		t.Fatalf("scan with rules disabled: %v\nstderr:\n%s", err, stderr)
	}
}

func TestScanSARIFOutputFile(t *testing.T) {
	dir := newTestRepo(t)
	reportPath := filepath.Join(dir, "vigil.sarif")

	out, stderr, err := runCLI(t, "scan", ".", "--format=sarif", "--output", reportPath)
	if err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(out, "wrote "+reportPath) {
		t.Errorf("missing output confirmation: %s", out)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("sarif is not valid JSON: %v\n%s", err, data)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) == 0 || sarif.Runs[0].Tool.Driver.Name != "vigil" {
		t.Fatalf("unexpected sarif driver: %+v", sarif.Runs)
	}
	if len(sarif.Runs[0].Results) == 0 {
		t.Error("sarif has no results")
	}
}

func TestScanRepeatedIncludeFlag(t *testing.T) {
	newTestRepo(t)

	out, stderr, err := runCLI(t, "scan", ".", "--format=json", "--include", "*.go", "--include=*.md")
	if err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if res.Stats.FilesScanned != 2 {
		t.Errorf("filesScanned = %d, want 2 (config.go and README.md)", res.Stats.FilesScanned)
	}
	if !findRule(res, "VGL-SEC-003") {
		t.Error("included Go file was not scanned")
	}
}

func TestScanDiffFromStdin(t *testing.T) {
	newTestRepo(t)

	diff := "diff --git a/extra.go b/extra.go\n" +
		"--- a/extra.go\n" +
		"+++ b/extra.go\n" +
		"@@ -0,0 +1,2 @@\n" +
		"+package extra\n" +
		"+const token = \"" + testGitHubToken + "\"\n"

	previous := stdinReader
	stdinReader = strings.NewReader(diff)
	t.Cleanup(func() { stdinReader = previous })

	out, stderr, err := runCLI(t, "scan", ".", "--diff", "-", "--format", "json")
	if err != nil {
		t.Fatalf("scan --diff -: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if !findRule(res, "VGL-SEC-003") {
		t.Fatalf("diff was not scanned: %s", out)
	}
	for _, f := range res.Findings {
		if f.RuleID == "VGL-SEC-003" && f.Location.Path != "extra.go" {
			t.Errorf("finding path = %q, want extra.go", f.Location.Path)
		}
	}
}

func TestReviewDiffFile(t *testing.T) {
	dir := newTestRepo(t)
	diffPath := filepath.Join(dir, "change.diff")
	diff := "diff --git a/reviewed.go b/reviewed.go\n" +
		"--- a/reviewed.go\n" +
		"+++ b/reviewed.go\n" +
		"@@ -0,0 +1,2 @@\n" +
		"+package reviewed\n" +
		"+const token = \"" + testGitHubToken + "\"\n"
	if err := os.WriteFile(diffPath, []byte(diff), 0o644); err != nil {
		t.Fatalf("write diff: %v", err)
	}

	out, stderr, err := runCLI(t, "review", "--diff", diffPath, "--format", "json")
	if err != nil {
		t.Fatalf("review: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if !findRule(res, "VGL-SEC-003") {
		t.Fatalf("review did not scan the diff: %s", out)
	}
}

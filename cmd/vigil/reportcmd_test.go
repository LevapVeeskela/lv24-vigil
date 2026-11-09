package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportLastAndSelectedScan(t *testing.T) {
	newTestRepo(t)

	out, stderr, err := runCLI(t, "scan", ".", "--format", "json")
	if err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr)
	}
	scanned := decodeScan(t, out)

	last, _, err := runCLI(t, "report", "--format", "json")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	var rendered scanJSON
	if err := json.Unmarshal([]byte(last), &rendered); err != nil {
		t.Fatalf("report JSON invalid: %v\n%s", err, last)
	}
	if rendered.ID != scanned.ID {
		t.Errorf("report rendered %q, want last scan %q", rendered.ID, scanned.ID)
	}

	selected, _, err := runCLI(t, "report", "--scan", scanned.ID, "--format=sarif")
	if err != nil {
		t.Fatalf("report --scan: %v", err)
	}
	if !strings.Contains(selected, `"version": "2.1.0"`) {
		t.Errorf("selected report is not SARIF:\n%s", selected)
	}
}

func TestReportWithoutScans(t *testing.T) {
	newTestRepo(t)

	_, _, err := runCLI(t, "report")
	if err == nil || !strings.Contains(err.Error(), "run `vigil scan`") {
		t.Fatalf("err = %v, want a run-scan hint", err)
	}
}

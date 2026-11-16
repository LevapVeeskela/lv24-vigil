package main

import (
	"encoding/json"
	"encoding/xml"
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

func TestReportJUnitFormat(t *testing.T) {
	newTestRepo(t)

	if _, stderr, err := runCLI(t, "scan", ".", "--format", "json"); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr)
	}

	out, stderr, err := runCLI(t, "report", "--format", "junit")
	if err != nil {
		t.Fatalf("report --format junit: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.HasPrefix(out, "<?xml") {
		t.Fatalf("report is not XML:\n%s", out)
	}

	var suite struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Skipped  int `xml:"skipped,attr"`
		Cases    []struct {
			Classname string `xml:"classname,attr"`
			Name      string `xml:"name,attr"`
			Failure   *struct {
				Message string `xml:"message,attr"`
			} `xml:"failure"`
		} `xml:"testsuite>testcase"`
	}
	if xerr := xml.Unmarshal([]byte(out), &suite); xerr != nil {
		t.Fatalf("report is not valid JUnit XML: %v\n%s", xerr, out)
	}
	if suite.Tests == 0 || suite.Failures == 0 {
		t.Fatalf("JUnit counts = tests %d, failures %d; want failures", suite.Tests, suite.Failures)
	}
	if len(suite.Cases) != suite.Tests {
		t.Errorf("testcase count = %d, want %d", len(suite.Cases), suite.Tests)
	}
	found := false
	for _, c := range suite.Cases {
		if c.Classname == "VGL-SEC-003" && c.Failure != nil {
			found = true
		}
	}
	if !found {
		t.Errorf("no failing testcase with classname VGL-SEC-003:\n%s", out)
	}

	if _, _, err := runCLI(t, "report", "--format", "pdf"); err == nil || !strings.Contains(err.Error(), "junit") {
		t.Fatalf("unknown format error = %v, want the accepted list with junit", err)
	}
}

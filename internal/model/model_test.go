package model

import (
	"fmt"
	"strings"
	"testing"
)

func TestSeverityRankAndParse(t *testing.T) {
	order := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Errorf("rank(%s) <= rank(%s)", order[i], order[i-1])
		}
	}
	if Severity("bogus").Rank() != 0 {
		t.Errorf("unknown severity rank = %d, want 0", Severity("bogus").Rank())
	}

	cases := map[string]Severity{
		"critical": SeverityCritical, "crit": SeverityCritical,
		"high": SeverityHigh, "error": SeverityHigh,
		"medium": SeverityMedium, "moderate": SeverityMedium, "warning": SeverityMedium, "warn": SeverityMedium,
		"low": SeverityLow, "note": SeverityLow,
		"info": SeverityInfo, "informational": SeverityInfo, "none": SeverityInfo,
		"  HIGH  ": SeverityHigh,
	}
	for input, want := range cases {
		got, ok := ParseSeverity(input)
		if !ok || got != want {
			t.Errorf("ParseSeverity(%q) = (%q, %v), want %q", input, got, ok, want)
		}
	}
	for _, input := range []string{"", "urgent", "critical!"} {
		if _, ok := ParseSeverity(input); ok {
			t.Errorf("ParseSeverity(%q) accepted an invalid value", input)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityHigh.AtLeast(SeverityMedium) {
		t.Error("high should be at least medium")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Error("low should not be at least high")
	}
	if !SeverityCritical.AtLeast(SeverityCritical) {
		t.Error("critical should be at least itself")
	}
	if SeverityInfo.AtLeast(SeverityLow) {
		t.Error("info should not be at least low")
	}
}

func sampleFinding() Finding {
	return Finding{
		RuleID:     "VGL-TEST-001",
		Title:      "test",
		Severity:   SeverityHigh,
		Evidence:   "  TOKEN = \"abc\"  ",
		Location:   Location{Path: "src/./auth.go", StartLine: 10},
		CWE:        []string{"CWE-89", "CWE-79"},
		OWASP:      []string{"A03:2021", "A01:2021"},
		Tags:       []string{"z", "a"},
		References: []string{"https://b.example", "https://a.example"},
	}
}

func TestComputeIDStableAndLineSensitive(t *testing.T) {
	a := sampleFinding()
	b := sampleFinding()
	b.Evidence = `token = "ABC"` // case and whitespace are normalised
	if a.ComputeID() != b.ComputeID() {
		t.Fatalf("IDs differ for normalised evidence: %q vs %q", a.ComputeID(), b.ComputeID())
	}
	if !strings.HasPrefix(a.ComputeID(), "VGL-") || len(a.ComputeID()) != 14 {
		t.Fatalf("unexpected ID shape: %q", a.ComputeID())
	}

	c := sampleFinding()
	c.Location.StartLine = 11
	if a.ComputeID() == c.ComputeID() {
		t.Fatal("ID did not change when the line changed")
	}
	if a.ComputeFingerprint() != c.ComputeFingerprint() {
		t.Fatal("fingerprint changed when only the line moved")
	}
}

func TestFingerprintStableAcrossLineMove(t *testing.T) {
	a := sampleFinding()
	b := sampleFinding()
	b.Location.StartLine = 99
	b.Location.EndLine = 100
	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Fatal("fingerprint depends on line numbers")
	}
	other := Finding{RuleID: a.RuleID, Location: Location{Path: a.Location.Path}, Evidence: "different"}
	if a.ComputeFingerprint() == other.ComputeFingerprint() {
		t.Fatal("fingerprint ignores evidence")
	}
	if !strings.HasPrefix(a.ComputeFingerprint(), "fp_") {
		t.Fatalf("unexpected fingerprint shape: %q", a.ComputeFingerprint())
	}
}

func TestNormalizeFillsAndSorts(t *testing.T) {
	f := sampleFinding()
	f.Normalize()
	if f.ID == "" || f.Fingerprint == "" {
		t.Fatalf("Normalize did not fill ID/fingerprint: %+v", f)
	}
	if f.Location.EndLine != f.Location.StartLine {
		t.Errorf("EndLine = %d, want %d", f.Location.EndLine, f.Location.StartLine)
	}
	if strings.Join(f.CWE, ",") != "CWE-79,CWE-89" {
		t.Errorf("CWE = %v", f.CWE)
	}
	if strings.Join(f.OWASP, ",") != "A01:2021,A03:2021" {
		t.Errorf("OWASP = %v", f.OWASP)
	}
	if strings.Join(f.Tags, ",") != "a,z" {
		t.Errorf("Tags = %v", f.Tags)
	}
	if strings.Join(f.References, ",") != "https://a.example,https://b.example" {
		t.Errorf("References = %v", f.References)
	}

	// A second Normalize must not change the values.
	id, fp := f.ID, f.Fingerprint
	f.Normalize()
	if f.ID != id || f.Fingerprint != fp {
		t.Fatal("Normalize is not idempotent")
	}
}

func TestSortFindings(t *testing.T) {
	fs := []Finding{
		{Severity: SeverityLow, Confidence: ConfidenceHigh, Location: Location{Path: "b.go", StartLine: 1}},
		{Severity: SeverityCritical, Confidence: ConfidenceLow, Location: Location{Path: "z.go", StartLine: 5}},
		{Severity: SeverityHigh, Confidence: ConfidenceHigh, Location: Location{Path: "a.go", StartLine: 9}},
		{Severity: SeverityHigh, Confidence: ConfidenceHigh, Location: Location{Path: "a.go", StartLine: 2}},
	}
	SortFindings(fs)
	want := []string{"z.go:5", "a.go:2", "a.go:9", "b.go:1"}
	var got []string
	for _, f := range fs {
		got = append(got, fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestFilter(t *testing.T) {
	fs := []Finding{
		{Severity: SeverityLow},
		{Severity: SeverityCritical},
		{Severity: SeverityMedium},
		{Severity: SeverityHigh},
	}
	got := Filter(fs, SeverityMedium, 0)
	if len(got) != 3 || got[0].Severity != SeverityCritical {
		t.Fatalf("Filter min=medium = %v", got)
	}
	got = Filter(fs, SeverityLow, 2)
	if len(got) != 2 {
		t.Fatalf("Filter max=2 returned %d findings", len(got))
	}
	got = Filter(fs, SeverityInfo, 10)
	if len(got) != 4 {
		t.Fatalf("Filter info = %d findings", len(got))
	}
}

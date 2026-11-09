package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

func sampleFinding() model.Finding {
	f := model.Finding{
		RuleID:     "TEST-SECRET",
		Title:      "secret",
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceHigh,
		Category:   model.CategorySecrets,
		Location:   model.Location{Path: "a.go", StartLine: 3},
		Evidence:   `password = "hunter2"`,
		Source:     model.SourceRule,
	}
	f.Normalize()
	return f
}

func TestBaselineRoundTripAndMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	f := sampleFinding()

	b := NewBaseline()
	if b.Version != BaselineVersion {
		t.Fatalf("version = %d", b.Version)
	}
	b.Add(f, "known issue")
	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if loaded.Version != BaselineVersion {
		t.Fatalf("loaded version = %d", loaded.Version)
	}
	if ok, why := loaded.Match(f); !ok || why != "known issue" {
		t.Fatalf("Match = %v, %q; want true, known issue", ok, why)
	}

	// The ID is an exact match even if the fingerprint was recomputed.
	byID := f
	byID.Fingerprint = "fp_different"
	if ok, _ := loaded.Match(byID); !ok {
		t.Fatal("expected match by finding ID")
	}

	other := f
	other.Evidence = `password = "different"`
	other.ID = ""
	other.Fingerprint = ""
	other.Normalize()
	if ok, _ := loaded.Match(other); ok {
		t.Fatal("unrelated finding matched the baseline")
	}
}

func TestBaselineMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	b, err := LoadBaseline(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatalf("missing baseline should be a no-op: %v", err)
	}
	if !b.empty() {
		t.Fatal("missing baseline should be empty")
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(bad); err == nil {
		t.Fatal("expected parse error")
	}

	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"version":99}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(future); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestScanAppliesBaseline(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", `var secret = "SECRET"`+"\n")

	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-SECRET",
		Title:    "secret",
		Severity: model.SeverityHigh,
		Category: model.CategorySecrets,
	}, func(f *rules.File) []model.Finding {
		for i, line := range f.Lines {
			if strings.Contains(line, "SECRET") {
				return []model.Finding{{
					Location: model.Location{Path: f.Path, StartLine: i + 1},
					Evidence: line,
				}}
			}
		}
		return nil
	}))

	s := New(reg, nil)
	full, err := s.Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("initial Scan: %v", err)
	}
	if len(full.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(full.Findings))
	}

	b := NewBaseline()
	b.Add(full.Findings[0], "accepted risk")
	if err := SaveBaseline(filepath.Join(root, DefaultBaselineFile), b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	res, err := s.Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatalf("baseline Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected all findings suppressed, got %#v", res.Findings)
	}
	if len(res.Suppressed) != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", len(res.Suppressed))
	}
	if !res.Suppressed[0].Suppressed || res.Suppressed[0].SuppressWhy != "accepted risk" {
		t.Fatalf("unexpected suppression: %#v", res.Suppressed[0])
	}

	again, err := s.Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("NoBaseline Scan: %v", err)
	}
	if len(again.Findings) != 1 {
		t.Fatalf("NoBaseline should ignore the file, got %d findings", len(again.Findings))
	}
}

func TestScanCorruptBaselineFailsOpen(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", `var secret = "SECRET"`+"\n")
	writeTestFile(t, root, DefaultBaselineFile, "{not json")

	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-SECRET",
		Title:    "secret",
		Severity: model.SeverityHigh,
		Category: model.CategorySecrets,
	}, func(f *rules.File) []model.Finding {
		for i, line := range f.Lines {
			if strings.Contains(line, "SECRET") {
				return []model.Finding{{
					Location: model.Location{Path: f.Path, StartLine: i + 1},
					Evidence: line,
				}}
			}
		}
		return nil
	}))

	res, err := New(reg, nil).Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("corrupt baseline must not hide findings, got %d", len(res.Findings))
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "baseline") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a baseline error, got %v", res.Errors)
	}
}

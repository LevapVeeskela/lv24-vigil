package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

func matchRule(id string, sev model.Severity, needle string) rules.Rule {
	return rules.New(model.RuleMeta{
		ID:       id,
		Title:    id,
		Severity: sev,
		Category: model.CategoryLogic,
	}, func(f *rules.File) []model.Finding {
		var out []model.Finding
		for i, line := range f.Lines {
			if strings.Contains(line, needle) {
				out = append(out, model.Finding{
					Location: model.Location{Path: f.Path, StartLine: i + 1},
					Evidence: line,
				})
			}
		}
		return out
	})
}

func findingIDs(findings []model.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.ID
	}
	return out
}

func TestScanDeterministicAcrossConcurrency(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		writeTestFile(t, root, fmt.Sprintf("f%02d.go", i), "line\nSECRET\n")
	}

	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-SECRET", model.SeverityHigh, "SECRET"))
	s := New(reg, nil)

	one, err := s.Scan(context.Background(), Options{Root: root, Concurrency: 1, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan concurrency 1: %v", err)
	}
	many, err := s.Scan(context.Background(), Options{Root: root, Concurrency: 8, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan concurrency 8: %v", err)
	}

	if len(one.Findings) != 20 || len(many.Findings) != 20 {
		t.Fatalf("expected 20 findings, got %d and %d", len(one.Findings), len(many.Findings))
	}
	a := strings.Join(findingIDs(one.Findings), ",")
	b := strings.Join(findingIDs(many.Findings), ",")
	if a != b {
		t.Fatalf("findings are not deterministic:\n%s\n%s", a, b)
	}
}

func TestScanRecoversRulePanics(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "a.go", "SECRET\n")
	writeTestFile(t, root, "b.go", "SECRET\n")

	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-PANIC",
		Title:    "panic",
		Severity: model.SeverityHigh,
		Category: model.CategoryLogic,
	}, func(f *rules.File) []model.Finding {
		panic("boom")
	}))
	reg.Add(matchRule("TEST-SECRET", model.SeverityHigh, "SECRET"))

	res, err := New(reg, nil).Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings from the healthy rule, got %d", len(res.Findings))
	}
	if len(res.Errors) != 2 {
		t.Fatalf("expected 2 panic errors, got %d: %v", len(res.Errors), res.Errors)
	}
	for _, e := range res.Errors {
		if !strings.Contains(e, "panicked") {
			t.Fatalf("unexpected error: %s", e)
		}
	}
}

func TestScanSeverityFilterAndMaxFindings(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "levels.go", strings.Join([]string{
		"CRITICAL",
		"HIGH",
		"MEDIUM",
		"LOW",
		"INFO",
		"",
	}, "\n"))

	levels := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}
	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-LEVELS",
		Title:    "levels",
		Severity: model.SeverityInfo,
		Category: model.CategoryLogic,
	}, func(f *rules.File) []model.Finding {
		out := make([]model.Finding, 0, len(levels))
		for i, level := range levels {
			out = append(out, model.Finding{
				Severity: level,
				Location: model.Location{Path: f.Path, StartLine: i + 1},
				Evidence: string(level),
			})
		}
		return out
	}))

	s := New(reg, nil)
	res, err := s.Scan(context.Background(), Options{
		Root:        root,
		MinSeverity: model.SeverityHigh,
		NoBaseline:  true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings at high+, got %d", len(res.Findings))
	}

	res, err = s.Scan(context.Background(), Options{
		Root:        root,
		MinSeverity: model.SeverityHigh,
		MaxFindings: 1,
		NoBaseline:  true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected only the critical finding, got %#v", res.Findings)
	}

	res, err = s.Scan(context.Background(), Options{
		Root:        root,
		MinSeverity: model.SeverityInfo,
		MaxFindings: 0,
		NoBaseline:  true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 5 {
		t.Fatalf("MaxFindings=0 must be unlimited, got %d", len(res.Findings))
	}
}

func TestScanDeduplicatesFindings(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "a.go", "SECRET\n")

	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "TEST-DUP",
		Title:    "dup",
		Severity: model.SeverityHigh,
		Category: model.CategoryLogic,
	}, func(f *rules.File) []model.Finding {
		finding := model.Finding{
			Location: model.Location{Path: f.Path, StartLine: 1},
			Evidence: "SECRET",
		}
		return []model.Finding{finding, finding}
	}))

	res, err := New(reg, nil).Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected duplicate findings to collapse, got %d", len(res.Findings))
	}
}

func TestScanOnlyAndDisableRules(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "a.go", "ALPHA\nBETA\n")

	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-ALPHA", model.SeverityHigh, "ALPHA"))
	reg.Add(matchRule("TEST-BETA", model.SeverityHigh, "BETA"))
	s := New(reg, nil)

	res, err := s.Scan(context.Background(), Options{Root: root, OnlyRules: []string{"TEST-ALPHA"}, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan only: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "TEST-ALPHA" {
		t.Fatalf("unexpected findings: %#v", res.Findings)
	}

	res, err = s.Scan(context.Background(), Options{Root: root, DisableRules: []string{"TEST-ALPHA"}, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan disable: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "TEST-BETA" {
		t.Fatalf("unexpected findings: %#v", res.Findings)
	}
}

func TestScanPathsExactSelection(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "a.go", "SECRET\n")
	writeTestFile(t, root, "b.go", "SECRET\n")

	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-SECRET", model.SeverityHigh, "SECRET"))
	s := New(reg, nil)

	res, err := s.ScanPaths(context.Background(), root, []string{"a.go"}, Options{NoBaseline: true})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Location.Path != "a.go" {
		t.Fatalf("scanned wrong path: %s", res.Findings[0].Location.Path)
	}

	// Absolute paths inside the root are accepted as well.
	abs := filepath.Join(root, "b.go")
	res, err = s.ScanPaths(context.Background(), root, []string{abs}, Options{NoBaseline: true})
	if err != nil {
		t.Fatalf("ScanPaths absolute: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Location.Path != "b.go" {
		t.Fatalf("absolute path scan failed: %#v", res.Findings)
	}
}

func TestScanPathsSkipsBinaryLargeAndOutside(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "bin.go", "SECRET\x00\n")
	writeTestFile(t, root, "big.go", strings.Repeat("SECRET", 100))
	outside := filepath.Join(filepath.Dir(root), "outside-vigil-test.go")
	if err := os.WriteFile(outside, []byte("SECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outside)

	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-SECRET", model.SeverityHigh, "SECRET"))
	s := New(reg, nil)

	res, err := s.ScanPaths(context.Background(), root, []string{"bin.go", "big.go", "../outside-vigil-test.go"}, Options{
		MaxFileBytes: 100,
		NoBaseline:   true,
	})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if res.Stats.FilesSkipped != 3 {
		t.Fatalf("files skipped = %d, want 3", res.Stats.FilesSkipped)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "outside scan root") {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
}

func TestScanFilesUsesProvidedFiles(t *testing.T) {
	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-SECRET", model.SeverityHigh, "SECRET"))
	s := New(reg, nil)

	file := &rules.File{
		Path:     "inline.go",
		Content:  []byte("SECRET\n"),
		Lines:    []string{"SECRET", ""},
		Language: LanguageGo,
		Size:     7,
	}
	res, err := s.ScanFiles(context.Background(), []*rules.File{nil, file}, Options{NoBaseline: true})
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Stats.FilesScanned != 1 || res.Stats.FilesSkipped != 1 {
		t.Fatalf("unexpected stats: %+v", res.Stats)
	}
}

func TestScanStatsAndEngine(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "a.go", "SECRET\n")
	writeTestFile(t, root, "b.go", "SECRET\n")

	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-SECRET", model.SeverityHigh, "SECRET"))
	reg.Add(matchRule("TEST-SECRET-2", model.SeverityMedium, "SECRET"))

	res, err := New(reg, nil).Scan(context.Background(), Options{Root: root, NoBaseline: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Engine != EngineName {
		t.Errorf("engine = %q", res.Engine)
	}
	if res.Version != EngineVersion {
		t.Errorf("version = %q", res.Version)
	}
	if res.Mode != "standard" {
		t.Errorf("mode = %q", res.Mode)
	}
	if res.Stats.FilesScanned != 2 {
		t.Errorf("files scanned = %d", res.Stats.FilesScanned)
	}
	if res.Stats.RulesRun != 2 {
		t.Errorf("rules run = %d", res.Stats.RulesRun)
	}
	if res.Stats.BytesScanned == 0 {
		t.Error("bytes scanned = 0")
	}
	if res.Stats.DurationMS < 0 {
		t.Error("negative duration")
	}
	if res.Stats.BySeverity[model.SeverityHigh] != 2 {
		t.Errorf("high count = %d", res.Stats.BySeverity[model.SeverityHigh])
	}
	if res.Stats.ByCategory[model.CategoryLogic] != 4 {
		t.Errorf("category count = %d", res.Stats.ByCategory[model.CategoryLogic])
	}
	if len(res.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(res.Findings))
	}
}

func TestScanMissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := New(rules.NewRegistry(), nil).Scan(context.Background(), Options{Root: missing}); err == nil {
		t.Fatal("expected an error for a missing root")
	}
}

func TestScanChangedOnly(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}
	root := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Vigil Test",
			"GIT_AUTHOR_EMAIL=vigil@example.test",
			"GIT_COMMITTER_NAME=Vigil Test",
			"GIT_COMMITTER_EMAIL=vigil@example.test",
			"GIT_CONFIG_NOSYSTEM=1",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	runGit("init", "-q")
	runGit("config", "core.autocrlf", "false")
	runGit("config", "commit.gpgsign", "false")
	writeTestFile(t, root, "a.go", "package a\n")
	writeTestFile(t, root, "b.go", "package b\n")
	runGit("add", "-A")
	runGit("commit", "-q", "-m", "initial")

	writeTestFile(t, root, "a.go", "package a\n// SECRET\n")
	writeTestFile(t, root, "c.go", "// SECRET\n")

	reg := rules.NewRegistry()
	reg.Add(matchRule("TEST-SECRET", model.SeverityHigh, "SECRET"))
	res, err := New(reg, nil).Scan(context.Background(), Options{
		Root:        root,
		ChangedOnly: true,
		NoBaseline:  true,
	})
	if err != nil {
		t.Fatalf("Scan changed-only: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(res.Findings), res.Findings)
	}
	paths := map[string]bool{}
	for _, f := range res.Findings {
		paths[f.Location.Path] = true
	}
	if !paths["a.go"] || !paths["c.go"] || paths["b.go"] {
		t.Fatalf("unexpected changed paths: %v", paths)
	}
}

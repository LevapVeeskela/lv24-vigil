package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func testTime(seconds int) time.Time {
	return time.Date(2026, time.February, 3, 4, 5, seconds, 0, time.UTC)
}

func sampleResult() *model.ScanResult {
	return &model.ScanResult{
		ID:         "scan-test-1",
		StartedAt:  testTime(0),
		FinishedAt: testTime(7),
		Root:       "/repo",
		Mode:       "standard",
		Findings: []model.Finding{
			{
				ID:          "VGL-CRIT000001",
				RuleID:      "go/sql-injection",
				Title:       "SQL injection",
				Description: "User input is concatenated into a SQL query.",
				Severity:    model.SeverityCritical,
				Confidence:  model.ConfidenceHigh,
				Category:    model.CategoryInjection,
				CWE:         []string{"CWE-89"},
				OWASP:       []string{"A03:2021"},
				Location: model.Location{
					Path:        "internal/db/query name.go",
					StartLine:   42,
					EndLine:     44,
					StartColumn: 5,
					EndColumn:   20,
					Snippet:     "q := buildQuery(name)",
				},
				Evidence:    "db.Query(\"SELECT * FROM users WHERE name = '\" + name + \"'\")",
				Remediation: "Use parameterized queries.",
				References:  []string{"https://example.com/sql-injection"},
				Tags:        []string{"sql", "database"},
				Fingerprint: "fp_sql_123",
				Source:      model.SourceRule,
				LLM: &model.LLMJudgement{
					Verdict:     "true_positive",
					Severity:    model.SeverityHigh,
					Confidence:  0.91,
					Reasoning:   "The name variable is attacker controlled.",
					Exploit:     "Send a crafted name parameter.",
					Remediation: "Bind the name parameter.",
					Model:       "gpt-test",
				},
				Fix: &model.Fix{
					Description: "Use a parameterized query.",
					Diff: "--- a/internal/db/query name.go\n" +
						"+++ b/internal/db/query name.go\n" +
						"@@ -42,1 +42,1 @@\n" +
						"-db.Query(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n" +
						"+db.Query(\"SELECT * FROM users WHERE name = ?\", name)\n",
					Files: []string{"internal/db/query name.go"},
				},
			},
			{
				ID:          "VGL-MED000002",
				RuleID:      "go/sql-injection",
				Title:       "SQL injection in report query",
				Description: "A second query is built with fmt.Sprintf.",
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceMedium,
				Category:    model.CategoryInjection,
				CWE:         []string{"CWE-89"},
				Location: model.Location{
					Path:      "internal/report/report.go",
					StartLine: 10,
					EndLine:   10,
				},
				Evidence: "query := fmt.Sprintf(\"SELECT * FROM reports WHERE id = %s\", id)",
				Source:   model.SourceRule,
			},
			{
				ID:          "VGL-LOW000003",
				RuleID:      "config/debug",
				Title:       "Debug mode enabled",
				Description: "Debug output can leak internals.",
				Severity:    model.SeverityLow,
				Confidence:  model.ConfidenceLow,
				Category:    model.CategoryConfig,
				Location: model.Location{
					Path:      "config/app.yaml",
					StartLine: 3,
				},
				Evidence: "debug: true\nsample := ```\n",
				Source:   model.SourceRule,
			},
			{
				ID:          "VGL-INFO000004",
				RuleID:      "web/xss",
				Title:       "<script>alert('xss')</script>",
				Description: "Reflected <script> content reaches the page.",
				Severity:    model.SeverityInfo,
				Confidence:  model.ConfidenceMedium,
				Category:    model.CategoryWeb,
				Location: model.Location{
					Path:      "web/view.html",
					StartLine: 1,
				},
				Evidence: "<script>alert(1)</script>",
				Source:   model.SourceRule,
			},
		},
		Suppressed: []model.Finding{
			{
				ID:          "VGL-SUP000005",
				RuleID:      "secrets/hardcoded",
				Title:       "Hardcoded secret",
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceHigh,
				Category:    model.CategorySecrets,
				Location:    model.Location{Path: "internal/config/secret.go", StartLine: 7},
				Evidence:    "const token = \"not-a-real-secret\"",
				Suppressed:  true,
				SuppressWhy: "baseline: known test fixture",
				Source:      model.SourceRule,
			},
		},
		Stats: model.Stats{
			FilesScanned: 12,
			FilesSkipped: 3,
			BytesScanned: 45678,
			DurationMS:   123,
			BySeverity: map[model.Severity]int{
				model.SeverityCritical: 1,
				model.SeverityMedium:   1,
				model.SeverityLow:      1,
				model.SeverityInfo:     1,
			},
			ByCategory: map[model.Category]int{
				model.CategoryInjection: 2,
				model.CategoryConfig:    1,
				model.CategoryWeb:       1,
			},
			RulesRun:  25,
			LLMCalls:  2,
			LLMTokens: 1234,
		},
		Model: &model.ModelInfo{
			Provider: "openai",
			Model:    "gpt-test",
			BaseURL:  "https://llm.example.com",
		},
		ThreatModel: "Untrusted input reaches a database query.",
		Errors:      []string{"skipped unreadable file"},
		Engine:      "vigil",
		Version:     "0.1.0-test",
	}
}

func emptyResult() *model.ScanResult {
	return &model.ScanResult{
		ID:         "scan-empty",
		StartedAt:  testTime(0),
		FinishedAt: testTime(1),
		Root:       "/repo",
		Mode:       "quick",
		Engine:     "vigil",
		Version:    "0.1.0-test",
	}
}

func TestRenderFormats(t *testing.T) {
	formats := []string{"md", "markdown", "", "json", "sarif", "html", "htm"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			out, err := Render(format, sampleResult(), Options{ShowFix: true})
			if err != nil {
				t.Fatalf("Render(%q) error: %v", format, err)
			}
			if len(out) == 0 {
				t.Fatalf("Render(%q) returned no output", format)
			}
		})
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	if _, err := Render("pdf", sampleResult(), Options{}); err == nil {
		t.Fatal("Render(pdf) expected an error")
	}
}

func TestRenderNilResult(t *testing.T) {
	if _, err := Render("md", nil, Options{}); err == nil {
		t.Fatal("Render(nil) expected an error")
	}
}

func TestWriteMatchesRender(t *testing.T) {
	res := sampleResult()
	want, err := Render("md", res, Options{ShowFix: true})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Write(&buf, "md", res, Options{ShowFix: true}); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatal("Write output differs from Render output")
	}
}

func TestWriteNilWriter(t *testing.T) {
	if err := Write(nil, "md", sampleResult(), Options{}); err == nil {
		t.Fatal("Write(nil) expected an error")
	}
}

func TestColorIsNoOp(t *testing.T) {
	res := sampleResult()
	for _, format := range []string{"md", "json", "sarif", "html"} {
		plain, err := Render(format, res, Options{ShowFix: true})
		if err != nil {
			t.Fatal(err)
		}
		colored, err := Render(format, res, Options{Color: true, ShowFix: true})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, colored) {
			t.Fatalf("%s output changed when Color=true", format)
		}
	}
}

func TestRenderDeterministic(t *testing.T) {
	res := sampleResult()
	for _, format := range []string{"md", "json", "sarif", "html"} {
		first, err := Render(format, res, Options{ShowFix: true})
		if err != nil {
			t.Fatal(err)
		}
		second, err := Render(format, res, Options{ShowFix: true})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("%s output is not deterministic", format)
		}
	}
}

func TestRenderDoesNotMutateResult(t *testing.T) {
	res := emptyResult()
	res.Findings = []model.Finding{
		{ID: "low", Severity: model.SeverityLow, Location: model.Location{Path: "b.go", StartLine: 2}},
		{ID: "critical", Severity: model.SeverityCritical, Location: model.Location{Path: "a.go", StartLine: 1}},
	}
	res.Suppressed = []model.Finding{
		{ID: "suppressed-low", Severity: model.SeverityLow, Location: model.Location{Path: "c.go", StartLine: 3}},
	}

	beforeFirst := res.Findings[0].ID
	beforeSuppressed := res.Suppressed[0].ID
	if _, err := Render("md", res, Options{}); err != nil {
		t.Fatal(err)
	}
	if res.Findings[0].ID != beforeFirst {
		t.Fatalf("Render reordered res.Findings: got %q, want %q", res.Findings[0].ID, beforeFirst)
	}
	if res.Suppressed[0].ID != beforeSuppressed {
		t.Fatalf("Render reordered res.Suppressed: got %q, want %q", res.Suppressed[0].ID, beforeSuppressed)
	}
}

func TestEmptyResultAllFormats(t *testing.T) {
	res := emptyResult()
	for _, format := range []string{"md", "json", "sarif", "html"} {
		out, err := Render(format, res, Options{})
		if err != nil {
			t.Fatalf("Render(%q) empty result error: %v", format, err)
		}
		if len(out) == 0 {
			t.Fatalf("Render(%q) empty result returned no output", format)
		}
	}
}

func TestInlineCodeWidensFence(t *testing.T) {
	got := inlineCode("a`b")
	if !strings.HasPrefix(got, "``") || !strings.HasSuffix(got, "``") {
		t.Fatalf("inlineCode did not widen fence: %q", got)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func containsAll(s string, wants ...string) bool {
	for _, want := range wants {
		if !strings.Contains(s, want) {
			return false
		}
	}
	return true
}

func TestArtifactURI(t *testing.T) {
	tests := []struct {
		name string
		path string
		root string
		want string
	}{
		{name: "relative", path: "internal/a.go", root: "/repo", want: "internal/a.go"},
		{name: "spaces", path: "internal/query name.go", root: "/repo", want: "internal/query%20name.go"},
		{name: "rooted", path: "/repo/internal/a.go", root: "/repo", want: "internal/a.go"},
		{name: "windows", path: `C:\repo\internal\a.go`, root: `C:\repo`, want: "internal/a.go"},
		{name: "dot slash", path: "./internal/a.go", root: "/repo", want: "internal/a.go"},
		{name: "unicode", path: "docs/привет.go", root: "/repo", want: "docs/%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82.go"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := artifactURI(tt.path, tt.root); got != tt.want {
				t.Fatalf("artifactURI(%q, %q) = %q, want %q", tt.path, tt.root, got, tt.want)
			}
		})
	}
}

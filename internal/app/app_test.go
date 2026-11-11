package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
)

const testAWSKey = "AKIAZ7Q2LMN4RSTUVWXY"

func hermeticEnv(t *testing.T) {
	t.Helper()
	t.Setenv("VIGIL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("VIGIL_NO_LLM", "1")
	for _, env := range []string{
		"VIGIL_PROVIDER", "VIGIL_MODEL", "VIGIL_BASE_URL", "VIGIL_API_KEY",
		"VIGIL_USE_LLM", "VIGIL_MODE", "VIGIL_MIN_SEVERITY", "VIGIL_CONCURRENCY",
		"VIGIL_MAX_FINDINGS", "VIGIL_FORMAT",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
		"OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY",
		"XAI_API_KEY", "OLLAMA_HOST",
	} {
		t.Setenv(env, "")
	}
}

func newTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".vigil"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.py"),
		[]byte("aws_access_key_id = \""+testAWSKey+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestNewScanAndStore(t *testing.T) {
	hermeticEnv(t)
	repo := newTestRepo(t)

	a, err := New(repo, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if a.Root != repo {
		t.Fatalf("Root = %q, want %q", a.Root, repo)
	}
	if a.LLM {
		t.Fatal("LLM is enabled despite VIGIL_NO_LLM=1 and no provider")
	}
	if !strings.HasPrefix(a.Store.Dir(), repo) {
		t.Errorf("Store.Dir() = %q, want inside %q", a.Store.Dir(), repo)
	}

	res, err := a.Scan(context.Background(), model.ScanRequest{Mode: "quick"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("Scan returned no findings for a hardcoded AWS key")
	}
	if res.Findings[0].RuleID != "VGL-SEC-001" {
		t.Errorf("first rule = %q, want VGL-SEC-001", res.Findings[0].RuleID)
	}
	if res.ID == "" {
		t.Fatal("scan has no ID")
	}

	last, err := a.LastScan()
	if err != nil {
		t.Fatalf("LastScan: %v", err)
	}
	if last.ID != res.ID {
		t.Errorf("LastScan ID = %q, want %q", last.ID, res.ID)
	}
	got, err := a.GetScan(res.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if len(got.Findings) != len(res.Findings) {
		t.Errorf("stored findings = %d, want %d", len(got.Findings), len(res.Findings))
	}
}

func TestReviewUnifiedDiff(t *testing.T) {
	hermeticEnv(t)
	repo := newTestRepo(t)
	a, err := New(repo, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	diff := "--- a/example.py\n+++ b/example.py\n@@ -0,0 +1,2 @@\n" +
		"+aws_access_key_id = \"" + testAWSKey + "\"\n+x = 1\n"
	res, err := a.Review(context.Background(), model.ScanRequest{Diff: diff})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if res.Mode != "quick" {
		t.Errorf("review mode = %q, want quick", res.Mode)
	}
	if len(res.Findings) == 0 {
		t.Fatal("review found nothing on the added key")
	}
	if res.Findings[0].Location.Path != "example.py" {
		t.Errorf("finding path = %q, want example.py", res.Findings[0].Location.Path)
	}
}

func TestOptionsMapping(t *testing.T) {
	hermeticEnv(t)
	t.Setenv("VIGIL_MODE", "quick")
	t.Setenv("VIGIL_MIN_SEVERITY", "high")
	t.Setenv("VIGIL_CONCURRENCY", "7")
	t.Setenv("VIGIL_MAX_FINDINGS", "9")

	a, err := New(newTestRepo(t), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	opts := a.Options(model.ScanRequest{})
	if opts.Mode != "quick" || opts.MinSeverity != model.SeverityHigh {
		t.Errorf("mode/severity = %q/%q", opts.Mode, opts.MinSeverity)
	}
	if opts.Concurrency != 7 || opts.MaxFindings != 9 {
		t.Errorf("concurrency/max = %d/%d", opts.Concurrency, opts.MaxFindings)
	}

	over := a.Options(model.ScanRequest{
		Mode:        "deep",
		MinSeverity: model.SeverityCritical,
		Concurrency: 2,
		MaxFindings: 3,
	})
	if over.Mode != "deep" || over.MinSeverity != model.SeverityCritical ||
		over.Concurrency != 2 || over.MaxFindings != 3 {
		t.Errorf("request overrides were not applied: %+v", over)
	}
}

func TestApplyFixRejectsEmptyAndUnsafeDiff(t *testing.T) {
	hermeticEnv(t)
	a, err := New(newTestRepo(t), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	if err := a.ApplyFix(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "empty fix") {
		t.Fatalf("ApplyFix(nil) = %v, want an empty-fix error", err)
	}
	if err := a.ApplyFix(context.Background(), &model.Fix{Diff: "  \n"}); err == nil || !strings.Contains(err.Error(), "empty fix") {
		t.Fatalf("ApplyFix(empty) = %v, want an empty-fix error", err)
	}
	unsafe := "--- a/../outside.txt\n+++ b/../outside.txt\n@@ -1 +1 @@\n-old\n+new\n"
	err = a.ApplyFix(context.Background(), &model.Fix{Diff: unsafe})
	if err == nil || !strings.Contains(err.Error(), "refusing to apply") {
		t.Fatalf("ApplyFix(unsafe) = %v, want a validation error", err)
	}
}

func TestNewOnFilePathUsesDirectory(t *testing.T) {
	hermeticEnv(t)
	dir := newTestRepo(t)
	file := filepath.Join(dir, "config.py")

	a, err := New(file, nil)
	if err != nil {
		t.Fatalf("New(file): %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.Root != abs {
		t.Errorf("Root = %q, want %q", a.Root, abs)
	}
}

func TestScanOSVIntegration(t *testing.T) {
	hermeticEnv(t)
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{
  "name": "fixture",
  "version": "1.0.0",
  "dependencies": {"left-pad": "1.0.0"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []any{
				map[string]any{
					"vulns": []any{
						map[string]any{
							"id":                "GHSA-test-1234",
							"summary":           "Test dependency vulnerability",
							"database_specific": map[string]any{"severity": "HIGH"},
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	// A project file may opt into OSV, but the endpoint override must come
	// from a trusted source (the environment here), never the project file.
	t.Setenv("VIGIL_OSV_BASE_URL", server.URL)
	cfg := "scan:\n  osv: true\n"
	if err := os.WriteFile(filepath.Join(repo, ".vigil.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := New(repo, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	disabled := false
	res, err := a.Scan(context.Background(), model.ScanRequest{UseLLM: &disabled})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var found *model.Finding
	for i := range res.Findings {
		if strings.HasPrefix(res.Findings[i].RuleID, "VGL-OSV-") {
			found = &res.Findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no OSV finding in %+v (errors: %v)", res.Findings, res.Errors)
	}
	if found.Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high", found.Severity)
	}
	if !strings.Contains(found.Title, "left-pad@1.0.0") {
		t.Errorf("title = %q", found.Title)
	}
}

// Regression: OSV advisories were appended after the scanner's filters, so
// they ignored the baseline, the minimum severity and the stats.
func TestScanOSVFindingsHonourBaselineSeverityAndStats(t *testing.T) {
	hermeticEnv(t)
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "requirements.txt"), []byte("requests==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{map[string]any{"vulns": []any{
			map[string]any{"id": "GHSA-base-line", "summary": "s", "database_specific": map[string]any{"severity": "HIGH"}},
		}}}})
	}))
	defer server.Close()
	t.Setenv("VIGIL_OSV_BASE_URL", server.URL)
	if err := os.WriteFile(filepath.Join(repo, ".vigil.yaml"), []byte("scan:\n  osv: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := New(repo, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	disabled := false

	// Stats count the advisory.
	res, err := a.Scan(context.Background(), model.ScanRequest{UseLLM: &disabled})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var osvFinding *model.Finding
	for i := range res.Findings {
		if strings.HasPrefix(res.Findings[i].RuleID, "VGL-OSV-") {
			osvFinding = &res.Findings[i]
		}
	}
	if osvFinding == nil {
		t.Fatalf("no OSV finding: %+v", res.Findings)
	}
	if res.Stats.BySeverity[model.SeverityHigh] == 0 {
		t.Errorf("stats ignore the OSV finding: %+v", res.Stats.BySeverity)
	}

	// Minimum severity filters it.
	res, err = a.Scan(context.Background(), model.ScanRequest{UseLLM: &disabled, MinSeverity: model.SeverityCritical})
	if err != nil {
		t.Fatalf("Scan critical: %v", err)
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.RuleID, "VGL-OSV-") {
			t.Fatalf("min severity critical kept %s", f.RuleID)
		}
	}

	// The baseline suppresses it.
	b := scanner.NewBaseline()
	b.Add(*osvFinding, "accepted risk")
	if err := scanner.SaveBaseline(filepath.Join(repo, scanner.DefaultBaselineFile), b); err != nil {
		t.Fatal(err)
	}
	res, err = a.Scan(context.Background(), model.ScanRequest{UseLLM: &disabled})
	if err != nil {
		t.Fatalf("Scan baseline: %v", err)
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.RuleID, "VGL-OSV-") {
			t.Fatalf("baselined advisory is still active: %s", f.RuleID)
		}
	}
	suppressed := false
	for _, f := range res.Suppressed {
		suppressed = suppressed || strings.HasPrefix(f.RuleID, "VGL-OSV-")
	}
	if !suppressed {
		t.Fatalf("baselined advisory missing from suppressed: %+v", res.Suppressed)
	}
}

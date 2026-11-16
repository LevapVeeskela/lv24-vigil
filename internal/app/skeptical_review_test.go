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
)

// Regression: the scanner capped rule findings first, OSV advisories were
// appended behind them, and the final cap ran before the sort. With as many
// rule findings as the cap, a critical advisory was dropped and --fail-on
// critical passed. The cap must keep the most severe findings, and a capped
// result must say so.
func TestScanCapKeepsMostSevereAfterOSVMerge(t *testing.T) {
	hermeticEnv(t)
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{
  "name": "fixture",
  "version": "1.0.0",
  "dependencies": {"left-pad": "1.0.0"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	src.WriteString("import os\nfrom flask import request\n\n")
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		src.WriteString("def run_" + name + "():\n    os.system(\"ls \" + request.args[\"" + name + "\"])\n\n")
	}
	if err := os.WriteFile(filepath.Join(repo, "handlers.py"), []byte(src.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []any{
				map[string]any{
					"vulns": []any{
						map[string]any{
							"id":                "GHSA-crit-0001",
							"summary":           "Critical dependency vulnerability",
							"database_specific": map[string]any{"severity": "CRITICAL"},
						},
					},
				},
			},
		})
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
	uncapped, err := a.Scan(context.Background(), model.ScanRequest{UseLLM: &disabled, MaxFindings: 1000})
	if err != nil {
		t.Fatalf("Scan (uncapped): %v", err)
	}
	if len(uncapped.Findings) < 5 {
		t.Fatalf("fixture produced %d findings, want at least 5: %+v", len(uncapped.Findings), uncapped.Findings)
	}
	if uncapped.Stats.Truncated != 0 {
		t.Fatalf("an uncapped scan reports %d truncated findings", uncapped.Stats.Truncated)
	}

	const limit = 3
	res, err := a.Scan(context.Background(), model.ScanRequest{UseLLM: &disabled, MaxFindings: limit})
	if err != nil {
		t.Fatalf("Scan (capped): %v", err)
	}
	if len(res.Findings) != limit {
		t.Fatalf("findings = %d, want the cap %d", len(res.Findings), limit)
	}
	if res.Findings[0].Severity != model.SeverityCritical || !strings.HasPrefix(res.Findings[0].RuleID, "VGL-OSV-") {
		t.Fatalf("the critical advisory was dropped by the cap; kept %s (%s) first", res.Findings[0].RuleID, res.Findings[0].Severity)
	}
	want := len(uncapped.Findings) - limit
	if res.Stats.Truncated != want {
		t.Errorf("stats.findingsTruncated = %d, want %d", res.Stats.Truncated, want)
	}
	if joined := strings.Join(res.Errors, "\n"); !strings.Contains(joined, "truncated") {
		t.Errorf("a capped result does not say it is truncated: %v", res.Errors)
	}
}

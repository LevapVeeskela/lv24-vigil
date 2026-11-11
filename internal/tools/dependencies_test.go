package tools_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/osv"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
)

// depsPayload mirrors the structuredContent of vigil_dependencies.
type depsPayload struct {
	Packages    []osv.Package   `json:"packages"`
	Findings    []model.Finding `json:"findings"`
	Errors      []string        `json:"errors"`
	Limitations []string        `json:"limitations"`
}

// osvQueryBatch is the subset of the querybatch request the fake server reads.
type osvQueryBatch struct {
	Queries []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	} `json:"queries"`
}

// fakeOSV starts a local OSV API that answers every query with a fixed
// advisory for left-pad and an empty result for everything else. It returns the
// server and a counter of querybatch requests.
func fakeOSV(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected OSV path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected OSV method %q", r.Method)
		}
		var batch osvQueryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode querybatch: %v", err)
		}
		calls++
		results := make([]any, 0, len(batch.Queries))
		for _, q := range batch.Queries {
			if q.Package.Name != "left-pad" {
				results = append(results, map[string]any{})
				continue
			}
			results = append(results, map[string]any{"vulns": []any{map[string]any{
				"id":      "GHSA-test-1234",
				"summary": "Test dependency vulnerability",
				"affected": []any{map[string]any{
					"package": map[string]any{"name": "left-pad", "ecosystem": q.Package.Ecosystem},
					"ranges": []any{map[string]any{
						"type":   "ECOSYSTEM",
						"events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "2.0.0"}},
					}},
				}},
				"database_specific": map[string]any{"severity": "HIGH"},
			}}})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func writeRepoFile(t *testing.T, repo, name, content string) {
	t.Helper()
	p := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestE2EDependenciesKnownAdvisories(t *testing.T) {
	h := newHarness(t)
	writeRepoFile(t, h.repo, "package.json", `{
  "name": "fixture",
  "version": "1.0.0",
  "dependencies": {"left-pad": "1.0.0"},
  "devDependencies": {"jest": "29.0.0"}
}`)
	srv, calls := fakeOSV(t)

	res := h.client.mustTool("vigil_dependencies", map[string]any{
		"osvBaseUrl":  srv.URL,
		"maxPackages": 10,
	})
	payload := structuredInto[depsPayload](t, res)

	if *calls != 1 {
		t.Errorf("querybatch calls = %d, want 1", *calls)
	}
	if len(payload.Packages) != 2 {
		t.Fatalf("packages = %d, want 2 (includeDev defaults to true): %+v", len(payload.Packages), payload.Packages)
	}
	names := map[string]osv.Package{}
	for _, p := range payload.Packages {
		names[p.Name] = p
	}
	if got, ok := names["left-pad"]; !ok || got.Version != "1.0.0" || got.Manifest != "package.json" {
		t.Errorf("left-pad package = %+v", got)
	}
	if len(payload.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(payload.Findings), payload.Findings)
	}
	f := payload.Findings[0]
	if !strings.HasPrefix(f.RuleID, "VGL-OSV-") {
		t.Errorf("rule id = %q, want a VGL-OSV id", f.RuleID)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.Remediation, "2.0.0") {
		t.Errorf("remediation = %q, want the fixed version", f.Remediation)
	}
	if len(payload.Errors) != 0 {
		t.Errorf("errors = %v, want none", payload.Errors)
	}
	if len(payload.Limitations) == 0 {
		t.Error("limitations are empty")
	}

	text := textOf(t, res)
	for _, want := range []string{
		"Known public advisories only; no match does not mean safe",
		"Packages: 2 queried",
		"Vulnerable dependency left-pad@1.0.0",
		"not a vulnerability verdict",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
}

func TestE2EDependenciesExcludeDev(t *testing.T) {
	h := newHarness(t)
	writeRepoFile(t, h.repo, "package.json", `{
  "name": "fixture",
  "version": "1.0.0",
  "dependencies": {"left-pad": "1.0.0"},
  "devDependencies": {"jest": "29.0.0"}
}`)
	srv, _ := fakeOSV(t)

	res := h.client.mustTool("vigil_dependencies", map[string]any{
		"osvBaseUrl": srv.URL,
		"includeDev": false,
	})
	payload := structuredInto[depsPayload](t, res)
	if len(payload.Packages) != 1 || payload.Packages[0].Name != "left-pad" {
		t.Fatalf("packages = %+v, want only left-pad", payload.Packages)
	}
	if !strings.Contains(textOf(t, res), "dev dependencies excluded") {
		t.Errorf("text does not state that dev dependencies were excluded:\n%s", textOf(t, res))
	}
}

func TestE2EDependenciesRejectsBadArguments(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"missing path", map[string]any{"path": "no-such-directory-xyz"}, "invalid arguments"},
		{"negative maxPackages", map[string]any{"maxPackages": -1}, "maxPackages"},
		{"bad osv url", map[string]any{"osvBaseUrl": "ftp://example.test"}, "absolute http(s) URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := h.client.tool("vigil_dependencies", tc.args)
			if !res.IsError {
				t.Fatalf("expected an error result, got %s", textOf(t, res))
			}
			if !strings.Contains(textOf(t, res), tc.want) {
				t.Errorf("error %q does not contain %q", textOf(t, res), tc.want)
			}
		})
	}
}

func TestE2EHardeningRunsOnlyAntiRERules(t *testing.T) {
	h := newHarness(t)

	// Replace the production registry with a tiny fake one so the test proves
	// the selection contract, not the detection quality of the ARE rules.
	reg := rules.NewRegistry()
	reg.Add(
		rules.New(model.RuleMeta{
			ID:       "VGL-ARE-003",
			Title:    "Debuggable release manifest",
			Severity: model.SeverityHigh,
			Category: model.CategoryAntiRE,
		}, func(f *rules.File) []model.Finding {
			if !strings.Contains(string(f.Content), `android:debuggable="true"`) {
				return nil
			}
			return []model.Finding{{Location: model.Location{Path: f.Path, StartLine: 1}}}
		}),
		rules.New(model.RuleMeta{
			ID:       "VGL-ARE-030",
			Title:    "Electron web security disabled",
			Severity: model.SeverityHigh,
			Category: model.CategoryAntiRE,
		}, func(f *rules.File) []model.Finding {
			if !strings.Contains(string(f.Content), "webSecurity: false") {
				return nil
			}
			return []model.Finding{{Location: model.Location{Path: f.Path, StartLine: 1}}}
		}),
		rules.New(model.RuleMeta{
			ID:       "VGL-SEC-999",
			Title:    "Fake secrets rule",
			Severity: model.SeverityCritical,
			Category: model.CategorySecrets,
		}, func(f *rules.File) []model.Finding {
			if !strings.Contains(string(f.Content), "aws_access_key_id") {
				return nil
			}
			return []model.Finding{{Location: model.Location{Path: f.Path, StartLine: 1}}}
		}),
	)
	h.app.Registry = reg
	h.app.Scanner = scanner.New(reg, nil)

	writeRepoFile(t, h.repo, "android/app/src/main/AndroidManifest.xml",
		`<manifest><application android:debuggable="true"/></manifest>`)
	writeRepoFile(t, h.repo, "electron/main.js", "new BrowserWindow({webSecurity: false});\n")

	res := h.client.mustTool("vigil_hardening", map[string]any{"noBaseline": true})
	scan := structuredInto[model.ScanResult](t, res)

	if scan.Stats.RulesRun != 2 {
		t.Errorf("rules run = %d, want 2 (anti-RE only)", scan.Stats.RulesRun)
	}
	got := map[string]bool{}
	for _, f := range scan.Findings {
		got[f.RuleID] = true
		if strings.HasPrefix(f.RuleID, "VGL-SEC-") {
			t.Errorf("non-anti-RE rule %q ran", f.RuleID)
		}
	}
	if !got["VGL-ARE-003"] || !got["VGL-ARE-030"] {
		t.Errorf("findings = %v, want VGL-ARE-003 and VGL-ARE-030", got)
	}

	text := textOf(t, res)
	for _, want := range []string{"Android (1)", "Electron (1)", "hardening gaps", "not vulnerabilities"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "VGL-SEC-999") {
		t.Errorf("text mentions the disabled rule:\n%s", text)
	}
}

func TestE2EHardeningSeverityFilter(t *testing.T) {
	h := newHarness(t)

	reg := rules.NewRegistry()
	reg.Add(rules.New(model.RuleMeta{
		ID:       "VGL-ARE-003",
		Title:    "Debuggable release manifest",
		Severity: model.SeverityHigh,
		Category: model.CategoryAntiRE,
	}, func(f *rules.File) []model.Finding {
		return []model.Finding{{Location: model.Location{Path: f.Path, StartLine: 1}}}
	}))
	h.app.Registry = reg
	h.app.Scanner = scanner.New(reg, nil)

	writeRepoFile(t, h.repo, "AndroidManifest.xml", `<manifest/>`)

	res := h.client.mustTool("vigil_hardening", map[string]any{"minSeverity": "critical", "noBaseline": true})
	scan := structuredInto[model.ScanResult](t, res)
	if len(scan.Findings) != 0 {
		t.Fatalf("findings = %+v, want none at critical", scan.Findings)
	}
	if !strings.Contains(textOf(t, res), "No hardening gaps found") {
		t.Errorf("text does not report a clean scope:\n%s", textOf(t, res))
	}

	bad := h.client.tool("vigil_hardening", map[string]any{"minSeverity": "severe"})
	if !bad.IsError || !strings.Contains(textOf(t, bad), "not a severity") {
		t.Errorf("invalid minSeverity was not rejected: %s", textOf(t, bad))
	}
}

func TestE2EHardeningRealRegistrySelection(t *testing.T) {
	h := newHarness(t)

	want := 0
	for _, m := range h.app.Registry.Metas() {
		if m.Category == model.CategoryAntiRE {
			want++
		}
	}
	if want == 0 {
		t.Fatal("the production registry has no anti-re rules")
	}

	res := h.client.mustTool("vigil_hardening", map[string]any{"noBaseline": true})
	scan := structuredInto[model.ScanResult](t, res)
	if scan.Stats.RulesRun != want {
		t.Errorf("rules run = %d, want %d anti-re rules", scan.Stats.RulesRun, want)
	}
	for _, f := range scan.Findings {
		if !strings.HasPrefix(f.RuleID, "VGL-ARE-") {
			t.Errorf("non-anti-RE finding %q in the hardening result", f.RuleID)
		}
	}
}

func TestE2EPromptsAntiREAndDependencies(t *testing.T) {
	h := newHarness(t)

	resp := h.client.call("prompts/list", nil)
	if resp.Error != nil {
		t.Fatalf("prompts/list: %v", resp.Error)
	}
	var list mcp.PromptsListResult
	if err := json.Unmarshal(resp.Result, &list); err != nil {
		t.Fatalf("decode prompts/list: %v", err)
	}
	names := map[string]bool{}
	for _, p := range list.Prompts {
		names[p.Name] = true
	}
	for _, want := range []string{"anti_re_hardening", "dependency_audit"} {
		if !names[want] {
			t.Errorf("prompt %q is not registered", want)
		}
	}

	wantText := map[string]string{
		"anti_re_hardening": "vigil_hardening",
		"dependency_audit":  "vigil_dependencies",
	}
	for name, tool := range wantText {
		got := h.client.call("prompts/get", map[string]any{
			"name":      name,
			"arguments": map[string]string{"path": "."},
		})
		if got.Error != nil {
			t.Fatalf("prompts/get %s: %v", name, got.Error)
		}
		var prompt mcp.GetPromptResult
		if err := json.Unmarshal(got.Result, &prompt); err != nil {
			t.Fatalf("decode prompts/get %s: %v", name, err)
		}
		if len(prompt.Messages) != 1 || prompt.Messages[0].Content.Type != "text" {
			t.Fatalf("prompt %s messages = %+v", name, prompt.Messages)
		}
		text := prompt.Messages[0].Content.Text
		if !strings.Contains(text, tool) {
			t.Errorf("prompt %s does not mention %s:\n%s", name, tool, text)
		}
		if len(text) > 8<<10 {
			t.Errorf("prompt %s is %d bytes, want a bounded prompt", name, len(text))
		}
	}

	// dependency_audit must not promise zero-day detection and must state the
	// no-advisory limitation.
	got := h.client.call("prompts/get", map[string]any{"name": "dependency_audit"})
	var prompt mcp.GetPromptResult
	if err := json.Unmarshal(got.Result, &prompt); err != nil {
		t.Fatalf("decode dependency_audit: %v", err)
	}
	text := prompt.Messages[0].Content.Text
	for _, want := range []string{"not proof of safety", "Never claim zero-day detection", "unsupported"} {
		if !strings.Contains(text, want) {
			t.Errorf("dependency_audit missing %q:\n%s", want, text)
		}
	}
}

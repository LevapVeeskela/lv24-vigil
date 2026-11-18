package tools_test

import (
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/tools"
)

// newOfflineClient builds a second App over the harness repository with the
// same construction-time offline option the MCP server uses, and a client whose
// Deps carries the offline flag.
func newOfflineClient(t *testing.T, h *harness) (*app.App, *rpcClient) {
	t.Helper()
	a, err := app.New(h.repo, nil, app.WithOffline())
	if err != nil {
		t.Fatalf("app.New offline: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, newModeClient(t, a, false, true)
}

// TestOfflineDependenciesRefusesWithoutScan proves the OSV tool returns a typed
// refusal before it resolves a path or reads a manifest, even when the caller
// supplies a reachable per-request endpoint.
func TestOfflineDependenciesRefusesWithoutScan(t *testing.T) {
	h := newHarness(t)
	writeRepoFile(t, h.repo, "package.json",
		`{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}`)
	srv, calls := fakeOSV(t)
	a, c := newOfflineClient(t, h)

	before, err := a.Store.List(0)
	if err != nil {
		t.Fatalf("list scans before: %v", err)
	}
	if len(before) != 0 {
		t.Fatalf("offline app already has %d scans", len(before))
	}

	res := callTool(t, c, "vigil_dependencies", map[string]any{"osvBaseUrl": srv.URL})
	if code := toolErrorCode(t, res); code != tools.CodeOffline {
		t.Fatalf("vigil_dependencies code = %q, want %q", code, tools.CodeOffline)
	}
	if text := textOf(t, res); !strings.Contains(text, tools.CodeOffline) {
		t.Errorf("refusal text does not carry %s: %q", tools.CodeOffline, text)
	}
	if *calls != 0 {
		t.Errorf("offline dependency audit made %d OSV request(s), want 0", *calls)
	}

	after, err := a.Store.List(0)
	if err != nil {
		t.Fatalf("list scans after: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("refused dependency audit created %d scan(s)", len(after))
	}
}

// TestOfflineScanIgnoresUseLLM proves the scan path stays deterministic: a
// requested model is ignored, no LLM call is recorded and the summary says so.
func TestOfflineScanIgnoresUseLLM(t *testing.T) {
	h := newHarness(t)
	_, c := newOfflineClient(t, h)

	res := callTool(t, c, "vigil_scan", map[string]any{"useLlm": true, "mode": "quick"})
	if res.IsError {
		t.Fatalf("offline vigil_scan failed: %s", textOf(t, res))
	}
	text := textOf(t, res)
	if !strings.Contains(text, "Model: not used (deterministic rules only)") {
		t.Errorf("summary does not report a deterministic run: %q", text)
	}
	if !strings.Contains(text, "useLlm was requested but no model is configured") {
		t.Errorf("summary does not report the ignored useLlm request: %q", text)
	}

	scan := structuredInto[model.ScanResult](t, res)
	if scan.Model != nil {
		t.Errorf("offline scan recorded model info: %+v", scan.Model)
	}
	if scan.Stats.LLMCalls != 0 {
		t.Errorf("offline scan reports %d LLM calls", scan.Stats.LLMCalls)
	}
	found := false
	for _, f := range scan.Findings {
		found = found || f.RuleID == "VGL-SEC-001"
	}
	if !found {
		t.Fatalf("offline scan did not run the deterministic rules: %+v", scan.Findings)
	}
}

type offlineStatusPayload struct {
	LLM      bool     `json:"llm"`
	Offline  bool     `json:"offline"`
	Network  string   `json:"network"`
	Warnings []string `json:"warnings"`
}

// TestOfflineStatusReportsNoNetwork proves vigil_status advertises the enforced
// posture rather than the requested flags.
func TestOfflineStatusReportsNoNetwork(t *testing.T) {
	h := newHarness(t)
	_, c := newOfflineClient(t, h)

	res := callTool(t, c, "vigil_status", map[string]any{})
	if res.IsError {
		t.Fatalf("vigil_status failed: %s", textOf(t, res))
	}
	status := structuredInto[offlineStatusPayload](t, res)
	if !status.Offline {
		t.Error("vigil_status does not report offline=true")
	}
	if status.Network != "none" {
		t.Errorf("network posture = %q, want none", status.Network)
	}
	if status.LLM {
		t.Error("vigil_status reports a configured model in offline mode")
	}
	offline := false
	for _, w := range status.Warnings {
		offline = offline || strings.Contains(w, "offline mode")
	}
	if !offline {
		t.Errorf("vigil_status warnings do not mention offline mode: %v", status.Warnings)
	}
}

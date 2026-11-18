package tools_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/tools"
)

// newModeClient starts a server with the enforcement flags set, so tests
// exercise the same path as `vigil mcp --read-only --offline`.
func newModeClient(t *testing.T, a *app.App, readOnly, offline bool) *rpcClient {
	t.Helper()
	srv := mcp.NewServer("vigil", "test", "Vigil")
	tools.Register(srv, tools.Deps{
		App:      a,
		Version:  "test",
		ReadOnly: readOnly,
		Offline:  offline,
	})
	if readOnly {
		srv.HideTools("vigil_fix")
	}
	return startServer(t, srv)
}

func callTool(t *testing.T, c *rpcClient, name string, args map[string]any) mcp.CallToolResult {
	t.Helper()
	resp := c.call("tools/call", map[string]any{"name": name, "arguments": args})
	if resp.Error != nil {
		t.Fatalf("tools/call %s: %v", name, resp.Error)
	}
	var res mcp.CallToolResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("decode tools/call %s: %v", name, err)
	}
	return res
}

// toolErrorCode returns structuredContent.error.code, failing when the result
// is not a typed error.
func toolErrorCode(t *testing.T, res mcp.CallToolResult) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("result is not an error: %+v", res.Content)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structuredContent: %v", err)
	}
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode structuredContent: %v", err)
	}
	if payload.Error.Code == "" {
		t.Fatalf("typed error has no code: %s", raw)
	}
	if payload.Error.Message == "" {
		t.Fatalf("typed error has no message: %s", raw)
	}
	return payload.Error.Code
}

func TestReadOnlyModeHidesAndRejectsWrites(t *testing.T) {
	h := newHarness(t)
	c := newModeClient(t, h.app, true, false)

	listResp := c.call("tools/list", nil)
	if listResp.Error != nil {
		t.Fatalf("tools/list: %v", listResp.Error)
	}
	var list mcp.ToolsListResult
	if err := json.Unmarshal(listResp.Result, &list); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	names := make(map[string]bool, len(list.Tools))
	for _, tool := range list.Tools {
		names[tool.Name] = true
	}
	if names["vigil_fix"] {
		t.Error("read-only tools/list still advertises vigil_fix")
	}
	if !names["vigil_scan"] || !names["vigil_baseline"] {
		t.Errorf("read-only tools/list dropped read tools: %v", names)
	}

	// Hiding is discovery only: a direct call must be rejected by the handler.
	res := callTool(t, c, "vigil_fix", map[string]any{"findingId": "VGL-ANY"})
	if code := toolErrorCode(t, res); code != tools.CodeReadOnly {
		t.Errorf("vigil_fix code = %q, want %q", code, tools.CodeReadOnly)
	}

	res = callTool(t, c, "vigil_baseline", map[string]any{"action": "add", "findingId": "VGL-ANY", "reason": "test"})
	if code := toolErrorCode(t, res); code != tools.CodeReadOnly {
		t.Errorf("baseline add code = %q, want %q", code, tools.CodeReadOnly)
	}

	res = callTool(t, c, "vigil_report", map[string]any{"path": "reports/vigil.md"})
	if code := toolErrorCode(t, res); code != tools.CodeReadOnly {
		t.Errorf("report path code = %q, want %q", code, tools.CodeReadOnly)
	}

	// Listing the baseline is still a read and must work.
	res = callTool(t, c, "vigil_baseline", map[string]any{"action": "list"})
	if res.IsError {
		t.Errorf("baseline list failed in read-only mode: %+v", res.Content)
	}

	res = callTool(t, c, "vigil_status", map[string]any{})
	if res.IsError {
		t.Fatalf("vigil_status failed: %+v", res.Content)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	var status struct {
		ReadOnly bool   `json:"readOnly"`
		Offline  bool   `json:"offline"`
		Network  string `json:"network"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !status.ReadOnly {
		t.Error("vigil_status does not report readOnly")
	}
	if status.Offline {
		t.Error("vigil_status reports offline in a read-only server")
	}
	if status.Network != "none" {
		t.Errorf("network posture = %q, want none with no model and OSV off", status.Network)
	}
}

func TestReadOnlyModeHidesFixPrompt(t *testing.T) {
	h := newHarness(t)
	c := newModeClient(t, h.app, true, false)

	resp := c.call("prompts/list", nil)
	if resp.Error != nil {
		t.Fatalf("prompts/list: %v", resp.Error)
	}
	var prompts mcp.PromptsListResult
	if err := json.Unmarshal(resp.Result, &prompts); err != nil {
		t.Fatalf("decode prompts/list: %v", err)
	}
	got := make(map[string]bool, len(prompts.Prompts))
	for _, p := range prompts.Prompts {
		got[p.Name] = true
	}
	if got["fix_finding"] {
		t.Error("read-only prompts/list still advertises fix_finding")
	}
	if !got["security_review"] {
		t.Error("read-only prompts/list dropped a read-only prompt")
	}
}

func TestFixPromptUsesBoundApproval(t *testing.T) {
	h := newHarness(t)
	resp := h.client.call("prompts/get", map[string]any{
		"name":      "fix_finding",
		"arguments": map[string]string{"findingId": "VGL-SEC-001"},
	})
	if resp.Error != nil {
		t.Fatalf("prompts/get fix_finding: %v", resp.Error)
	}
	var prompt mcp.GetPromptResult
	if err := json.Unmarshal(resp.Result, &prompt); err != nil {
		t.Fatalf("decode fix_finding prompt: %v", err)
	}
	body := prompt.Messages[0].Content.Text
	for _, want := range []string{`"mode": "propose"`, `"mode": "apply"`, "fixId", "diffSha256", "VGL-FILE-CHANGED"} {
		if !strings.Contains(body, want) {
			t.Errorf("fix_finding prompt missing %q:\n%s", want, body)
		}
	}
}

func TestDefaultModeKeepsMutatingTools(t *testing.T) {
	h := newHarness(t)
	c := newModeClient(t, h.app, false, false)

	listResp := c.call("tools/list", nil)
	if listResp.Error != nil {
		t.Fatalf("tools/list: %v", listResp.Error)
	}
	var list mcp.ToolsListResult
	if err := json.Unmarshal(listResp.Result, &list); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	found := false
	for _, tool := range list.Tools {
		if tool.Name == "vigil_fix" {
			found = true
		}
	}
	if !found {
		t.Error("default tools/list is missing vigil_fix")
	}
}

func TestOfflineModeReportsPostureAndRejectsFix(t *testing.T) {
	h := newHarness(t)
	c := newModeClient(t, h.app, false, true)

	res := callTool(t, c, "vigil_status", map[string]any{})
	if res.IsError {
		t.Fatalf("vigil_status failed: %+v", res.Content)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	var status struct {
		Offline bool   `json:"offline"`
		Network string `json:"network"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !status.Offline || status.Network != "none" {
		t.Errorf("offline status = %+v, want offline=true network=none", status)
	}

	res = callTool(t, c, "vigil_fix", map[string]any{"findingId": "VGL-ANY"})
	if code := toolErrorCode(t, res); code != tools.CodeOffline {
		t.Errorf("vigil_fix code = %q, want %q", code, tools.CodeOffline)
	}
}

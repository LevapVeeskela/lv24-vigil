package tools_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/store"
	"github.com/levapveeskela/lv24-vigil/internal/tools"
)

const (
	// awsKey triggers VGL-SEC-001 and is not a placeholder value.
	awsKey = "AKIAZ7Q2LMN4RSTUVWXY"
	// apiKeySentinel must never appear in any tool output.
	apiKeySentinel = "sk-test-sentinel-value-1234567890"
)

type harness struct {
	t      *testing.T
	app    *app.App
	repo   string
	client *rpcClient
}

// newHarness builds a hermetic app on a temp repository. Host keys and config
// are neutralised with t.Setenv so the developer's real setup never leaks in.
func newHarness(t *testing.T) *harness {
	t.Helper()

	t.Setenv("VIGIL_NO_LLM", "1")
	t.Setenv("VIGIL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("VIGIL_API_KEY", apiKeySentinel)
	for _, env := range []string{
		"VIGIL_PROVIDER", "VIGIL_MODEL", "VIGIL_BASE_URL", "VIGIL_USE_LLM",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
		"OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY",
		"XAI_API_KEY", "OLLAMA_HOST",
	} {
		t.Setenv(env, "")
	}

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".vigil"), 0o755); err != nil {
		t.Fatalf("create .vigil: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "config.py"),
		[]byte("aws_access_key_id = \""+awsKey+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config.py: %v", err)
	}

	a, err := app.New(repo, nil)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	h := &harness{t: t, app: a, repo: repo}
	h.client = newClient(t, a)
	return h
}

// newClient starts a fresh MCP server over in-memory pipes. Resources are
// snapshotted at registration, so tests that need vigil://scan/<id> start a
// client after the scan exists.
func newClient(t *testing.T, a *app.App) *rpcClient {
	t.Helper()
	srv := mcp.NewServer("vigil", "test", "Vigil")
	tools.Register(srv, tools.Deps{App: a, Version: "test"})
	return startServer(t, srv)
}

func startServer(t *testing.T, srv *mcp.Server) *rpcClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(context.Background(), inR, outW)
		_ = outW.Close()
	}()

	c := &rpcClient{t: t, in: inW, out: bufio.NewReader(outR), done: done}
	t.Cleanup(func() {
		_ = inW.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("mcp server did not stop")
		}
		_ = outR.Close()
	})
	return c
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *mcp.RPCError   `json:"error"`
}

type rpcClient struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Reader
	next int
	done chan error
}

func (c *rpcClient) call(method string, params any) rpcResponse {
	c.t.Helper()
	c.next++
	req := map[string]any{"jsonrpc": "2.0", "id": c.next, "method": method}
	if params != nil {
		req["params"] = params
	}
	c.send(req)

	for {
		line, err := c.readLine()
		if err != nil {
			c.t.Fatalf("read response for %s: %v", method, err)
		}
		var resp rpcResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			c.t.Fatalf("decode response %q: %v", string(line), err)
		}
		if len(resp.ID) == 0 {
			continue // server notification
		}
		var id int
		if err := json.Unmarshal(resp.ID, &id); err != nil || id != c.next {
			continue
		}
		return resp
	}
}

func (c *rpcClient) notify(method string, params any) {
	c.t.Helper()
	req := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		req["params"] = params
	}
	c.send(req)
}

func (c *rpcClient) send(v any) {
	c.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		c.t.Fatalf("encode request: %v", err)
	}
	if _, err := c.in.Write(append(data, '\n')); err != nil {
		c.t.Fatalf("write request: %v", err)
	}
}

type readOutcome struct {
	line []byte
	err  error
}

func (c *rpcClient) readLine() ([]byte, error) {
	ch := make(chan readOutcome, 1)
	go func() {
		line, err := c.out.ReadBytes('\n')
		ch <- readOutcome{line: line, err: err}
	}()
	select {
	case r := <-ch:
		return r.line, r.err
	case <-time.After(20 * time.Second):
		c.t.Fatalf("timed out waiting for an MCP response")
		return nil, io.EOF
	}
}

// tool calls a tool and fails the test on a transport-level error. Tool-level
// failures are returned in the result (IsError) for the caller to inspect.
func (c *rpcClient) tool(name string, args any) mcp.CallToolResult {
	c.t.Helper()
	params := map[string]any{"name": name}
	if args != nil {
		params["arguments"] = args
	}
	resp := c.call("tools/call", params)
	if resp.Error != nil {
		c.t.Fatalf("tools/call %s: %v", name, resp.Error)
	}
	var res mcp.CallToolResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		c.t.Fatalf("decode tools/call %s result: %v", name, err)
	}
	return res
}

func (c *rpcClient) mustTool(name string, args any) mcp.CallToolResult {
	c.t.Helper()
	res := c.tool(name, args)
	if res.IsError {
		c.t.Fatalf("%s returned an error: %s", name, textOf(c.t, res))
	}
	return res
}

func textOf(t *testing.T, res mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("tool result has no content")
	}
	return res.Content[0].Text
}

func structuredInto[T any](t *testing.T, res mcp.CallToolResult) T {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatalf("tool result has no structuredContent")
	}
	data, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("re-encode structuredContent: %v", err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode structuredContent: %v", err)
	}
	return out
}

func (h *harness) scan() model.ScanResult {
	h.t.Helper()
	res := h.client.mustTool("vigil_scan", map[string]any{"mode": "quick"})
	scan := structuredInto[model.ScanResult](h.t, res)
	if len(scan.Findings) == 0 {
		h.t.Fatalf("scan returned no findings for a hardcoded AWS key: %s", textOf(h.t, res))
	}
	return scan
}

type rulesPayload struct {
	Count int              `json:"count"`
	Total int              `json:"total"`
	Rules []model.RuleMeta `json:"rules"`
}

type baselineFinding struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type baselinePayload struct {
	Path         string            `json:"path"`
	Version      int               `json:"version"`
	Fingerprints []string          `json:"fingerprints"`
	Findings     []baselineFinding `json:"findings"`
}

type reportWritePayload struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	ScanID string `json:"scanId"`
}

type historyPayload struct {
	Count int             `json:"count"`
	Scans []store.Summary `json:"scans"`
}

type verifyPayload struct {
	Resolved     bool   `json:"resolved"`
	StillPresent bool   `json:"stillPresent"`
	MatchKind    string `json:"matchKind"`
}

func TestHandshakeAndToolList(t *testing.T) {
	h := newHarness(t)

	initResp := h.client.call("initialize", map[string]any{
		"protocolVersion": mcp.ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test-client", "version": "1.0"},
	})
	if initResp.Error != nil {
		t.Fatalf("initialize: %v", initResp.Error)
	}
	var init mcp.InitializeResult
	if err := json.Unmarshal(initResp.Result, &init); err != nil {
		t.Fatalf("decode initialize result: %v", err)
	}
	if init.ProtocolVersion != mcp.ProtocolVersion {
		t.Errorf("protocolVersion = %q, want %q", init.ProtocolVersion, mcp.ProtocolVersion)
	}
	if init.ServerInfo.Name != "vigil" {
		t.Errorf("serverInfo.name = %q, want vigil", init.ServerInfo.Name)
	}
	if init.ServerInfo.Version != "test" {
		t.Errorf("serverInfo.version = %q, want test", init.ServerInfo.Version)
	}
	h.client.notify("notifications/initialized", nil)

	listResp := h.client.call("tools/list", nil)
	if listResp.Error != nil {
		t.Fatalf("tools/list: %v", listResp.Error)
	}
	var list mcp.ToolsListResult
	if err := json.Unmarshal(listResp.Result, &list); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}

	want := map[string]bool{
		"vigil_scan":         true,
		"vigil_review":       true,
		"vigil_explain":      true,
		"vigil_fix":          true,
		"vigil_threat_model": true,
		"vigil_status":       true,
		"vigil_rules":        true,
		"vigil_baseline":     true,
		"vigil_report":       true,
		"vigil_verify":       true,
		"vigil_history":      true,
	}
	if len(list.Tools) != len(want) {
		t.Fatalf("tools/list returned %d tools, want %d", len(list.Tools), len(want))
	}
	order := tools.ToolNames()
	for i, tool := range list.Tools {
		if !want[tool.Name] {
			t.Errorf("unexpected tool %q", tool.Name)
		}
		if i < len(order) && tool.Name != order[i] {
			t.Errorf("tool %d = %q, want stable order %q", i, tool.Name, order[i])
		}
		if len(tool.InputSchema) == 0 || string(tool.InputSchema) == "null" {
			t.Errorf("tool %q has an empty inputSchema", tool.Name)
		}
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Errorf("tool %q schema is not JSON: %v", tool.Name, err)
			continue
		}
		if schema["type"] != "object" {
			t.Errorf("tool %q schema type = %v, want object", tool.Name, schema["type"])
		}
	}
}

func TestStatusRulesAndScan(t *testing.T) {
	h := newHarness(t)

	statusRes := h.client.mustTool("vigil_status", nil)
	statusText := textOf(t, statusRes)
	if strings.Contains(statusText, apiKeySentinel) {
		t.Fatalf("vigil_status leaked the API key")
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(statusText), &status); err != nil {
		t.Fatalf("vigil_status is not JSON: %v\n%s", err, statusText)
	}
	if status["root"] != h.repo {
		t.Errorf("status root = %v, want %s", status["root"], h.repo)
	}
	if status["llm"] != false {
		t.Errorf("status llm = %v, want false", status["llm"])
	}
	if status["apiKey"] != "configured" {
		t.Errorf("status apiKey = %v, want configured", status["apiKey"])
	}
	if rules, ok := status["rules"].(float64); !ok || rules < 1 {
		t.Errorf("status rules = %v, want >= 1", status["rules"])
	}

	rulesRes := h.client.mustTool("vigil_rules", map[string]any{"category": "secrets"})
	rulesText := textOf(t, rulesRes)
	if !strings.Contains(rulesText, "VGL-SEC-001") {
		t.Errorf("vigil_rules secrets table does not mention VGL-SEC-001:\n%s", rulesText)
	}
	rules := structuredInto[rulesPayload](t, rulesRes)
	if rules.Count == 0 || rules.Count > rules.Total {
		t.Errorf("rules count = %d, total = %d", rules.Count, rules.Total)
	}
	for _, r := range rules.Rules {
		if r.Category != model.CategorySecrets {
			t.Errorf("category filter leaked rule %s (%s)", r.ID, r.Category)
		}
	}

	noMatch := h.client.mustTool("vigil_rules", map[string]any{"query": "zzz-no-such-rule"})
	if !strings.Contains(textOf(t, noMatch), "No rules match") {
		t.Errorf("expected an empty rules message, got:\n%s", textOf(t, noMatch))
	}

	scanRes := h.client.mustTool("vigil_scan", map[string]any{"mode": "quick"})
	scan := structuredInto[model.ScanResult](t, scanRes)
	if len(scan.Findings) == 0 {
		t.Fatalf("scan returned no findings for a hardcoded AWS key")
	}
	if scan.Findings[0].RuleID != "VGL-SEC-001" {
		t.Errorf("first finding rule = %q, want VGL-SEC-001", scan.Findings[0].RuleID)
	}
	scanText := textOf(t, scanRes)
	if strings.Contains(scanText, awsKey) {
		t.Fatalf("vigil_scan text leaked the raw AWS key")
	}
	if !strings.Contains(scanText, "VGL-SEC-001") && !strings.Contains(scanText, "AWS access key") {
		t.Errorf("scan summary does not mention the finding:\n%s", scanText)
	}
	if strings.Contains(scanText, apiKeySentinel) {
		t.Fatalf("vigil_scan text leaked the API key")
	}
}

func TestFindingLookupExplainAndFix(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	id := scan.Findings[0].ID

	explainRes := h.client.mustTool("vigil_explain", map[string]any{"findingId": id})
	explainText := textOf(t, explainRes)
	for _, want := range []string{id, "Severity", "Remediation", "No model is configured"} {
		if !strings.Contains(explainText, want) {
			t.Errorf("vigil_explain text missing %q:\n%s", want, explainText)
		}
	}

	fixRes := h.client.tool("vigil_fix", map[string]any{"findingId": id})
	if !fixRes.IsError {
		t.Fatalf("vigil_fix without a model should be an error result")
	}
	if !strings.Contains(textOf(t, fixRes), "needs a model") {
		t.Errorf("vigil_fix error is not helpful: %s", textOf(t, fixRes))
	}

	miss := h.client.tool("vigil_explain", map[string]any{"findingId": "VGL-DOESNOTEXIST"})
	if !miss.IsError {
		t.Fatalf("explain with an unknown finding should fail")
	}
	missText := textOf(t, miss)
	if !strings.Contains(missText, "not found") || !strings.Contains(missText, "Available findings") {
		t.Errorf("finding lookup miss is not helpful: %s", missText)
	}

	missingArg := h.client.tool("vigil_explain", map[string]any{})
	if !missingArg.IsError || !strings.Contains(textOf(t, missingArg), "invalid arguments") {
		t.Errorf("missing findingId should be an invalid-arguments error: %s", textOf(t, missingArg))
	}

	badType := h.client.tool("vigil_scan", map[string]any{"mode": 5})
	if !badType.IsError || !strings.Contains(textOf(t, badType), "invalid arguments") {
		t.Errorf("bad argument type should be an invalid-arguments error: %s", textOf(t, badType))
	}

	unknown := h.client.call("tools/call", map[string]any{"name": "vigil_nope", "arguments": map[string]any{}})
	if unknown.Error == nil {
		t.Fatalf("unknown tool should be a JSON-RPC error")
	}
	if !strings.Contains(unknown.Error.Message, "unknown tool") {
		t.Errorf("unknown tool error = %q", unknown.Error.Message)
	}
}

func TestBaselineLifecycle(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	id := scan.Findings[0].ID

	noReason := h.client.tool("vigil_baseline", map[string]any{"action": "add", "findingId": id})
	if !noReason.IsError || !strings.Contains(textOf(t, noReason), "reason is required") {
		t.Fatalf("baseline add without a reason should fail: %s", textOf(t, noReason))
	}

	added := h.client.mustTool("vigil_baseline", map[string]any{
		"action":    "add",
		"findingId": id,
		"reason":    "test fixture: accepted for the MCP test",
	})
	if !strings.Contains(textOf(t, added), "Added "+id) {
		t.Errorf("baseline add text = %s", textOf(t, added))
	}

	listed := h.client.mustTool("vigil_baseline", map[string]any{"action": "list"})
	listText := textOf(t, listed)
	if !strings.Contains(listText, id) || !strings.Contains(listText, "accepted for the MCP test") {
		t.Errorf("baseline list does not show the entry:\n%s", listText)
	}
	baseline := structuredInto[baselinePayload](t, listed)
	if baseline.Version != 1 {
		t.Errorf("baseline version = %d, want 1", baseline.Version)
	}
	if len(baseline.Findings) != 1 || len(baseline.Fingerprints) != 1 {
		t.Errorf("baseline has %d findings and %d fingerprints, want 1 and 1", len(baseline.Findings), len(baseline.Fingerprints))
	}

	removed := h.client.mustTool("vigil_baseline", map[string]any{"action": "remove", "findingId": id})
	if !strings.Contains(textOf(t, removed), "Removed") {
		t.Errorf("baseline remove text = %s", textOf(t, removed))
	}
	afterRemove := h.client.mustTool("vigil_baseline", map[string]any{"action": "list"})
	if !strings.Contains(textOf(t, afterRemove), "The baseline is empty") {
		t.Errorf("baseline is not empty after remove:\n%s", textOf(t, afterRemove))
	}

	unknown := h.client.tool("vigil_baseline", map[string]any{"action": "remove", "findingId": "VGL-NOPE000000"})
	if !unknown.IsError || !strings.Contains(textOf(t, unknown), "not in the baseline") {
		t.Errorf("removing an absent finding should fail helpfully: %s", textOf(t, unknown))
	}

	h.client.mustTool("vigil_baseline", map[string]any{"action": "add", "findingId": id, "reason": "second pass"})
	cleared := h.client.mustTool("vigil_baseline", map[string]any{"action": "clear"})
	if !strings.Contains(textOf(t, cleared), "Cleared") {
		t.Errorf("baseline clear text = %s", textOf(t, cleared))
	}
	afterClear := h.client.mustTool("vigil_baseline", map[string]any{"action": "list"})
	if !strings.Contains(textOf(t, afterClear), "The baseline is empty") {
		t.Errorf("baseline is not empty after clear:\n%s", textOf(t, afterClear))
	}
}

func TestReportHistoryAndVerify(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()
	id := scan.Findings[0].ID

	md := h.client.mustTool("vigil_report", map[string]any{"format": "md"})
	if !strings.Contains(textOf(t, md), "# Vigil security report") {
		t.Errorf("markdown report missing its title:\n%s", textOf(t, md))
	}

	jsonReport := h.client.mustTool("vigil_report", map[string]any{"format": "json"})
	var envelope map[string]any
	if err := json.Unmarshal([]byte(textOf(t, jsonReport)), &envelope); err != nil {
		t.Fatalf("json report is not JSON: %v", err)
	}
	if envelope["schemaVersion"] != "1" {
		t.Errorf("json report schemaVersion = %v, want 1", envelope["schemaVersion"])
	}
	if envelope["id"] != scan.ID {
		t.Errorf("json report id = %v, want %s", envelope["id"], scan.ID)
	}

	written := h.client.mustTool("vigil_report", map[string]any{
		"format": "md",
		"path":   filepath.Join("reports", "vigil.md"),
	})
	if !strings.Contains(textOf(t, written), "Wrote") {
		t.Errorf("report write text = %s", textOf(t, written))
	}
	writePayload := structuredInto[reportWritePayload](t, written)
	if !filepath.IsAbs(writePayload.Path) {
		t.Errorf("report path = %q, want absolute", writePayload.Path)
	}
	if !strings.HasPrefix(writePayload.Path, h.repo) {
		t.Errorf("report path %q is outside the app root %q", writePayload.Path, h.repo)
	}
	data, err := os.ReadFile(writePayload.Path)
	if err != nil {
		t.Fatalf("read written report: %v", err)
	}
	if len(data) == 0 || len(data) != writePayload.Bytes {
		t.Errorf("written report has %d bytes, payload says %d", len(data), writePayload.Bytes)
	}

	for _, bad := range []string{"../escape.md", filepath.Join(h.repo, "absolute.md")} {
		res := h.client.tool("vigil_report", map[string]any{"format": "md", "path": bad})
		if !res.IsError {
			t.Errorf("report path %q should be rejected", bad)
		}
	}

	history := h.client.mustTool("vigil_history", map[string]any{"limit": 5})
	if !strings.Contains(textOf(t, history), scan.ID) {
		t.Errorf("vigil_history does not list %s:\n%s", scan.ID, textOf(t, history))
	}
	hist := structuredInto[historyPayload](t, history)
	if hist.Count < 1 || len(hist.Scans) < 1 || hist.Scans[0].ID == "" {
		t.Errorf("history payload is empty: %+v", hist)
	}

	verify := h.client.mustTool("vigil_verify", map[string]any{"findingId": id})
	vp := structuredInto[verifyPayload](t, verify)
	if vp.Resolved || !vp.StillPresent || vp.MatchKind != "fingerprint" {
		t.Errorf("verify before fix = %+v, want still present by fingerprint", vp)
	}

	clean := "import os\naws_access_key_id = os.environ[\"AWS_ACCESS_KEY_ID\"]\n"
	if err := os.WriteFile(filepath.Join(h.repo, "config.py"), []byte(clean), 0o644); err != nil {
		t.Fatalf("rewrite config.py: %v", err)
	}
	verifyAfter := h.client.mustTool("vigil_verify", map[string]any{"findingId": id})
	va := structuredInto[verifyPayload](t, verifyAfter)
	if !va.Resolved || va.StillPresent {
		t.Errorf("verify after fix = %+v, want resolved", va)
	}
}

func TestResourcesAndPrompts(t *testing.T) {
	h := newHarness(t)
	scan := h.scan()

	readResource := func(uri string) mcp.ResourcesReadResult {
		t.Helper()
		resp := h.client.call("resources/read", map[string]any{"uri": uri})
		if resp.Error != nil {
			t.Fatalf("resources/read %s: %v", uri, resp.Error)
		}
		var rr mcp.ResourcesReadResult
		if err := json.Unmarshal(resp.Result, &rr); err != nil {
			t.Fatalf("decode resources/read %s: %v", uri, err)
		}
		return rr
	}

	status := readResource("vigil://status")
	if len(status.Contents) != 1 || status.Contents[0].MimeType != "application/json" {
		t.Fatalf("vigil://status contents = %+v", status.Contents)
	}
	var statusBody map[string]any
	if err := json.Unmarshal([]byte(status.Contents[0].Text), &statusBody); err != nil {
		t.Fatalf("vigil://status is not JSON: %v", err)
	}
	if statusBody["root"] != h.repo {
		t.Errorf("vigil://status root = %v, want %s", statusBody["root"], h.repo)
	}

	rules := readResource("vigil://rules")
	if len(rules.Contents) != 1 {
		t.Fatalf("vigil://rules contents = %+v", rules.Contents)
	}
	var rulesBody struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(rules.Contents[0].Text), &rulesBody); err != nil {
		t.Fatalf("vigil://rules is not JSON: %v", err)
	}
	if rulesBody.Count < 1 {
		t.Errorf("vigil://rules count = %d", rulesBody.Count)
	}

	last := readResource("vigil://scan/last")
	var lastScan model.ScanResult
	if err := json.Unmarshal([]byte(last.Contents[0].Text), &lastScan); err != nil {
		t.Fatalf("vigil://scan/last is not JSON: %v", err)
	}
	if lastScan.ID != scan.ID {
		t.Errorf("vigil://scan/last id = %s, want %s", lastScan.ID, scan.ID)
	}

	// A scan created after the first server started is exposed by a server
	// that registers after the scan exists.
	fresh := newClient(t, h.app)
	resp := fresh.call("resources/read", map[string]any{"uri": "vigil://scan/" + scan.ID})
	if resp.Error != nil {
		t.Fatalf("vigil://scan/%s: %v", scan.ID, resp.Error)
	}
	var byID mcp.ResourcesReadResult
	if err := json.Unmarshal(resp.Result, &byID); err != nil {
		t.Fatalf("decode vigil://scan/%s: %v", scan.ID, err)
	}
	var byIDScan model.ScanResult
	if err := json.Unmarshal([]byte(byID.Contents[0].Text), &byIDScan); err != nil {
		t.Fatalf("vigil://scan/%s is not JSON: %v", scan.ID, err)
	}
	if byIDScan.ID != scan.ID {
		t.Errorf("vigil://scan/%s id = %s", scan.ID, byIDScan.ID)
	}

	// A registered scan that disappears must produce a clear resource error,
	// not an empty document.
	if err := os.Remove(filepath.Join(h.app.Store.Dir(), scan.ID+".json")); err != nil {
		t.Fatalf("remove stored scan: %v", err)
	}
	gone := fresh.call("resources/read", map[string]any{"uri": "vigil://scan/" + scan.ID})
	if gone.Error == nil {
		t.Errorf("reading a missing scan should fail")
	} else if !strings.Contains(gone.Error.Message, "unknown scan") {
		t.Errorf("missing scan error = %q, want it to mention the unknown scan", gone.Error.Message)
	}

	promptsResp := h.client.call("prompts/list", nil)
	if promptsResp.Error != nil {
		t.Fatalf("prompts/list: %v", promptsResp.Error)
	}
	var prompts mcp.PromptsListResult
	if err := json.Unmarshal(promptsResp.Result, &prompts); err != nil {
		t.Fatalf("decode prompts/list: %v", err)
	}
	gotPrompts := map[string]bool{}
	for _, p := range prompts.Prompts {
		gotPrompts[p.Name] = true
	}
	for _, want := range []string{"security_review", "threat_model", "fix_finding"} {
		if !gotPrompts[want] {
			t.Errorf("prompt %q is not registered", want)
		}
	}

	promptResp := h.client.call("prompts/get", map[string]any{
		"name":      "security_review",
		"arguments": map[string]string{"path": h.repo},
	})
	if promptResp.Error != nil {
		t.Fatalf("prompts/get security_review: %v", promptResp.Error)
	}
	var prompt mcp.GetPromptResult
	if err := json.Unmarshal(promptResp.Result, &prompt); err != nil {
		t.Fatalf("decode security_review prompt: %v", err)
	}
	if len(prompt.Messages) != 1 || prompt.Messages[0].Content.Type != "text" {
		t.Fatalf("security_review messages = %+v", prompt.Messages)
	}
	body := prompt.Messages[0].Content.Text
	for _, want := range []string{"vigil_scan", "untrusted", "Severity policy", h.repo} {
		if !strings.Contains(body, want) {
			t.Errorf("security_review prompt missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, apiKeySentinel) {
		t.Errorf("security_review prompt leaked the API key")
	}

	missing := h.client.call("prompts/get", map[string]any{"name": "fix_finding", "arguments": map[string]string{}})
	if missing.Error == nil {
		t.Fatalf("fix_finding without findingId should fail")
	}
}

func TestReviewDiff(t *testing.T) {
	h := newHarness(t)

	diff := "--- a/example.py\n+++ b/example.py\n@@ -0,0 +1,2 @@\n" +
		"+aws_access_key_id = \"" + awsKey + "\"\n+x = 1\n"
	res := h.client.mustTool("vigil_review", map[string]any{"diff": diff})
	scan := structuredInto[model.ScanResult](t, res)
	if scan.Mode != "quick" {
		t.Errorf("review mode = %q, want quick", scan.Mode)
	}
	if len(scan.Findings) == 0 {
		t.Fatalf("review of a diff with a hardcoded key returned no findings")
	}
	if scan.Findings[0].Location.Path != "example.py" {
		t.Errorf("review finding path = %q, want example.py", scan.Findings[0].Location.Path)
	}
	if !strings.Contains(textOf(t, res), "changed lines") {
		t.Errorf("review summary does not describe the diff scope:\n%s", textOf(t, res))
	}
}

func TestThreatModelRequiresModel(t *testing.T) {
	h := newHarness(t)

	res := h.client.tool("vigil_threat_model", nil)
	if !res.IsError {
		t.Fatalf("vigil_threat_model without a model should be an error result")
	}
	if !strings.Contains(textOf(t, res), "needs a model") {
		t.Errorf("threat model error is not helpful: %s", textOf(t, res))
	}
}

func TestTextResponsesAreBounded(t *testing.T) {
	h := newHarness(t)

	// Many independent keys make a markdown report larger than the 40 KiB cap.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString("aws_access_key_id = \"AKIA")
		for j := 0; j < 16; j++ {
			b.WriteByte(alphabet[(i*7+j*11)%len(alphabet)])
		}
		b.WriteString("\"\n")
	}
	if err := os.WriteFile(filepath.Join(h.repo, "many.py"), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write many.py: %v", err)
	}

	scanRes := h.client.mustTool("vigil_scan", map[string]any{"mode": "quick", "maxFindings": 500})
	scan := structuredInto[model.ScanResult](t, scanRes)
	if len(scan.Findings) < 100 {
		t.Fatalf("expected many findings, got %d", len(scan.Findings))
	}

	reportRes := h.client.mustTool("vigil_report", map[string]any{"format": "md"})
	text := textOf(t, reportRes)
	if len(text) > 41*1024 {
		t.Errorf("report text is %d bytes, want <= ~40 KiB", len(text))
	}
	if !strings.Contains(text, "truncated") {
		t.Errorf("expected a truncation note in a large response")
	}
}

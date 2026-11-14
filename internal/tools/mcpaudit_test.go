package tools_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// mcpAuditConfig has an unpinned npx package (VGL-MCP-001) and a literal token
// (VGL-MCP-002).
const mcpAuditConfig = `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/work"],
      "env": {"GITHUB_TOKEN": "ghp_7Qm2Lx9Rt4Vw8Yz3Nc6Bd1Fg5Hj0Kl2Pq"}
    }
  }
}
`

func writeMCPAuditConfig(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestMCPAuditToolFindsMCPRules(t *testing.T) {
	h := newHarness(t)
	writeMCPAuditConfig(t, h.repo, ".mcp.json", mcpAuditConfig)

	res := h.client.mustTool("vigil_mcp_audit", map[string]any{"path": "."})
	text := textOf(t, res)
	for _, want := range []string{"Vigil MCP configuration audit", "VGL-MCP-001", "VGL-MCP-002", "No configured server is started"} {
		if !strings.Contains(text, want) {
			t.Errorf("vigil_mcp_audit text missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ghp_7Qm2Lx9Rt4Vw8Yz3Nc6Bd1Fg5Hj0Kl2Pq") {
		t.Error("vigil_mcp_audit leaked the literal secret")
	}

	audit := structuredInto[model.ScanResult](t, res)
	if audit.Mode != "mcp-audit" {
		t.Errorf("mode = %q, want mcp-audit", audit.Mode)
	}
	if audit.Stats.RulesRun != 10 {
		t.Errorf("rulesRun = %d, want 10 VGL-MCP rules", audit.Stats.RulesRun)
	}
	if len(audit.Findings) == 0 {
		t.Fatal("vigil_mcp_audit returned no findings for a config with two known issues")
	}
	for _, f := range audit.Findings {
		if !strings.HasPrefix(f.RuleID, "VGL-MCP-") {
			t.Errorf("vigil_mcp_audit returned a non-MCP rule %q", f.RuleID)
		}
	}
}

func TestMCPAuditToolMinSeverity(t *testing.T) {
	h := newHarness(t)
	writeMCPAuditConfig(t, h.repo, ".mcp.json", mcpAuditConfig)

	res := h.client.mustTool("vigil_mcp_audit", map[string]any{"minSeverity": "critical"})
	audit := structuredInto[model.ScanResult](t, res)
	if len(audit.Findings) == 0 {
		t.Fatal("no critical finding reported")
	}
	for _, f := range audit.Findings {
		if f.Severity != model.SeverityCritical {
			t.Errorf("minSeverity=critical returned a %s finding", f.Severity)
		}
	}
}

func TestMCPAuditToolIncludeUser(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	writeMCPAuditConfig(t, home, "claude_desktop_config.json", mcpAuditConfig)

	h := newHarness(t)
	res := h.client.mustTool("vigil_mcp_audit", map[string]any{"includeUser": true})
	audit := structuredInto[model.ScanResult](t, res)
	if len(audit.Findings) == 0 {
		t.Fatal("includeUser did not read the home config")
	}
	for _, f := range audit.Findings {
		if !strings.HasPrefix(f.Location.Path, "~/") {
			t.Errorf("user config finding path = %q, want ~/-relative", f.Location.Path)
		}
	}
}

// mcpAuditCompactConfig keeps an unpinned package, a filesystem root and a
// literal credential on one line.
const mcpAuditCompactConfig = `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"],"env":{"API_KEY":"9f8e7d6c5b4a39281706f5e4d3c2b1a0"}}}}`

const mcpAuditCompactSecret = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"

func TestMCPAuditToolRedactsCompactConfigSecret(t *testing.T) {
	h := newHarness(t)
	writeMCPAuditConfig(t, h.repo, ".mcp.json", mcpAuditCompactConfig)

	res := h.client.mustTool("vigil_mcp_audit", map[string]any{"path": "."})
	text := textOf(t, res)
	if strings.Contains(text, mcpAuditCompactSecret) {
		t.Errorf("vigil_mcp_audit text leaked the literal credential:\n%s", text)
	}
	if data, err := json.Marshal(res); err != nil {
		t.Fatalf("marshal tool result: %v", err)
	} else if strings.Contains(string(data), mcpAuditCompactSecret) {
		t.Errorf("serialized tool result leaked the literal credential:\n%s", data)
	}

	audit := structuredInto[model.ScanResult](t, res)
	if audit.Stats.FilesScanned != 1 {
		t.Errorf("filesScanned = %d, want 1", audit.Stats.FilesScanned)
	}
	found := map[string]bool{}
	for _, f := range audit.Findings {
		found[f.RuleID] = true
		if strings.Contains(f.Location.Snippet, mcpAuditCompactSecret) {
			t.Errorf("%s structuredContent snippet leaked the literal credential: %q", f.RuleID, f.Location.Snippet)
		}
		if strings.Contains(f.Evidence, mcpAuditCompactSecret) {
			t.Errorf("%s structuredContent evidence leaked the literal credential: %q", f.RuleID, f.Evidence)
		}
	}
	for _, want := range []string{"VGL-MCP-001", "VGL-MCP-002", "VGL-MCP-005"} {
		if !found[want] {
			t.Errorf("vigil_mcp_audit did not report %s on the compact config (reported %v)", want, found)
		}
	}
}

// mcpAuditAuthHeaderConfig holds a bearer token in a headers map on one line,
// next to an unpinned command and a cleartext endpoint.
const mcpAuditAuthHeaderConfig = `{"mcpServers":{"remote":{"command":"npx -y @acme/remote-mcp","url":"http://mcp.example.com/sse","headers":{"Authorization":"Bearer ` + mcpAuditAuthToken + `"}}}}`

const mcpAuditAuthToken = "8Qm2Lx9Vb4Tz1Kp7Yr3Nd6Ws0Qh5Jc2Fa8Ue"

func TestMCPAuditToolRedactsAuthorizationHeader(t *testing.T) {
	h := newHarness(t)
	writeMCPAuditConfig(t, h.repo, ".mcp.json", mcpAuditAuthHeaderConfig)

	res := h.client.mustTool("vigil_mcp_audit", map[string]any{"path": "."})
	text := textOf(t, res)
	if strings.Contains(text, mcpAuditAuthToken) {
		t.Errorf("vigil_mcp_audit text leaked the bearer token:\n%s", text)
	}
	if data, err := json.Marshal(res); err != nil {
		t.Fatalf("marshal tool result: %v", err)
	} else if strings.Contains(string(data), mcpAuditAuthToken) {
		t.Errorf("serialized tool result leaked the bearer token:\n%s", data)
	}

	audit := structuredInto[model.ScanResult](t, res)
	found := map[string]bool{}
	for _, f := range audit.Findings {
		found[f.RuleID] = true
		if strings.Contains(f.Location.Snippet, mcpAuditAuthToken) {
			t.Errorf("%s structuredContent snippet leaked the bearer token: %q", f.RuleID, f.Location.Snippet)
		}
		if strings.Contains(f.Evidence, mcpAuditAuthToken) {
			t.Errorf("%s structuredContent evidence leaked the bearer token: %q", f.RuleID, f.Evidence)
		}
	}
	for _, want := range []string{"VGL-MCP-001", "VGL-MCP-004"} {
		if !found[want] {
			t.Errorf("vigil_mcp_audit did not report %s on the auth-header config (reported %v)", want, found)
		}
	}
}

func TestMCPAuditToolCountsInspectedConfigs(t *testing.T) {
	h := newHarness(t)
	writeMCPAuditConfig(t, h.repo, ".mcp.json", mcpAuditConfig)
	// Discovered by name, refused by the rules: skipped, not scanned.
	writeMCPAuditConfig(t, h.repo, "docs/.mcp.json", mcpAuditConfig)

	res := h.client.mustTool("vigil_mcp_audit", map[string]any{"path": "."})
	audit := structuredInto[model.ScanResult](t, res)
	if audit.Stats.FilesScanned != 1 {
		t.Errorf("filesScanned = %d, want 1", audit.Stats.FilesScanned)
	}
	if audit.Stats.FilesSkipped != 1 {
		t.Errorf("filesSkipped = %d, want 1", audit.Stats.FilesSkipped)
	}
	if text := textOf(t, res); !strings.Contains(text, "Config files skipped: 1") {
		t.Errorf("summary does not report the skipped config:\n%s", text)
	}
}

func TestMCPAuditToolConfinesPathToRoot(t *testing.T) {
	h := newHarness(t)
	res := h.client.tool("vigil_mcp_audit", map[string]any{"path": ".."})
	if !res.IsError {
		t.Fatalf("path outside the project root was accepted: %s", textOf(t, res))
	}
	if !strings.Contains(textOf(t, res), "outside the project root") {
		t.Errorf("unexpected confinement error: %s", textOf(t, res))
	}
}

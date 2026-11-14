package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testMCPConfig is a project MCP config with two findings: an unpinned npx
// package (VGL-MCP-001) and a literal token in env (VGL-MCP-002).
const testMCPConfig = `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/work"],
      "env": {"GITHUB_TOKEN": "ghp_7Qm2Lx9Rt4Vw8Yz3Nc6Bd1Fg5Hj0Kl2Pq"}
    }
  }
}
`

func writeMCPConfig(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestMCPAuditJSONFindsOnlyMCPRules(t *testing.T) {
	dir := t.TempDir()
	writeMCPConfig(t, dir, ".mcp.json", testMCPConfig)
	writeMCPConfig(t, dir, "config.go", "package config\n")

	out, stderr, err := runCLI(t, "mcp-audit", dir, "--format", "json")
	if err != nil {
		t.Fatalf("mcp-audit: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if res.Mode != "mcp-audit" {
		t.Errorf("mode = %q, want mcp-audit", res.Mode)
	}
	if res.Stats.FilesScanned != 1 {
		t.Errorf("filesScanned = %d, want 1", res.Stats.FilesScanned)
	}
	if !findRule(res, "VGL-MCP-001") || !findRule(res, "VGL-MCP-002") {
		t.Fatalf("mcp-audit did not report the expected rules: %s", out)
	}
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.RuleID, "VGL-MCP-") {
			t.Errorf("mcp-audit reported a non-MCP rule: %s", f.RuleID)
		}
	}
	if strings.Contains(out, "ghp_7Qm2Lx9Rt4Vw8Yz3Nc6Bd1Fg5Hj0Kl2Pq") {
		t.Error("mcp-audit leaked the literal secret")
	}
}

func TestMCPAuditFailOnAndMaxFindings(t *testing.T) {
	dir := t.TempDir()
	writeMCPConfig(t, dir, ".mcp.json", testMCPConfig)

	_, _, err := runCLI(t, "mcp-audit", dir, "--format", "json", "--fail-on", "critical")
	if !errors.Is(err, ErrFindings) {
		t.Fatalf("err = %v, want ErrFindings", err)
	}

	out, stderr, err := runCLI(t, "mcp-audit", dir, "--format", "json", "--max-findings", "1")
	if err != nil {
		t.Fatalf("mcp-audit --max-findings: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1\n%s", len(res.Findings), out)
	}

	if _, _, err := runCLI(t, "mcp-audit", dir, "--fail-on", "urgent"); err == nil {
		t.Error("an invalid --fail-on value was accepted")
	}
	if _, _, err := runCLI(t, "mcp-audit", dir, "--max-findings", "-1"); err == nil {
		t.Error("a negative --max-findings value was accepted")
	}
}

func TestMCPAuditSARIFOutputFile(t *testing.T) {
	dir := t.TempDir()
	writeMCPConfig(t, dir, ".mcp.json", testMCPConfig)
	reportPath := filepath.Join(dir, "mcp-audit.sarif")

	out, stderr, err := runCLI(t, "mcp-audit", dir, "--format", "sarif", "--output", reportPath)
	if err != nil {
		t.Fatalf("mcp-audit: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(out, "wrote "+reportPath) {
		t.Errorf("missing output confirmation: %s", out)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("sarif is not valid JSON: %v\n%s", err, data)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) == 0 || len(sarif.Runs[0].Results) == 0 {
		t.Fatalf("sarif has no results: %s", data)
	}
	for _, r := range sarif.Runs[0].Results {
		if !strings.HasPrefix(r.RuleID, "VGL-MCP-") {
			t.Errorf("sarif reported a non-MCP rule: %s", r.RuleID)
		}
	}
}

func TestMCPAuditUserConfigsStayInKnownHomePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	writeMCPConfig(t, home, "claude_desktop_config.json", testMCPConfig)
	dir := t.TempDir()

	out, stderr, err := runCLI(t, "mcp-audit", dir, "--user", "--format", "json")
	if err != nil {
		t.Fatalf("mcp-audit --user: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	if !findRule(res, "VGL-MCP-001") {
		t.Fatalf("--user did not read the home config: %s", out)
	}
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.Location.Path, "~/") {
			t.Errorf("user config finding path = %q, want ~/-relative", f.Location.Path)
		}
	}
	if strings.Contains(out, filepath.ToSlash(home)) {
		t.Errorf("mcp-audit leaked the absolute home path: %s", out)
	}

	// Without --user the project scan must not read user configs.
	out, stderr, err = runCLI(t, "mcp-audit", dir, "--format", "json")
	if err != nil {
		t.Fatalf("mcp-audit: %v\nstderr:\n%s", err, stderr)
	}
	if res := decodeScan(t, out); len(res.Findings) != 0 {
		t.Fatalf("project-only audit read user configs: %s", out)
	}
}

// compactMCPConfig keeps an unpinned package, a filesystem root and a literal
// credential on a single line, the shape that used to leak the value verbatim
// into snippets and evidence.
const compactMCPConfig = `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"],"env":{"API_KEY":"9f8e7d6c5b4a39281706f5e4d3c2b1a0"}}}}`

const compactMCPSecret = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"

func TestMCPAuditRedactsCompactConfigSecret(t *testing.T) {
	dir := t.TempDir()
	writeMCPConfig(t, dir, ".mcp.json", compactMCPConfig)

	for _, format := range []string{"json", "sarif", "md"} {
		out, stderr, err := runCLI(t, "mcp-audit", dir, "--format", format)
		if err != nil {
			t.Fatalf("mcp-audit --format %s: %v\nstderr:\n%s", format, err, stderr)
		}
		if strings.Contains(out, compactMCPSecret) {
			t.Errorf("%s output leaked the literal credential:\n%s", format, out)
		}
	}

	out, stderr, err := runCLI(t, "mcp-audit", dir, "--format", "json")
	if err != nil {
		t.Fatalf("mcp-audit: %v\nstderr:\n%s", err, stderr)
	}
	res := decodeScan(t, out)
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, compactMCPSecret) {
			t.Errorf("%s evidence leaked the literal credential: %q", f.RuleID, f.Evidence)
		}
	}
	for _, want := range []string{"VGL-MCP-001", "VGL-MCP-002", "VGL-MCP-005"} {
		if !findRule(res, want) {
			t.Errorf("mcp-audit did not report %s on the compact config:\n%s", want, out)
		}
	}
}

func TestMCPAuditCountsOnlyInspectedConfigs(t *testing.T) {
	dir := t.TempDir()
	writeMCPConfig(t, dir, ".mcp.json", testMCPConfig)
	// Discovered by name but refused by the rules: it must be skipped, not
	// reported as a scanned file with zero findings.
	writeMCPConfig(t, dir, "docs/.mcp.json", testMCPConfig)

	out, stderr, err := runCLI(t, "mcp-audit", dir, "--format", "json")
	if err != nil {
		t.Fatalf("mcp-audit: %v\nstderr:\n%s", err, stderr)
	}
	var stats struct {
		Stats struct {
			FilesScanned int `json:"filesScanned"`
			FilesSkipped int `json:"filesSkipped"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &stats); err != nil {
		t.Fatalf("stdout is not valid scan JSON: %v\n%s", err, out)
	}
	if stats.Stats.FilesScanned != 1 {
		t.Errorf("filesScanned = %d, want 1 (docs configs are not inspected)", stats.Stats.FilesScanned)
	}
	if stats.Stats.FilesSkipped != 1 {
		t.Errorf("filesSkipped = %d, want 1", stats.Stats.FilesSkipped)
	}
	res := decodeScan(t, out)
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Location.Path, "docs/") {
			t.Errorf("mcp-audit reported a finding from a skipped docs config: %s", f.Location.Path)
		}
	}
}

func TestMCPAuditHelp(t *testing.T) {
	out, _, err := runCLI(t, "mcp-audit", "--help")
	if err != nil {
		t.Fatalf("mcp-audit --help: %v", err)
	}
	for _, want := range []string{"Usage: vigil mcp-audit", "--user", "--format md|json|sarif", "--fail-on"} {
		if !strings.Contains(out, want) {
			t.Errorf("mcp-audit help missing %q:\n%s", want, out)
		}
	}

	help, _, err := runCLI(t, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, want := range []string{"vigil mcp-audit", "vigil sbom"} {
		if !strings.Contains(help, want) {
			t.Errorf("main help missing %q:\n%s", want, help)
		}
	}
}

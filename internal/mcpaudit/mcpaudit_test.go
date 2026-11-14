package mcpaudit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// makeDirLink creates a directory link. Windows file symlinks need a privilege
// the test runner usually does not have, but junctions do not.
func makeDirLink(t *testing.T, link, target string) error {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("symlink is not available")
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeConfig(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func relSet(t *testing.T, root string, paths []string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatalf("rel %s: %v", p, err)
		}
		out[filepath.ToSlash(rel)] = true
	}
	return out
}

func TestDiscoverFindsMCPConfigs(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, ".mcp.json", "{}")
	writeConfig(t, root, ".vscode/mcp.json", "{}")
	writeConfig(t, root, "nested/mcp-config.json", "{}")
	writeConfig(t, root, "claude_desktop_config.json", "{}")
	writeConfig(t, root, "opencode.json", "{}")
	writeConfig(t, root, "opencode.jsonc", "{}")
	writeConfig(t, root, "agents/pkg.mcp.json", "{}")
	writeConfig(t, root, "package.json", "{}")
	writeConfig(t, root, "node_modules/dep/.mcp.json", "{}")
	writeConfig(t, root, "README.md", "mcp")

	got, err := Discover(root, false)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	set := relSet(t, root, got)
	for _, want := range []string{
		".mcp.json", ".vscode/mcp.json", "nested/mcp-config.json",
		"claude_desktop_config.json", "opencode.json", "opencode.jsonc", "agents/pkg.mcp.json",
	} {
		if !set[want] {
			t.Errorf("Discover did not return %s; got %v", want, got)
		}
	}
	for _, unwanted := range []string{"package.json", "node_modules/dep/.mcp.json", "README.md"} {
		if set[unwanted] {
			t.Errorf("Discover returned %s; got %v", unwanted, got)
		}
	}
}

func TestDiscoverRefusesOutsideRootSymlink(t *testing.T) {
	outside := t.TempDir()
	writeConfig(t, outside, ".mcp.json", "{}")
	root := t.TempDir()
	if err := makeDirLink(t, filepath.Join(root, "linked"), outside); err != nil {
		t.Skipf("directory links unavailable: %v", err)
	}

	got, err := Discover(root, false)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Discover followed a symlink outside root: %v", got)
	}
}

func TestDiscoverBoundsFileSize(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(strings.Repeat(" ", int(MaxFileBytes)+1)), 0o600); err != nil {
		t.Fatalf("write oversized config: %v", err)
	}
	got, err := Discover(root, false)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Discover returned an oversized file: %v", got)
	}
}

func TestDiscoverIncludeUser(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	userDesktop := writeConfig(t, home, "claude_desktop_config.json", "{}")
	userMCP := writeConfig(t, home, ".config/mcp/files.json", "{}")
	userOpenCode := writeConfig(t, home, ".config/opencode/opencode.jsonc", "{}")
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	userOpenCodeWin := writeConfig(t, home, "AppData/Roaming/opencode/opencode.json", "{}")
	writeConfig(t, home, ".config/mcp/nested/ignored.json", "{}")

	root := t.TempDir()
	got, err := Discover(root, false)
	if err != nil {
		t.Fatalf("Discover without user configs: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("user configs were returned without includeUser: %v", got)
	}

	got, err = Discover(root, true)
	if err != nil {
		t.Fatalf("Discover with user configs: %v", err)
	}
	set := map[string]bool{}
	for _, p := range got {
		set[filepath.Clean(p)] = true
	}
	for _, want := range []string{userDesktop, userMCP, userOpenCode, userOpenCodeWin} {
		if !set[filepath.Clean(want)] {
			t.Errorf("Discover did not return user config %s; got %v", want, got)
		}
	}
	for _, p := range got {
		if strings.Contains(filepath.ToSlash(p), "/nested/") {
			t.Errorf("Discover returned a nested user config: %s", p)
		}
	}
}

func TestDiscoverRefusesUserConfigOutsideHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	outside := t.TempDir()
	writeConfig(t, outside, "evil.json", "{}")
	linkDir := filepath.Join(home, ".config", "mcp")
	if err := os.MkdirAll(filepath.Dir(linkDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := makeDirLink(t, linkDir, outside); err != nil {
		t.Skipf("directory links unavailable: %v", err)
	}

	got, err := Discover(t.TempDir(), true)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Discover followed a user config link outside home: %v", got)
	}
}

func TestRunAppliesOnlyMCPRules(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, ".mcp.json",
		`{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}}}`)

	fake := rules.New(model.RuleMeta{
		ID:          "VGL-CFG-999",
		Title:       "unrelated rule",
		Description: "must not run as part of an MCP audit",
		Severity:    model.SeverityHigh,
		Category:    model.CategoryConfig,
	}, func(f *rules.File) []model.Finding {
		return []model.Finding{{Location: model.Location{Path: f.Path, StartLine: 1}}}
	})

	res, err := Run(context.Background(), root, false, append(rules.MCPRules(), fake))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("Run returned no findings for an unpinned MCP server")
	}
	for _, fd := range res.Findings {
		if !strings.HasPrefix(fd.RuleID, MCPRulePrefix) {
			t.Errorf("Run executed a non-MCP rule: %q", fd.RuleID)
		}
	}
	if res.Scanned != 1 || res.Skipped != 0 {
		t.Errorf("Run counts = %d scanned / %d skipped, want 1/0", res.Scanned, res.Skipped)
	}
}

func TestRunScansVSCodeConfig(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, ".vscode/mcp.json",
		`{"servers":{"remote":{"type":"http","url":"http://mcp.example.com/sse"}}}`)

	got, err := Run(context.Background(), root, false, rules.MCPRules())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, fd := range got.Findings {
		if fd.RuleID == "VGL-MCP-004" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Run did not scan .vscode/mcp.json: %+v", got.Findings)
	}
}

func TestRunScansUserConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	writeConfig(t, home, ".config/mcp/files.json",
		`{"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/server"]}}}`)

	got, err := Run(context.Background(), t.TempDir(), true, rules.MCPRules())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, fd := range got.Findings {
		if fd.RuleID == "VGL-MCP-001" && strings.HasPrefix(fd.Location.Path, "~/.config/mcp/") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Run did not scan a user .config/mcp config: %+v", got.Findings)
	}
}

func TestRunOpenCodeConfigNoFalsePositives(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, "opencode.json", `{
  "$schema": "https://opencode.ai/config.json",
  "model": "opencode/example",
  "provider": {
    "acme": {"options": {"apiKey": "sk-live-9fJ2kLm8Qp3Rt5Vw7Xy1Za"}}
  },
  "autoApprove": ["*"],
  "mcp": {
    "files": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"],
      "enabled": true
    }
  }
}`)

	got, err := Run(context.Background(), root, false, rules.MCPRules())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got.Findings) != 0 {
		t.Fatalf("normal opencode.json produced %d findings: %+v", len(got.Findings), got.Findings)
	}
}

func TestRunCountsOnlyInspectedConfigs(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, ".mcp.json",
		`{"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/server"]}}}`)
	// Discovered by name, but the rules refuse documentation, tests and
	// examples: they must be reported as skipped, never as scanned.
	writeConfig(t, root, "docs/.mcp.json", `{"mcpServers":{"fs":{"command":"npx","args":["-y","x"]}}}`)
	writeConfig(t, root, "tests/fixtures/mcp.json", `{}`)
	writeConfig(t, root, "examples/mcp-config.json", `{}`)

	res, err := Run(context.Background(), root, false, rules.MCPRules())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1", res.Scanned)
	}
	if res.Skipped != 3 {
		t.Errorf("Skipped = %d, want 3", res.Skipped)
	}
	if len(res.Findings) == 0 {
		t.Fatal("Run returned no findings for the inspected config")
	}
	for _, fd := range res.Findings {
		if strings.HasPrefix(fd.Location.Path, "docs/") {
			t.Errorf("Run reported a finding from a skipped docs config: %+v", fd)
		}
	}
}

func TestRunScansOpenCodeJSONC(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, "opencode.jsonc", `{
  // opencode keeps its MCP servers in a top-level "mcp" object
  "provider": {"acme": {"options": {"apiKey": "sk-live-9fJ2kLm8Qp3Rt5Vw7Xy1Za"}}},
  "mcp": {
    "files": {"type": "local", "command": ["npx", "-y", "@scope/server"]}
  }
}`)

	res, err := Run(context.Background(), root, false, rules.MCPRules())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Scanned != 1 {
		t.Fatalf("Scanned = %d, want 1", res.Scanned)
	}
	found := false
	for _, fd := range res.Findings {
		if fd.RuleID == "VGL-MCP-001" {
			found = true
		}
		if strings.Contains(fd.Location.Snippet, "sk-live-9fJ2kLm8Qp3Rt5Vw7Xy1Za") ||
			strings.Contains(fd.Evidence, "sk-live-9fJ2kLm8Qp3Rt5Vw7Xy1Za") {
			t.Errorf("opencode.jsonc finding leaked a provider key: %+v", fd)
		}
	}
	if !found {
		t.Fatalf("Run did not inspect opencode.jsonc: %+v", res.Findings)
	}
}

func TestRunCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, t.TempDir(), false, rules.MCPRules()); err == nil {
		t.Fatal("Run ignored a canceled context")
	}
}

func TestIsConfigPath(t *testing.T) {
	yes := []string{".mcp.json", "mcp.json", "mcp-config.json", "claude_desktop_config.json",
		".vscode/mcp.json", "opencode.json", "opencode.jsonc", "agents/server.mcp.json", "mcp.yaml"}
	no := []string{"package.json", "README.md", "mcp-config.json.bak", "docs/mcp.html", ""}
	for _, p := range yes {
		if !IsConfigPath(p) {
			t.Errorf("IsConfigPath(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if IsConfigPath(p) {
			t.Errorf("IsConfigPath(%q) = true, want false", p)
		}
	}
}

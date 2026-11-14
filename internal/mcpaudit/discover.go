// Package mcpaudit discovers MCP server configuration files and evaluates the
// VGL-MCP rule family over them.
//
// Discovery is deterministic and offline. It reads files under a caller's
// project root and, when asked, a small set of known config paths under the
// user's home directory. It never follows a symlink outside those trees, never
// starts a process, never opens a network connection and never writes a file.
package mcpaudit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/safepath"
)

// MaxFileBytes is the largest MCP config file discovery and Run will read.
// Real configs are a few kilobytes; the bound keeps a hostile or accidental
// blob from being loaded into memory.
const MaxFileBytes int64 = 1 << 20

// skipDirs are dependency, build and VCS trees that never hold a loadable MCP
// config. ".vscode" is deliberately absent: .vscode/mcp.json is a supported
// location even though the scanner walker prunes that directory.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	".next":        true,
	".nuxt":        true,
	"coverage":     true,
	".idea":        true,
	".vigil":       true,
}

// Discover returns the absolute paths of MCP configuration files under root.
// It finds .mcp.json, mcp.json, mcp-config.json, claude_desktop_config.json,
// opencode.json, opencode.jsonc, *.mcp.json and their yaml variants, including
// .vscode/mcp.json.
//
// When includeUser is true it also adds known user-level configs from the
// user's home directory (claude_desktop_config.json, .config/mcp/*.json and
// the opencode config under .config/opencode or %APPDATA%\opencode among
// them), but only when they are regular, readable files that resolve inside the
// home directory.
//
// Unreadable entries are skipped rather than turning the whole audit into an
// error; an empty or invalid root is reported.
func Discover(root string, includeUser bool) ([]string, error) {
	base, err := resolveDir(root)
	if err != nil {
		return nil, err
	}
	return discoverUnder(base, includeUser), nil
}

// discoverUnder is the resolved-root half of Discover. base must be an
// absolute, existing directory.
func discoverUnder(base string, includeUser bool) []string {
	found := map[string]bool{}
	walkErr := filepath.WalkDir(base, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p == base {
				return nil
			}
			if skipDirs[strings.ToLower(d.Name())] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() && d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		if !IsConfigPath(d.Name()) || !readableUnder(p, base) {
			return nil
		}
		if abs, err := filepath.Abs(p); err == nil {
			found[filepath.Clean(abs)] = true
		}
		return nil
	})
	if walkErr != nil {
		return nil
	}
	if includeUser {
		for _, p := range userConfigs() {
			found[p] = true
		}
	}
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// IsConfigPath reports whether a base name (or a path whose base name is
// considered) is a known MCP configuration file name.
func IsConfigPath(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
	if p == "" {
		return false
	}
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case ".mcp.json", "mcp.json", "mcp-config.json", "claude_desktop_config.json",
		"opencode.json", "opencode.jsonc",
		"mcp.yaml", "mcp.yml", "mcp-config.yaml", "mcp-config.yml":
		return true
	}
	for _, suffix := range []string{".mcp.json", ".mcp.jsonc", ".mcp.yaml", ".mcp.yml"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func resolveDir(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("mcpaudit: resolve root: %w", err)
	}
	abs = filepath.Clean(abs)
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("mcpaudit: root %s: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("mcpaudit: root %s is not a directory", abs)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	return abs, nil
}

// readableUnder reports whether p is a regular file of bounded size whose
// fully resolved path stays inside base.
func readableUnder(p, base string) bool {
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		realBase = filepath.Clean(base)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil || !safepath.Within(realBase, real) {
		return false
	}
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileBytes {
		return false
	}
	fh, err := os.Open(p)
	if err != nil {
		return false
	}
	_ = fh.Close()
	return true
}

// userConfigs returns the known user-level MCP configs that exist, are
// readable and resolve inside the home directory.
func userConfigs() []string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return nil
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return nil
	}
	home = filepath.Clean(home)

	candidates := []string{
		filepath.Join(home, "claude_desktop_config.json"),
		filepath.Join(home, ".config", "claude", "claude_desktop_config.json"),
		filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".config", "opencode", "opencode.json"),
		filepath.Join(home, ".config", "opencode", "opencode.jsonc"),
	}
	// Windows keeps the opencode config under %APPDATA%\opencode. The env var
	// is read here rather than derived from home, and readableUnder still
	// rejects anything that resolves outside home.
	if appData := strings.TrimSpace(os.Getenv("APPDATA")); appData != "" {
		candidates = append(candidates,
			filepath.Join(appData, "opencode", "opencode.json"),
			filepath.Join(appData, "opencode", "opencode.jsonc"),
		)
	}
	dirs := []string{
		filepath.Join(home, ".config", "mcp"),
	}
	var out []string
	for _, p := range candidates {
		if readableUnder(p, home) {
			out = append(out, filepath.Clean(p))
		}
	}
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, p := range matches {
			if readableUnder(p, home) {
				out = append(out, filepath.Clean(p))
			}
		}
	}
	return out
}

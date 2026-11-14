package mcpaudit

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// MCPRulePrefix selects the rule family this package owns.
const MCPRulePrefix = "VGL-MCP-"

// Result is the outcome of one MCP configuration audit: the findings plus the
// file accounting a report shows.
type Result struct {
	Findings []model.Finding
	// Scanned counts discovered configs a rule actually inspected.
	Scanned int
	// Skipped counts discovered or user configs the rules refuse: documentation,
	// test fixtures, examples, oversized or unreadable files.
	Skipped int
}

// Run discovers MCP configuration files under root (plus known user configs
// when includeUser is true) and runs the given rules over them. Only rules
// whose ID starts with VGL-MCP- are executed, so a caller can pass a full
// registry without mixing unrelated findings into an MCP posture report.
//
// Files are read once, capped at MaxFileBytes, and the context is checked
// between files. A file the rules refuse (documentation, tests, examples) is
// counted as skipped rather than scanned, so the report never shows a config
// that produced no inspection. The function never executes a command from a
// config.
func Run(ctx context.Context, root string, includeUser bool, rs []rules.Rule) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	selected := make([]rules.Rule, 0, len(rs))
	for _, r := range rs {
		if r == nil {
			continue
		}
		if strings.HasPrefix(r.Meta().ID, MCPRulePrefix) {
			selected = append(selected, r)
		}
	}
	base, err := resolveDir(root)
	if err != nil {
		return Result{}, err
	}
	if len(selected) == 0 {
		return Result{}, nil
	}
	paths := discoverUnder(base, includeUser)
	home, _ := os.UserHomeDir()
	if home != "" {
		if abs, err := filepath.Abs(home); err == nil {
			home = filepath.Clean(abs)
		}
	}

	res := Result{}
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		f, ok := loadFile(base, home, p)
		if !ok || !rules.MCPConfigFile(f) {
			res.Skipped++
			continue
		}
		res.Scanned++
		for _, r := range selected {
			meta := r.Meta()
			findings := r.Check(f)
			for i := range findings {
				if findings[i].RuleID == "" {
					findings[i].RuleID = meta.ID
				}
				if findings[i].Category == "" {
					findings[i].Category = meta.Category
				}
				findings[i].Normalize()
			}
			res.Findings = append(res.Findings, findings...)
		}
	}
	model.SortFindings(res.Findings)
	return res, nil
}

// loadFile reads one config with the discovery size bound and builds the file
// value rules expect. It returns false for anything unreadable, oversized or
// binary.
func loadFile(base, home, p string) (*rules.File, bool) {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileBytes {
		return nil, false
	}
	fh, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, MaxFileBytes+1))
	if err != nil || int64(len(data)) > MaxFileBytes {
		return nil, false
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, false
	}
	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return &rules.File{
		Path:     displayPath(base, home, p),
		AbsPath:  p,
		Content:  data,
		Lines:    lines,
		Language: detectLanguage(p),
		Size:     len(data),
	}, true
}

// displayPath keeps a finding location readable: root-relative for project
// configs, ~-relative for user configs, absolute as a last resort.
func displayPath(base, home, p string) string {
	if rel, err := filepath.Rel(base, p); err == nil && !escapes(rel) {
		return filepath.ToSlash(rel)
	}
	if home != "" {
		if rel, err := filepath.Rel(home, p); err == nil && !escapes(rel) {
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(p)
}

func escapes(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel)
}

// detectLanguage mirrors the scanner labels for the extensions MCP configs
// use. It is local so this package does not depend on the scanner walker.
func detectLanguage(p string) string {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".json", ".jsonc":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	default:
		return "other"
	}
}

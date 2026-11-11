package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// runHardening runs only the anti-RE hardening rules (VGL-ARE-*). It reuses the
// scan pipeline so reports, baselines, severity filters and exit codes behave
// exactly like a normal scan, but forces deterministic-only output and skips
// the configured OSV lookup so advisory findings never mix into a posture
// report.
func runHardening(args []string, stdout, stderr io.Writer) error {
	if len(antiREIDs()) == 0 {
		return errors.New("hardening: no anti-RE rules are registered in this build")
	}
	prefixed := []string{
		"--no-llm",
		"--no-osv",
	}
	prefixed = append(prefixed, args...)
	return runScanLikeMode("hardening", prefixed, false, true, stdout, stderr)
}

// antiREIDs returns the IDs of every registered anti-RE rule.
func antiREIDs() []string {
	ids := make([]string, 0, 32)
	for _, meta := range rules.Default().Metas() {
		if meta.Category == model.CategoryAntiRE {
			ids = append(ids, meta.ID)
		}
	}
	return ids
}

// hardeningRules scopes a hardening run to the anti-RE family. Without
// --rules every VGL-ARE rule runs; with --rules the selection may only narrow
// that set, so the command can never report a non-hardening finding.
func hardeningRules(requested []string) ([]string, error) {
	all := antiREIDs()
	if len(requested) == 0 {
		return all, nil
	}
	known := make(map[string]bool, len(all))
	for _, id := range all {
		known[id] = true
	}
	out := make([]string, 0, len(requested))
	for _, raw := range requested {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if !known[id] {
			return nil, fmt.Errorf("hardening: --rules accepts only anti-RE rule IDs (VGL-ARE-*), got %q", raw)
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return all, nil
	}
	return out, nil
}

// hardeningPlatformOrder is the display order used by the CLI summary. It
// mirrors the MCP tool's grouping so both adapters tell the same story.
var hardeningPlatformOrder = []string{
	"Android", "iOS", "React Native", "Flutter", "Electron", "Web", "Native", ".NET", "Node", "Other",
}

// printHardeningSummary groups gaps by the REA surface they affect. The full
// report still follows unless --quiet is set.
func printHardeningSummary(w io.Writer, res *model.ScanResult, _ bool) {
	fmt.Fprintf(w, "vigil hardening — %s\n", displayPath(res.Root))
	fmt.Fprintf(w, "  files     %d scanned, %d skipped\n", res.Stats.FilesScanned, res.Stats.FilesSkipped)
	fmt.Fprintf(w, "  duration  %s\n", formatDuration(res.Stats.DurationMS))
	fmt.Fprintf(w, "  findings  %s\n", severitySummary(res.Stats.BySeverity))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "These are hardening gaps in the release configuration, not vulnerabilities.")
	fmt.Fprintln(w, "A missing control is not proof that the app is exploitable or bypassable.")

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "\nNo anti-RE hardening gaps found in this scope.")
		return
	}

	groups := map[string][]model.Finding{}
	for _, f := range res.Findings {
		groups[hardeningPlatformFor(f.RuleID)] = append(groups[hardeningPlatformFor(f.RuleID)], f)
	}
	printed := 0
	for _, platform := range hardeningPlatformOrder {
		fs := groups[platform]
		if len(fs) == 0 || printed >= 20 {
			continue
		}
		fmt.Fprintf(w, "\n%s (%d):\n", platform, len(fs))
		for _, f := range fs {
			if printed >= 20 {
				break
			}
			location := f.Location.Path
			if f.Location.StartLine > 0 {
				location = fmt.Sprintf("%s:%d", location, f.Location.StartLine)
			}
			fmt.Fprintf(w, "  %-6s %s — %s\n", strings.ToUpper(string(f.Severity)), f.RuleID, location)
			printed++
		}
	}
	if rest := len(res.Findings) - printed; rest > 0 {
		fmt.Fprintf(w, "\n… and %d more finding(s) in the report below.\n", rest)
	}
}

// hardeningPlatformFor mirrors the MCP tool's rule-to-platform mapping.
func hardeningPlatformFor(ruleID string) string {
	id := strings.ToUpper(strings.TrimSpace(ruleID))
	if !strings.HasPrefix(id, "VGL-ARE-") {
		return "Other"
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimPrefix(id, "VGL-ARE-"), "%d", &n); err != nil {
		return "Other"
	}
	switch n {
	case 50:
		return "Native"
	case 51:
		return ".NET"
	case 52, 53:
		return "iOS"
	case 54:
		return "Android"
	case 55:
		return "React Native"
	case 56, 57, 58:
		return "Electron"
	case 59:
		return "Web"
	}
	switch n / 10 {
	case 0:
		return "Android"
	case 1:
		return "iOS"
	case 2:
		return "Flutter"
	case 3:
		return "Electron"
	case 4:
		return "Node"
	default:
		return "Other"
	}
}

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// hardeningPlatformAll is the default --platform selection: every anti-RE
// platform.
const hardeningPlatformAll = "all"

// hardeningPlatformOrder is the stable display order used by the CLI summary.
// It mirrors the MCP tool's grouping so both adapters tell the same story.
var hardeningPlatformOrder = []string{
	"Android", "iOS", "Electron", "Node", "Flutter", "Web", "Other",
}

// hardeningPlatformNames maps the accepted --platform values to the canonical
// group name. Native, .NET and React Native findings have no dedicated group,
// so they are reported as Other.
var hardeningPlatformNames = map[string]string{
	"android":  "Android",
	"ios":      "iOS",
	"electron": "Electron",
	"node":     "Node",
	"flutter":  "Flutter",
	"web":      "Web",
	"other":    "Other",
}

// hardeningSelectedPlatform carries the --platform selection from
// runHardening to hardeningRules and printHardeningSummary. The summary is
// printed by the shared scan pipeline, which knows nothing about hardening
// flags, so the selection has to travel outside the flag set. runHardening
// assigns it on every run, so no stale value survives a command.
var hardeningSelectedPlatform = hardeningPlatformAll

// runHardening runs only the anti-RE hardening rules (VGL-ARE-*). It reuses the
// scan pipeline so reports, baselines, severity filters and exit codes behave
// exactly like a normal scan, but forces deterministic-only output and skips
// the configured OSV lookup so advisory findings never mix into a posture
// report.
func runHardening(args []string, stdout, stderr io.Writer) error {
	if len(antiREIDs()) == 0 {
		return errors.New("hardening: no anti-RE rules are registered in this build")
	}
	rest, platform, err := takeHardeningPlatform(args)
	if err != nil {
		return err
	}
	if wantsHardeningHelp(args) {
		printScanUsage(stdout, "hardening", false)
		fmt.Fprintln(stdout, "  --platform NAME        android, ios, electron, node, flutter, web, other or all (default all)")
		return nil
	}
	hardeningSelectedPlatform = platform

	prefixed := []string{
		"--no-llm",
		"--no-osv",
	}
	prefixed = append(prefixed, rest...)
	return runScanLikeMode("hardening", prefixed, false, true, stdout, stderr)
}

// wantsHardeningHelp reports whether the user asked for the usage text. The
// shared flag set would print it too, but it cannot mention --platform, which
// is consumed before the shared parser runs.
func wantsHardeningHelp(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "-h", "-help", "--help":
			return true
		}
	}
	return false
}

// takeHardeningPlatform removes --platform from args and returns the canonical
// selection. Both "--platform x" and "--platform=x" are accepted.
func takeHardeningPlatform(args []string) ([]string, string, error) {
	rest := make([]string, 0, len(args))
	raw := hardeningPlatformAll
	found := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--platform" || arg == "-platform":
			if i+1 >= len(args) {
				return nil, "", errors.New("hardening: --platform needs a value (android, ios, electron, node, flutter, web, other or all)")
			}
			i++
			raw = args[i]
			found = true
		case strings.HasPrefix(arg, "--platform="), strings.HasPrefix(arg, "-platform="):
			_, raw, _ = strings.Cut(arg, "=")
			found = true
		default:
			rest = append(rest, arg)
		}
	}
	if !found {
		return rest, hardeningPlatformAll, nil
	}
	platform, err := parseHardeningPlatform(raw)
	if err != nil {
		return nil, "", err
	}
	return rest, platform, nil
}

// parseHardeningPlatform accepts the CLI and MCP values and returns the
// canonical group name, or hardeningPlatformAll for "all"/"".
func parseHardeningPlatform(v string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(v))
	if key == "" || key == hardeningPlatformAll {
		return hardeningPlatformAll, nil
	}
	if platform, ok := hardeningPlatformNames[key]; ok {
		return platform, nil
	}
	return "", fmt.Errorf("hardening: unknown platform %q (use android, ios, electron, node, flutter, web, other or all)", v)
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

// hardeningRules scopes a hardening run to the anti-RE family and the selected
// platform. Without --rules every VGL-ARE rule of that platform runs; with
// --rules the selection may only narrow that set, so the command can never
// report a non-hardening finding.
func hardeningRules(requested []string) ([]string, error) {
	all := antiREIDs()
	if hardeningSelectedPlatform != hardeningPlatformAll {
		all = antiREIDsForPlatform(hardeningSelectedPlatform)
		if len(all) == 0 {
			return nil, fmt.Errorf("hardening: no anti-RE rules for platform %s", hardeningSelectedPlatform)
		}
	}
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
			if hardeningSelectedPlatform != hardeningPlatformAll {
				return nil, fmt.Errorf("hardening: %s is not an anti-RE rule for platform %s; --platform narrows --rules", id, strings.ToLower(hardeningSelectedPlatform))
			}
			return nil, fmt.Errorf("hardening: --rules accepts only anti-RE rule IDs (VGL-ARE-*), got %q", raw)
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return all, nil
	}
	return out, nil
}

// antiREIDsForPlatform returns the anti-RE rules whose metadata declares the
// given platform.
func antiREIDsForPlatform(platform string) []string {
	ids := make([]string, 0, 32)
	for _, meta := range rules.Default().Metas() {
		if meta.Category != model.CategoryAntiRE {
			continue
		}
		if hardeningPlatform(meta) == platform {
			ids = append(ids, meta.ID)
		}
	}
	return ids
}

// hardeningPlatformIndex maps rule IDs to their declared platform. Rules
// without Platform metadata are absent and fall back to the numeric ranges.
func hardeningPlatformIndex() map[string]string {
	metas := rules.Default().Metas()
	index := make(map[string]string, len(metas))
	for _, meta := range metas {
		if platform := strings.TrimSpace(meta.Platform); platform != "" {
			index[strings.ToUpper(strings.TrimSpace(meta.ID))] = platform
		}
	}
	return index
}

// printHardeningSummary groups gaps by the platform they affect. The full
// report still follows unless --quiet is set.
func printHardeningSummary(w io.Writer, res *model.ScanResult, _ bool) {
	index := hardeningPlatformIndex()
	selected := hardeningPlatformLabel(hardeningSelectedPlatform)
	fmt.Fprintf(w, "vigil hardening — %s\n", displayPath(res.Root))
	fmt.Fprintf(w, "  files     %d scanned, %d skipped\n", res.Stats.FilesScanned, res.Stats.FilesSkipped)
	fmt.Fprintf(w, "  duration  %s\n", formatDuration(res.Stats.DurationMS))
	fmt.Fprintf(w, "  findings  %s\n", severitySummary(res.Stats.BySeverity))
	fmt.Fprintf(w, "  platform  %s\n", selected)
	// The detected line is the whole anti-RE rule set, so a platform filter
	// never hides that other platforms exist. The finding counts describe what
	// this run actually found; the rule counts describe the coverage that the
	// selection skipped.
	fmt.Fprintf(w, "  detected  %s\n", hardeningPlatformCoverage(hardeningSelectedPlatform, res.Findings))
	if hardeningSelectedPlatform != hardeningPlatformAll {
		fmt.Fprintf(w, "  note      only %s rules were scanned; run without --platform to review every platform\n", strings.ToLower(hardeningSelectedPlatform))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "These are hardening gaps in the release configuration, not vulnerabilities.")
	fmt.Fprintln(w, "A missing control is not proof that the app is exploitable or bypassable.")

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "\nNo anti-RE hardening gaps found in this scope.")
		return
	}

	groups := map[string][]model.Finding{}
	considered := 0
	for _, f := range res.Findings {
		platform := hardeningPlatformFor(f.RuleID, index[strings.ToUpper(strings.TrimSpace(f.RuleID))])
		// The scan already runs only the selected platform's rules; skipping
		// the others here keeps a directly-built result set honest too.
		if hardeningSelectedPlatform != hardeningPlatformAll && platform != hardeningSelectedPlatform {
			continue
		}
		considered++
		groups[platform] = append(groups[platform], f)
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
	if rest := considered - printed; rest > 0 {
		fmt.Fprintf(w, "\n… and %d more finding(s) in the report below.\n", rest)
	}
}

// hardeningPlatformCoverage renders the finding count per platform and the
// rule coverage next to it, in the stable display order. Groups the current
// selection skips are marked as filtered and only carry their rule count.
func hardeningPlatformCoverage(selected string, findings []model.Finding) string {
	index := hardeningPlatformIndex()
	findingCounts := map[string]int{}
	for _, f := range findings {
		findingCounts[hardeningPlatformFor(f.RuleID, index[strings.ToUpper(strings.TrimSpace(f.RuleID))])]++
	}
	ruleCounts := map[string]int{}
	for _, meta := range rules.Default().Metas() {
		if meta.Category != model.CategoryAntiRE {
			continue
		}
		ruleCounts[hardeningPlatform(meta)]++
	}
	parts := make([]string, 0, len(hardeningPlatformOrder))
	for _, platform := range hardeningPlatformOrder {
		n := ruleCounts[platform]
		found := findingCounts[platform]
		if n == 0 && found == 0 {
			continue
		}
		if selected != hardeningPlatformAll && selected != platform {
			parts = append(parts, fmt.Sprintf("%s (%d %s, filtered)", platform, n, plural(n, "rule", "rules")))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%d %s, %d %s)", platform, found,
			plural(found, "finding", "findings"), n, plural(n, "rule", "rules")))
	}
	return strings.Join(parts, ", ")
}

// hardeningPlatformLabel is the human-readable selection, with the number of
// rules it keeps so a filter never looks like a smaller rule pack.
func hardeningPlatformLabel(selected string) string {
	total := len(antiREIDs())
	if selected == hardeningPlatformAll {
		return fmt.Sprintf("all (%d anti-RE rules)", total)
	}
	return fmt.Sprintf("%s (%d of %d anti-RE rules)", strings.ToLower(selected), len(antiREIDsForPlatform(selected)), total)
}

// hardeningPlatform resolves a rule's platform from its metadata. The numeric
// ID ranges are only the fallback for rules that declare no platform.
func hardeningPlatform(meta model.RuleMeta) string {
	return hardeningPlatformFor(meta.ID, meta.Platform)
}

// hardeningPlatformFor resolves one rule. A declared platform wins; the
// numeric ranges of the original rule waves (00x Android, 01x iOS, 02x
// Flutter, 03x Electron, 04x Node, 05x per-surface) are the fallback so rules
// that predate the metadata field still group correctly.
func hardeningPlatformFor(ruleID, platform string) string {
	if name, ok := hardeningPlatformNames[strings.ToLower(strings.TrimSpace(platform))]; ok {
		return name
	}
	if strings.TrimSpace(platform) != "" {
		// Legacy labels (Native, .NET, React Native) and anything unexpected
		// belong to the catch-all group rather than inventing a new one.
		return "Other"
	}
	id := strings.ToUpper(strings.TrimSpace(ruleID))
	if !strings.HasPrefix(id, "VGL-ARE-") {
		return "Other"
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimPrefix(id, "VGL-ARE-"), "%d", &n); err != nil {
		return "Other"
	}
	switch n {
	case 50, 51, 55:
		// Rust, .NET and React Native have no dedicated display group; they
		// share the catch-all so no finding falls outside hardeningPlatformOrder.
		return "Other"
	case 52, 53:
		return "iOS"
	case 54:
		return "Android"
	case 56, 57, 58:
		return "Electron"
	case 59:
		return "Web"
	case 60, 61, 62:
		return "Android"
	case 63:
		return "Electron"
	case 64:
		return "iOS"
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

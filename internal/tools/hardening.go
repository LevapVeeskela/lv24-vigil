package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// hardeningPlatformAll is the default platform selection: every anti-RE
// platform.
const hardeningPlatformAll = "all"

// hardeningPlatforms is the stable display order of the platform groups.
var hardeningPlatforms = []string{
	"Android", "iOS", "Electron", "Node", "Flutter", "Web", "Other",
}

// hardeningPlatformNames maps the accepted platform values to the canonical
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

// hardeningTopFindings bounds the text summary; structuredContent carries the
// full scan result.
const hardeningTopFindings = 20

type hardeningArgs struct {
	Path        string `json:"path"`
	Platform    string `json:"platform"`
	MinSeverity string `json:"minSeverity"`
	MaxFindings int    `json:"maxFindings"`
	Offset      int    `json:"offset"`
	NoBaseline  bool   `json:"noBaseline"`
}

func registerHardening(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_hardening",
		Title: "Review anti-reverse-engineering hardening",
		Description: "Run only the anti-RE hardening rules (VGL-ARE-*): release minification, debug signing, " +
			"debuggable builds, backup and cleartext settings, plist transport exceptions, release obfuscation, " +
			"Electron/Node isolation, inspector flags and production source maps. Reports hardening gaps, not " +
			"vulnerabilities. Optionally narrow the review to one platform. Results are windowed: maxFindings " +
			"is the page size (default 50, capped at 500) and offset selects the page; the page object states " +
			"total, hasMore and nextOffset, and a coverage object states what was scanned. Returns a text " +
			"summary grouped by platform and the scan result as structuredContent. Writes local scan " +
			"history, never source files.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"path":        mcp.Prop("string", "Mobile or desktop project to review. Defaults to the server's project root."),
			"platform":    mcp.PropEnum("Only report findings for this platform. Defaults to all.", "all", "android", "ios", "electron", "node", "flutter", "web", "other"),
			"minSeverity": mcp.PropEnum("Minimum severity to report.", "critical", "high", "medium", "low", "info"),
			"maxFindings": mcp.PropInt("Page size: maximum findings in this window (default 50, capped at 500)."),
			"offset":      mcp.PropInt("Zero-based finding offset for paging. Start with 0, then pass page.nextOffset from the previous result."),
			"noBaseline":  mcp.PropBool("Ignore the baseline and report suppressed findings as active."),
		}),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleHardening(ctx, d, raw)
		},
	})
}

func handleHardening(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	if d.App.Registry == nil {
		return mcp.TextError("vigil is not initialised: the rule registry is missing"), nil
	}
	var args hardeningArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	platform, err := parseHardeningPlatform(args.Platform)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}
	if err := checkOffset(args.Offset); err != nil {
		return errorResult(d, "%v", err), nil
	}
	minSeverity, err := parseSeverityArg(args.MinSeverity)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}
	root, err := resolvePath(d, args.Path)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}

	metas := d.App.Registry.Metas()
	ids := antiREIDs(metas)
	if len(ids) == 0 {
		return mcp.TextError("no anti-RE hardening rules are registered in this build; update Vigil"), nil
	}
	// Narrow the rule set before the scan, exactly like the CLI does. Filtering
	// findings afterwards would let rules from other platforms consume the
	// MaxFindings budget, so a selected platform could lose every gap and the
	// summary could claim there is nothing to fix.
	if platform != hardeningPlatformAll {
		ids = antiREIDsForPlatform(metas, platform)
		if len(ids) == 0 {
			return mcp.TextError("no anti-RE hardening rules for platform %s are registered in this build", strings.ToLower(platform)), nil
		}
	}

	// Hardening is a deterministic posture check: never let a configured model
	// reorder or drop the gaps.
	disabled := false
	limit := clampInt(args.MaxFindings, maxFindingsDefault, maxFindingsCap)
	fetch := args.Offset + limit
	if fetch > maxFindingsCap {
		fetch = maxFindingsCap
	}
	res, err := d.App.Scan(ctx, model.ScanRequest{
		Root:        root,
		UseLLM:      &disabled,
		OnlyRules:   ids,
		MinSeverity: minSeverity,
		MaxFindings: fetch,
		NoBaseline:  args.NoBaseline,
		DisableOSV:  true,
	})
	if err != nil {
		return errorResult(d, "hardening scan failed: %v", err), nil
	}

	// Defence in depth: the scan already ran only the selected platform's
	// rules, but a result built by another path must not leak other platforms.
	// The filter also rebuilds every aggregate that describes the kept set.
	index := hardeningPlatformIndex(metas)
	applyHardeningPlatformFilter(res, platform, index)
	view, page, cov, reported := scanPage(res, args.Offset, limit, false)
	detected := hardeningPlatformCounts(view.Findings, index)
	text := hardeningSummary(d, view, ids, platform, detected, page, cov) + pageCapNote(reported, page.Total)
	return result(d, text, &scanPayload{ScanResult: view, Page: &page, Coverage: cov}), nil
}

// antiREIDs returns the IDs of every registered rule in the anti-re category.
func antiREIDs(metas []model.RuleMeta) []string {
	ids := make([]string, 0, len(metas))
	for _, m := range metas {
		if m.Category == model.CategoryAntiRE {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

// antiREIDsForPlatform returns the anti-RE rules that resolve to the given
// platform group. Narrowing OnlyRules before the scan keeps MaxFindings and the
// stats scoped to the selection.
func antiREIDsForPlatform(metas []model.RuleMeta, platform string) []string {
	ids := make([]string, 0, len(metas))
	for _, m := range metas {
		if m.Category != model.CategoryAntiRE {
			continue
		}
		if hardeningPlatformFor(m.ID, m.Platform) == platform {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

// hardeningRuleCounts counts the anti-RE rules per platform group.
func hardeningRuleCounts(metas []model.RuleMeta) map[string]int {
	counts := make(map[string]int, len(hardeningPlatforms))
	for _, m := range metas {
		if m.Category != model.CategoryAntiRE {
			continue
		}
		counts[hardeningPlatformFor(m.ID, m.Platform)]++
	}
	return counts
}

// hardeningPlatformIndex maps rule IDs to their declared Platform. Rules
// without the field are absent and fall back to the numeric ID ranges.
func hardeningPlatformIndex(metas []model.RuleMeta) map[string]string {
	index := make(map[string]string, len(metas))
	for _, m := range metas {
		if platform := strings.TrimSpace(m.Platform); platform != "" {
			index[strings.ToUpper(strings.TrimSpace(m.ID))] = platform
		}
	}
	return index
}

// hardeningPlatform resolves a rule's platform: the declared metadata wins,
// the numeric ID ranges are only the fallback. Anything outside the anti-RE
// family (for example a dependency finding from a separately enabled scanner)
// is reported as Other instead of being guessed.
func hardeningPlatform(ruleID string, index map[string]string) string {
	return hardeningPlatformFor(ruleID, index[strings.ToUpper(strings.TrimSpace(ruleID))])
}

// hardeningPlatformFor resolves one rule. A declared platform wins; the
// numeric ranges of the rule waves (00x Android, 01x iOS, 02x Flutter, 03x
// Electron, 04x Node, 05x per-surface) are the fallback.
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
	n, err := strconv.Atoi(strings.TrimPrefix(id, "VGL-ARE-"))
	if err != nil {
		return "Other"
	}
	switch n {
	case 50, 51, 55:
		// Rust, .NET and React Native have no dedicated display group; they
		// share the catch-all so no finding falls outside hardeningPlatforms.
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

// parseHardeningPlatform accepts the tool values and returns the canonical
// group name, or hardeningPlatformAll for "all"/"".
func parseHardeningPlatform(v string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(v))
	if key == "" || key == hardeningPlatformAll {
		return hardeningPlatformAll, nil
	}
	if platform, ok := hardeningPlatformNames[key]; ok {
		return platform, nil
	}
	return "", fmt.Errorf("unknown platform %q (use android, ios, electron, node, flutter, web, other or all)", v)
}

// hardeningPlatformCount is one platform row of the detected distribution.
type hardeningPlatformCount struct {
	Platform string
	Findings int
}

// hardeningPlatformCounts counts findings per platform in the stable display
// order.
func hardeningPlatformCounts(findings []model.Finding, index map[string]string) []hardeningPlatformCount {
	totals := map[string]int{}
	for _, f := range findings {
		totals[hardeningPlatform(f.RuleID, index)]++
	}
	out := make([]hardeningPlatformCount, 0, len(hardeningPlatforms))
	for _, platform := range hardeningPlatforms {
		if totals[platform] == 0 {
			continue
		}
		out = append(out, hardeningPlatformCount{Platform: platform, Findings: totals[platform]})
	}
	return out
}

// filterFindingsByPlatform keeps only the findings of the selected platform.
func filterFindingsByPlatform(findings []model.Finding, platform string, index map[string]string) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if hardeningPlatform(f.RuleID, index) != platform {
			continue
		}
		out = append(out, f)
	}
	return out
}

// applyHardeningPlatformFilter drops findings and suppressed entries outside
// the selected platform and rebuilds BySeverity/ByCategory from the kept
// findings. Files, duration and RulesRun describe the scan itself and stay
// intact.
func applyHardeningPlatformFilter(res *model.ScanResult, platform string, index map[string]string) {
	if res == nil {
		return
	}
	if platform != hardeningPlatformAll {
		res.Findings = filterFindingsByPlatform(res.Findings, platform, index)
		res.Suppressed = filterFindingsByPlatform(res.Suppressed, platform, index)
	}
	res.Stats.BySeverity, res.Stats.ByCategory = hardeningStats(res.Findings)
}

// hardeningStats recomputes the severity and category aggregates from the
// findings a caller actually receives.
func hardeningStats(findings []model.Finding) (map[model.Severity]int, map[model.Category]int) {
	bySeverity := make(map[model.Severity]int, 5)
	byCategory := make(map[model.Category]int, 16)
	for _, f := range findings {
		bySeverity[f.Severity]++
		byCategory[f.Category]++
	}
	return bySeverity, byCategory
}

// hardeningPlatformLine renders the selection, the detected finding counts and
// the rule coverage so a platform filter never hides what it skipped.
func hardeningPlatformLine(selected string, detected []hardeningPlatformCount, rules map[string]int) string {
	findings := make(map[string]int, len(detected))
	for _, c := range detected {
		findings[c.Platform] = c.Findings
	}
	parts := make([]string, 0, len(hardeningPlatforms))
	for _, platform := range hardeningPlatforms {
		ruleCount := rules[platform]
		findingCount := findings[platform]
		if ruleCount == 0 && findingCount == 0 {
			continue
		}
		if selected != hardeningPlatformAll && selected != platform {
			parts = append(parts, fmt.Sprintf("%s (%d %s, filtered)", platform, ruleCount, hardeningPlural(ruleCount, "rule", "rules")))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%d %s, %d %s)", platform,
			findingCount, hardeningPlural(findingCount, "finding", "findings"),
			ruleCount, hardeningPlural(ruleCount, "rule", "rules")))
	}
	if len(parts) == 0 {
		return strings.ToLower(selected)
	}
	return strings.ToLower(selected) + " — " + strings.Join(parts, ", ")
}

// hardeningPlural picks the singular or plural noun for a count.
func hardeningPlural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

// hardeningSummary renders the human-readable half of vigil_hardening. It
// groups gaps by platform and never turns a missing control into a
// vulnerability claim.
func hardeningSummary(d Deps, res *model.ScanResult, ids []string, platform string, detected []hardeningPlatformCount, page pageInfo, cov *coverageInfo) string {
	var metas []model.RuleMeta
	if d.App != nil && d.App.Registry != nil {
		metas = d.App.Registry.Metas()
	}
	index := hardeningPlatformIndex(metas)
	rules := hardeningRuleCounts(metas)

	var b strings.Builder
	fmt.Fprintf(&b, "Vigil anti-RE hardening — %d hardening gap(s)\n", page.Total)
	fmt.Fprintf(&b, "Root: %s\n", res.Root)
	fmt.Fprintf(&b, "Rules: %d anti-RE rules (VGL-ARE)\n", len(ids))
	fmt.Fprintf(&b, "Platform: %s\n", hardeningPlatformLine(platform, detected, rules))
	if page.Total == len(res.Findings) {
		fmt.Fprintf(&b, "Findings: %d (%s)\n", len(res.Findings), severityLine(res.Findings))
	} else {
		fmt.Fprintf(&b, "Findings: %d shown of %d (%s)\n", len(res.Findings), page.Total, severityLine(res.Findings))
	}
	fmt.Fprintf(&b, "Page: %s\n", pageNote(page))
	fmt.Fprintf(&b, "%s\n", coverageNote(cov))
	if len(res.Suppressed) > 0 {
		fmt.Fprintf(&b, "Baseline: %d finding(s) suppressed (set noBaseline=true to include them)\n", len(res.Suppressed))
	}
	fmt.Fprintf(&b, "Files: %d scanned, %d skipped in %d ms\n", res.Stats.FilesScanned, res.Stats.FilesSkipped, res.Stats.DurationMS)
	// The scan forces UseLLM=false, so a configured model is never consulted;
	// naming it here would suggest model output that does not exist.
	b.WriteString("Model: not used (deterministic anti-RE rules)\n")
	fmt.Fprintf(&b, "Warnings: %s\n", warningLine(res.Errors))
	b.WriteString("\nThese are hardening gaps in the project's release configuration, not vulnerabilities. ")
	b.WriteString("A missing control says what is absent, not that the app is exploitable, backdoored or bypassable.\n")

	if page.Total == 0 {
		b.WriteString("\nNo hardening gaps found by the anti-RE rules in this scope.\n")
		return b.String()
	}
	if len(res.Findings) == 0 {
		b.WriteString("\nNo hardening gaps in this window. Pass offset=0 to start from the first finding.\n")
		return b.String()
	}

	groups := map[string][]model.Finding{}
	for _, f := range res.Findings {
		group := hardeningPlatform(f.RuleID, index)
		groups[group] = append(groups[group], f)
	}

	printed := 0
	areCount := 0
	for _, f := range res.Findings {
		if strings.HasPrefix(strings.ToUpper(f.RuleID), "VGL-ARE-") {
			areCount++
		}
	}
	for _, group := range hardeningPlatforms {
		fs := groups[group]
		if len(fs) == 0 || printed >= hardeningTopFindings {
			continue
		}
		fmt.Fprintf(&b, "\n%s (%d):\n", group, len(fs))
		for _, f := range fs {
			if printed == hardeningTopFindings {
				break
			}
			fmt.Fprintf(&b, "  %d. %s\n", printed+1, findingSummary(f))
			printed++
		}
	}
	if rest := len(res.Findings) - printed; rest > 0 {
		fmt.Fprintf(&b, "\n… and %d more finding(s) (raise maxFindings or read structuredContent).\n", rest)
	}
	if other := len(res.Findings) - areCount; other > 0 {
		fmt.Fprintf(&b, "\n%d finding(s) are not part of the anti-RE family; they come from other scanners enabled in the config.\n", other)
	}
	return b.String()
}

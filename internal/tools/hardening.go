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

// hardeningPlatforms is the stable display order of the platform groups.
var hardeningPlatforms = []string{
	"Android", "iOS", "React Native", "Flutter", "Electron", "Web", "Native", ".NET", "Node", "Other",
}

// hardeningTopFindings bounds the text summary; structuredContent carries the
// full scan result.
const hardeningTopFindings = 20

type hardeningArgs struct {
	Path        string `json:"path"`
	MinSeverity string `json:"minSeverity"`
	MaxFindings int    `json:"maxFindings"`
	NoBaseline  bool   `json:"noBaseline"`
}

func registerHardening(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_hardening",
		Title: "Review anti-reverse-engineering hardening",
		Description: "Run only the anti-RE hardening rules (VGL-ARE-*): release minification, debug signing, " +
			"debuggable builds, backup and cleartext settings, plist transport exceptions, release obfuscation, " +
			"Electron/Node isolation, inspector flags and production source maps. Reports hardening gaps, not " +
			"vulnerabilities. Returns a text summary grouped by platform and the full scan result as structuredContent.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"path":        mcp.Prop("string", "Mobile or desktop project to review. Defaults to the server's project root."),
			"minSeverity": mcp.PropEnum("Minimum severity to report.", "critical", "high", "medium", "low", "info"),
			"maxFindings": mcp.PropInt("Maximum findings to return (default 50, capped at 500)."),
			"noBaseline":  mcp.PropBool("Ignore the baseline and report suppressed findings as active."),
		}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
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

	minSeverity, err := parseSeverityArg(args.MinSeverity)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}
	root, err := resolvePath(d, args.Path)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}

	ids := antiREIDs(d.App.Registry.Metas())
	if len(ids) == 0 {
		return mcp.TextError("no anti-RE hardening rules are registered in this build; update Vigil"), nil
	}

	// Hardening is a deterministic posture check: never let a configured model
	// reorder or drop the gaps.
	disabled := false
	res, err := d.App.Scan(ctx, model.ScanRequest{
		Root:        root,
		UseLLM:      &disabled,
		OnlyRules:   ids,
		MinSeverity: minSeverity,
		MaxFindings: clampInt(args.MaxFindings, maxFindingsDefault, maxFindingsCap),
		NoBaseline:  args.NoBaseline,
		DisableOSV:  true,
	})
	if err != nil {
		return errorResult(d, "hardening scan failed: %v", err), nil
	}
	return result(d, hardeningSummary(d, res, ids), res), nil
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

// hardeningPlatform maps a VGL-ARE rule to its platform family. The first
// wave is grouped by tens (00x Android, 01x iOS, 02x Flutter, 03x Electron,
// 04x Node); the second wave (05x) maps REA-specific surfaces individually.
// Anything else (for example a dependency finding from a separately enabled
// scanner) is reported as Other instead of being guessed.
func hardeningPlatform(ruleID string) string {
	id := strings.ToUpper(strings.TrimSpace(ruleID))
	if !strings.HasPrefix(id, "VGL-ARE-") {
		return "Other"
	}
	n, err := strconv.Atoi(strings.TrimPrefix(id, "VGL-ARE-"))
	if err != nil {
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

// hardeningSummary renders the human-readable half of vigil_hardening. It
// groups gaps by platform and never turns a missing control into a
// vulnerability claim.
func hardeningSummary(d Deps, res *model.ScanResult, ids []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Vigil anti-RE hardening — %d hardening gap(s)\n", len(res.Findings))
	fmt.Fprintf(&b, "Root: %s\n", res.Root)
	fmt.Fprintf(&b, "Rules: %d anti-RE rules (VGL-ARE)\n", len(ids))
	fmt.Fprintf(&b, "Findings: %d (%s)\n", len(res.Findings), severityLine(res.Findings))
	if len(res.Suppressed) > 0 {
		fmt.Fprintf(&b, "Baseline: %d finding(s) suppressed (set noBaseline=true to include them)\n", len(res.Suppressed))
	}
	fmt.Fprintf(&b, "Files: %d scanned, %d skipped in %d ms\n", res.Stats.FilesScanned, res.Stats.FilesSkipped, res.Stats.DurationMS)
	fmt.Fprintf(&b, "Model: %s\n", modelLine(d, res.Model))
	fmt.Fprintf(&b, "Warnings: %s\n", warningLine(res.Errors))
	b.WriteString("\nThese are hardening gaps in the project's release configuration, not vulnerabilities. ")
	b.WriteString("A missing control says what is absent, not that the app is exploitable, backdoored or bypassable.\n")

	if len(res.Findings) == 0 {
		b.WriteString("\nNo hardening gaps found by the anti-RE rules in this scope.\n")
		return b.String()
	}

	groups := map[string][]model.Finding{}
	for _, f := range res.Findings {
		platform := hardeningPlatform(f.RuleID)
		groups[platform] = append(groups[platform], f)
	}

	printed := 0
	areCount := 0
	for _, f := range res.Findings {
		if strings.HasPrefix(strings.ToUpper(f.RuleID), "VGL-ARE-") {
			areCount++
		}
	}
	for _, platform := range hardeningPlatforms {
		fs := groups[platform]
		if len(fs) == 0 || printed >= hardeningTopFindings {
			continue
		}
		fmt.Fprintf(&b, "\n%s (%d):\n", platform, len(fs))
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

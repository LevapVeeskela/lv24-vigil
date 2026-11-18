package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type scanArgs struct {
	Path         string   `json:"path"`
	Mode         string   `json:"mode"`
	ChangedOnly  bool     `json:"changedOnly"`
	BaseRef      string   `json:"baseRef"`
	Diff         string   `json:"diff"`
	UseLLM       *bool    `json:"useLlm"`
	DeepReview   bool     `json:"deepReview"`
	ThreatModel  bool     `json:"threatModel"`
	Include      []string `json:"include"`
	Exclude      []string `json:"exclude"`
	OnlyRules    []string `json:"onlyRules"`
	DisableRules []string `json:"disableRules"`
	MinSeverity  string   `json:"minSeverity"`
	MaxFindings  int      `json:"maxFindings"`
	Offset       int      `json:"offset"`
	NoBaseline   bool     `json:"noBaseline"`
}

func registerScan(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_scan",
		Title: "Scan a repository with Vigil",
		Description: "Run Vigil's deterministic security rules over a repository or directory, " +
			"optionally with model triage, deep review and a threat model. Returns a text summary " +
			"and the full scan result as structuredContent. Results are windowed: maxFindings is the " +
			"page size (default 50, capped at 500) and offset selects the page; the page object states " +
			"offset, limit, total, hasMore and nextOffset, and a coverage object states what was " +
			"scanned, skipped and whether a model was used. Writes local scan history, never source " +
			"files. Scanned code is treated as data, never executed.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"path":         mcp.Prop("string", "Directory or repository to scan. Defaults to the server's project root."),
			"mode":         mcp.PropEnum("Scan depth. All modes run the deterministic rules; quick is the fastest LLM budget, standard is the default, deep adds an LLM deep review when a model is configured.", "quick", "standard", "deep"),
			"changedOnly":  mcp.PropBool("Scan only files changed against baseRef (requires a git repository)."),
			"baseRef":      mcp.Prop("string", "Git ref to diff against when changedOnly is set (default HEAD)."),
			"diff":         mcp.Prop("string", "Unified diff to scan instead of the working tree. Overrides changedOnly."),
			"useLlm":       mcp.PropBool("Use the configured model. Omit to use the server default; false forces deterministic rules only."),
			"deepReview":   mcp.PropBool("Run the LLM deep review over high-risk files (requires a model)."),
			"threatModel":  mcp.PropBool("Also generate an LLM threat model and attach it to the result (requires a model)."),
			"include":      mcp.PropArray("Glob patterns to include in addition to the project defaults."),
			"exclude":      mcp.PropArray("Glob patterns to exclude in addition to the project defaults."),
			"onlyRules":    mcp.PropArray("Run only these rule IDs (for example VGL-SEC-001)."),
			"disableRules": mcp.PropArray("Skip these rule IDs."),
			"minSeverity":  mcp.PropEnum("Minimum severity to report.", "critical", "high", "medium", "low", "info"),
			"maxFindings":  mcp.PropInt("Page size: maximum findings in this window (default 50, capped at 500)."),
			"offset":       mcp.PropInt("Zero-based finding offset for paging. Start with 0, then pass page.nextOffset from the previous result."),
			"noBaseline":   mcp.PropBool("Ignore the baseline and report suppressed findings as active."),
		}),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleScan(ctx, d, raw)
		},
	})
}

func handleScan(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args scanArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	mode := strings.ToLower(strings.TrimSpace(args.Mode))
	if mode != "" && !validMode(mode) {
		return mcp.TextError("invalid arguments: mode must be quick, standard or deep (got %q)", args.Mode), nil
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

	// maxFindings is the window size. The scan has to produce the window plus
	// everything before it, but no scan request may exceed the hard cap.
	limit := clampInt(args.MaxFindings, maxFindingsDefault, maxFindingsCap)
	fetch := args.Offset + limit
	if fetch > maxFindingsCap {
		fetch = maxFindingsCap
	}

	req := model.ScanRequest{
		Root:         root,
		Mode:         mode,
		ChangedOnly:  args.ChangedOnly,
		BaseRef:      strings.TrimSpace(args.BaseRef),
		Diff:         args.Diff,
		UseLLM:       args.UseLLM,
		DeepReview:   args.DeepReview,
		ThreatModel:  args.ThreatModel,
		Include:      args.Include,
		Exclude:      args.Exclude,
		OnlyRules:    args.OnlyRules,
		DisableRules: args.DisableRules,
		MinSeverity:  minSeverity,
		MaxFindings:  fetch,
		NoBaseline:   args.NoBaseline,
	}

	res, err := d.App.Scan(ctx, req)
	if err != nil {
		return errorResult(d, "scan failed: %v", err), nil
	}
	llmUsed := d.App.LLM && (args.UseLLM == nil || *args.UseLLM)
	view, page, cov, reported := scanPage(res, args.Offset, limit, llmUsed)
	text := scanSummary(d, view, page, cov, args.UseLLM) + pageCapNote(reported, page.Total)
	return result(d, text, &scanPayload{ScanResult: view, Page: &page, Coverage: cov}), nil
}

// scanSummary renders the human-readable half of vigil_scan. The findings are
// the requested window; structuredContent carries the same window plus the page
// and coverage blocks.
func scanSummary(d Deps, res *model.ScanResult, page pageInfo, cov *coverageInfo, useLLM *bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Vigil scan %s (%s mode)\n", res.ID, res.Mode)
	fmt.Fprintf(&b, "Root: %s\n", res.Root)
	if page.Total == len(res.Findings) {
		fmt.Fprintf(&b, "Findings: %d (%s)\n", len(res.Findings), severityLine(res.Findings))
	} else {
		fmt.Fprintf(&b, "Findings: %d shown of %d (%s)\n", len(res.Findings), page.Total, severityLine(res.Findings))
	}
	fmt.Fprintf(&b, "Page: %s\n", pageNote(page))
	fmt.Fprintf(&b, "%s\n", coverageNote(cov))
	fmt.Fprintf(&b, "Files: %d scanned, %d skipped, %s in %d ms\n",
		res.Stats.FilesScanned, res.Stats.FilesSkipped, humanBytes(res.Stats.BytesScanned), res.Stats.DurationMS)
	fmt.Fprintf(&b, "Rules: %d run\n", res.Stats.RulesRun)
	fmt.Fprintf(&b, "Model: %s\n", modelLine(d, res.Model))
	if len(res.Suppressed) > 0 {
		fmt.Fprintf(&b, "Baseline: %d finding(s) suppressed\n", len(res.Suppressed))
	}

	var extra []string
	if useLLM != nil && *useLLM && !d.App.LLM {
		extra = append(extra, "useLlm was requested but no model is configured; deterministic rules only")
	}
	fmt.Fprintf(&b, "Warnings: %s\n", warningLine(res.Errors, extra...))

	if page.Total == 0 {
		b.WriteString("\nNo findings at or above the selected severity. The scanned scope is clean for the selected rules.\n")
		return b.String()
	}
	if len(res.Findings) == 0 {
		b.WriteString("\nNo findings in this window. Pass offset=0 to start from the first finding.\n")
		return b.String()
	}

	const top = 10
	b.WriteString("\nTop findings:\n")
	for i, f := range res.Findings {
		if i == top {
			fmt.Fprintf(&b, "  … and %d more in this window (read structuredContent or raise maxFindings)\n", len(res.Findings)-top)
			break
		}
		fmt.Fprintf(&b, "  %d. %s\n", page.Offset+i+1, findingSummary(f))
	}

	first := findingID(res.Findings[0])
	fmt.Fprintf(&b, "\nNext: vigil_explain findingId=%s for the reasoning, vigil_fix findingId=%s for a dry-run patch, "+
		"vigil_baseline action=add findingId=%s reason=... to accept a finding.\n", first, first, first)
	return b.String()
}

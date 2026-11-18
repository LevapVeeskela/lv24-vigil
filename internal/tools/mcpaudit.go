package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/mcpaudit"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
	"github.com/levapveeskela/lv24-vigil/internal/version"
)

// mcpAuditTopFindings bounds the text summary; structuredContent carries the
// complete audit result.
const mcpAuditTopFindings = 20

type mcpAuditArgs struct {
	Path        string `json:"path"`
	IncludeUser bool   `json:"includeUser"`
	MinSeverity string `json:"minSeverity"`
	MaxFindings int    `json:"maxFindings"`
	Offset      int    `json:"offset"`
}

func registerMCPAudit(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_mcp_audit",
		Title: "Audit MCP server configuration",
		Description: "Run only the MCP configuration rules (VGL-MCP-*): unpinned server packages, literal secrets " +
			"in env/headers/args, cleartext remote endpoints, disabled TLS verification, dangerous mounts, " +
			"auto-approval and prompt-injection surfaces. Reads .mcp.json, mcp.json, mcp-config.json, " +
			"claude_desktop_config.json, opencode.json[c], *.mcp.json and YAML variants; with includeUser it also " +
			"reads known home-directory configs. Deterministic and offline: no configured server is started, no " +
			"endpoint is contacted and nothing is written. Results are windowed: maxFindings is the page size " +
			"(default 50, capped at 500) and offset selects the page; the page object states total, hasMore and " +
			"nextOffset, and a coverage object states what was read. Returns a text summary and the audit result " +
			"as structuredContent.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"path":        mcp.Prop("string", "Directory to audit. Defaults to the server's project root; the resolved path must stay inside it."),
			"includeUser": mcp.PropBool("Also read known user-level MCP configs under the home directory."),
			"minSeverity": mcp.PropEnum("Minimum severity to report.", "critical", "high", "medium", "low", "info"),
			"maxFindings": mcp.PropInt("Page size: maximum findings in this window (default 50, capped at 500)."),
			"offset":      mcp.PropInt("Zero-based finding offset for paging. Start with 0, then pass page.nextOffset from the previous result."),
		}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleMCPAudit(ctx, d, raw)
		},
	})
}

func handleMCPAudit(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	if d.App.Registry == nil {
		return mcp.TextError("vigil is not initialised: the rule registry is missing"), nil
	}
	var args mcpAuditArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	minSeverity, err := parseSeverityArg(args.MinSeverity)
	if err != nil {
		return typedResult(d, toolErrorf(CodeArgs, "%v", err)), nil
	}
	if minSeverity == "" {
		minSeverity = model.SeverityInfo
	}
	if err := checkScanOffset(args.Offset); err != nil {
		return errorResult(d, "%v", err), nil
	}
	root, err := resolveMCPAuditPath(d, args.Path)
	if err != nil {
		return typedResult(d, toolErrorf(CodeBadPath, "%v", err)), nil
	}

	ruleCount := 0
	for _, r := range d.App.Registry.All() {
		if r != nil && strings.HasPrefix(r.Meta().ID, mcpaudit.MCPRulePrefix) {
			ruleCount++
		}
	}
	if ruleCount == 0 {
		return mcp.TextError("no MCP configuration rules are registered in this build; update Vigil"), nil
	}

	started := time.Now().UTC()
	audit, err := mcpaudit.Run(ctx, root, args.IncludeUser, d.App.Registry.All())
	if err != nil {
		return errorResult(d, "MCP audit failed: %v", err), nil
	}
	finished := time.Now().UTC()

	limit := clampInt(args.MaxFindings, maxFindingsDefault, maxFindingsCap)
	qualified := model.Filter(audit.Findings, minSeverity, 0)
	reported := len(qualified)
	total := reported
	if total > maxFindingsCap {
		total = maxFindingsCap
	}
	start, end, page := window(total, args.Offset, limit)
	if start > len(qualified) {
		start = len(qualified)
	}
	if end > len(qualified) {
		end = len(qualified)
	}
	if start > end {
		start = end
	}
	findings := append([]model.Finding{}, qualified[start:end]...)

	res := mcpAuditScanResult(root, findings, audit.Scanned, audit.Skipped, ruleCount, started, finished)
	res.Stats.FindingsTotal = total
	cov := coverageFor(res, false)
	text := mcpAuditSummary(res, args.IncludeUser, page, cov) + pageCapNote(reported, total)
	return result(d, text, &scanPayload{ScanResult: res, Page: &page, Coverage: cov}), nil
}

// resolveMCPAuditPath resolves a requested directory and keeps it inside the
// server root. The audit is a project posture check; includeUser is the only
// way it reads outside that root, and only from known home config paths.
func resolveMCPAuditPath(d Deps, p string) (string, error) {
	root, err := resolvePath(d, p)
	if err != nil {
		return "", err
	}
	realRoot, realTarget := d.App.Root, root
	if resolved, err := filepath.EvalSymlinks(realRoot); err == nil {
		realRoot = resolved
	}
	if resolved, err := filepath.EvalSymlinks(realTarget); err == nil {
		realTarget = resolved
	}
	if !safepath.Within(realRoot, realTarget) {
		return "", fmt.Errorf("path %q is outside the project root %s; MCP audit reads only the server root and, with includeUser, known home configs", p, d.App.Root)
	}
	return root, nil
}

// mcpAuditScanResult shapes the audit like a scan result so clients can consume
// one stable structure. It is never stored in scan history.
func mcpAuditScanResult(root string, findings []model.Finding, scanned, skipped, ruleCount int, started, finished time.Time) *model.ScanResult {
	res := &model.ScanResult{
		ID:         "mcp-audit",
		StartedAt:  started,
		FinishedAt: finished,
		Root:       root,
		Mode:       "mcp-audit",
		Findings:   append([]model.Finding{}, findings...),
		Stats: model.Stats{
			FilesScanned: scanned,
			FilesSkipped: skipped,
			RulesRun:     ruleCount,
			BySeverity:   map[model.Severity]int{},
			ByCategory:   map[model.Category]int{},
		},
		Engine:  "vigil-mcpaudit",
		Version: version.Version,
	}
	for _, f := range findings {
		res.Stats.BySeverity[f.Severity]++
		res.Stats.ByCategory[f.Category]++
	}
	res.Stats.DurationMS = finished.Sub(started).Milliseconds()
	return res
}

// mcpAuditSummary renders the human-readable half of vigil_mcp_audit. It is
// explicit about the scan boundary and never treats a clean config as proof
// that an MCP server is trustworthy.
func mcpAuditSummary(res *model.ScanResult, includeUser bool, page pageInfo, cov *coverageInfo) string {
	var b strings.Builder
	scope := "project configs only"
	if includeUser {
		scope = "project configs plus known user configs"
	}
	fmt.Fprintf(&b, "Vigil MCP configuration audit — %s\n", res.Root)
	fmt.Fprintf(&b, "Config files: %d inspected (%s)\n", res.Stats.FilesScanned, scope)
	if res.Stats.FilesSkipped > 0 {
		fmt.Fprintf(&b, "Config files skipped: %d (documentation, tests, examples, oversized or unreadable)\n", res.Stats.FilesSkipped)
	}
	fmt.Fprintf(&b, "Rules: %d MCP configuration rules (VGL-MCP), deterministic and offline\n", res.Stats.RulesRun)
	if page.Total == len(res.Findings) {
		fmt.Fprintf(&b, "Findings: %d (%s)\n", len(res.Findings), severityLine(res.Findings))
	} else {
		fmt.Fprintf(&b, "Findings: %d shown of %d (%s)\n", len(res.Findings), page.Total, severityLine(res.Findings))
	}
	fmt.Fprintf(&b, "Page: %s\n", pageNote(page))
	fmt.Fprintf(&b, "%s\n", coverageNote(cov))
	b.WriteString("Model: not used (deterministic MCP configuration rules)\n")
	b.WriteString("\nOnly MCP configuration text is read. No configured server is started, no endpoint is\n")
	b.WriteString("contacted and nothing is written. A clean audit does not prove that an MCP server is\n")
	b.WriteString("trustworthy: the rules cannot see the server's own code or runtime behaviour.\n")

	if page.Total == 0 {
		b.WriteString("\nNo MCP configuration findings in this scope.\n")
		return b.String()
	}
	if len(res.Findings) == 0 {
		b.WriteString("\nNo MCP configuration findings in this window. Pass offset=0 to start from the first finding.\n")
		return b.String()
	}

	b.WriteString("\nTop findings:\n")
	for i, f := range res.Findings {
		if i == mcpAuditTopFindings {
			fmt.Fprintf(&b, "  … and %d more finding(s) in this window (raise maxFindings or read structuredContent).\n", len(res.Findings)-i)
			break
		}
		fmt.Fprintf(&b, "  %d. [%s] %s %s — %s\n", page.Offset+i+1, f.RuleID, displaySeverity(f.Severity), oneLine(f.Title), locationString(f.Location))
	}
	return b.String()
}

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/mcpaudit"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/report"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
	"github.com/levapveeskela/lv24-vigil/internal/version"
)

// mcpAuditEngine identifies an MCP posture report in the report header. It is
// not a stored scan: the command never writes scan history.
const mcpAuditEngine = "vigil-mcpaudit"

// runMCPAudit runs only the VGL-MCP rules over discovered MCP server
// configuration files. It is deterministic and offline: no configured server
// or endpoint is started or contacted, and nothing is written except the
// explicitly requested report file.
func runMCPAudit(args []string, stdout, _ io.Writer) error {
	fs := newFlagSet("mcp-audit")
	flagPath := fs.String("path", "", "directory to audit (default .); a positional path also works")
	includeUser := fs.Bool("user", false, "also read known user-level MCP configs under the home directory")
	format := fs.String("format", "md", "output format: md, json or sarif")
	output := fs.String("output", "", "write the report to FILE (\"-\" for stdout)")
	failOn := fs.String("fail-on", "", "exit 2 when a finding at or above this severity exists")
	maxFindings := fs.Int("max-findings", 0, "cap the number of findings (0 = no cap)")

	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, `Usage: vigil mcp-audit [path] [flags]

Runs only the VGL-MCP rules over MCP server configuration files (.mcp.json,
mcp.json, mcp-config.json, claude_desktop_config.json, opencode.json[c], *.mcp.json
and their YAML variants). Deterministic and offline: no configured server is
started, no endpoint is contacted and nothing is written except --output.

Flags:
  --path DIR              directory to audit (default .); a positional path also works
  --user                  also read known user-level configs under the home directory
  --format md|json|sarif  output format (default md)
  --output FILE           write the report to FILE ("-" = stdout)
  --fail-on LEVEL         exit 2 when a finding at or above LEVEL exists
  --max-findings N        cap the number of findings (0 = no cap)
`)
		return nil
	}
	if err != nil {
		return fmt.Errorf("mcp-audit: %w", err)
	}

	root, err := resolvePathArgument("mcp-audit", positional, *flagPath)
	if err != nil {
		return err
	}
	formatName, err := canonicalFormat(*format)
	if err != nil {
		return fmt.Errorf("mcp-audit: %w", err)
	}
	if formatName == "html" {
		return errors.New("mcp-audit: --format must be md, json or sarif (html is not supported)")
	}
	var failSeverity model.Severity
	if strings.TrimSpace(*failOn) != "" {
		failSeverity, err = parseSeverity(*failOn)
		if err != nil {
			return fmt.Errorf("mcp-audit: --fail-on: %w", err)
		}
	}
	if *maxFindings < 0 {
		return fmt.Errorf("mcp-audit: --max-findings must be 0 or a positive integer (got %d)", *maxFindings)
	}

	all := rules.Default().All()
	ruleCount := countMCPRules(all)
	if ruleCount == 0 {
		return errors.New("mcp-audit: no VGL-MCP rules are registered in this build")
	}

	ctx, stop := signalContext()
	defer stop()

	started := time.Now().UTC()
	audit, err := mcpaudit.Run(ctx, root, *includeUser, all)
	if err != nil {
		return fmt.Errorf("mcp-audit: %w", err)
	}
	findings := model.Filter(audit.Findings, model.SeverityInfo, *maxFindings)
	finished := time.Now().UTC()

	res := mcpAuditResult(root, findings, audit.Scanned, audit.Skipped, ruleCount, started, finished)
	data, err := report.Render(formatName, res, report.Options{})
	if err != nil {
		return err
	}
	if *output == "" || *output == "-" {
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("mcp-audit: write report: %w", err)
		}
	} else {
		if err := writeFile(*output, data); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote %s\n", *output)
	}

	if failSeverity != "" && hasFindingsAtLeast(res.Findings, failSeverity) {
		return ErrFindings
	}
	return nil
}

// mcpAuditResult shapes an MCP posture audit like a scan result so the JSON,
// SARIF and Markdown renderers stay the single report path. It is not stored in
// scan history and carries no model information.
func mcpAuditResult(root string, findings []model.Finding, scanned, skipped, ruleCount int, started, finished time.Time) *model.ScanResult {
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
		Engine:  mcpAuditEngine,
		Version: version.Version,
	}
	for _, f := range findings {
		res.Stats.BySeverity[f.Severity]++
		res.Stats.ByCategory[f.Category]++
	}
	res.Stats.DurationMS = finished.Sub(started).Milliseconds()
	return res
}

// countMCPRules reports how many rules in rs belong to the VGL-MCP family.
func countMCPRules(rs []rules.Rule) int {
	n := 0
	for _, r := range rs {
		if r != nil && strings.HasPrefix(r.Meta().ID, mcpaudit.MCPRulePrefix) {
			n++
		}
	}
	return n
}

// resolvePathArgument resolves the shared "positional path or --path" form used
// by the auditing and inventory commands.
func resolvePathArgument(command string, positional []string, flagPath string) (string, error) {
	if len(positional) > 1 {
		return "", fmt.Errorf("%s: expected at most one path, got %d", command, len(positional))
	}
	p := flagPath
	if len(positional) == 1 {
		if p != "" && p != positional[0] {
			return "", fmt.Errorf("%s: path given twice (%q and %q)", command, p, positional[0])
		}
		p = positional[0]
	}
	if p == "" {
		p = "."
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("%s: resolve %q: %w", command, p, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("%s: %q does not exist or is not readable", command, abs)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s: %q is not a directory", command, abs)
	}
	return abs, nil
}

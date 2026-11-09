package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/report"
)

type reportArgs struct {
	Format string `json:"format"`
	ScanID string `json:"scanId"`
	Path   string `json:"path"`
}

func registerReport(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_report",
		Title: "Render a Vigil scan report",
		Description: "Render a stored scan as Markdown, JSON, SARIF or HTML. Without path the report is " +
			"returned as text; with path it is written inside the app root and the absolute path is returned.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"format": mcp.PropEnum("Report format. Defaults to md.", "md", "json", "sarif", "html"),
			"scanId": mcp.Prop("string", "Scan to render. Defaults to the most recent scan."),
			"path":   mcp.Prop("string", "Relative path inside the app root to write the report to (for example reports/vigil.md)."),
		}),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleReport(ctx, d, raw)
		},
	})
}

func handleReport(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args reportArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	format, err := reportFormat(args.Format)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}
	scan, err := loadScan(d, args.ScanID)
	if err != nil {
		return errorResult(d, "%v", err), nil
	}
	data, err := report.Render(format, scan, report.Options{ShowFix: true})
	if err != nil {
		return errorResult(d, "report failed: %v", err), nil
	}

	if strings.TrimSpace(args.Path) == "" {
		payload := map[string]any{
			"format":   format,
			"scanId":   scan.ID,
			"bytes":    len(data),
			"findings": len(scan.Findings),
		}
		return result(d, string(data), payload), nil
	}

	target, err := resolveInsideRoot(d.App.Root, args.Path)
	if err != nil {
		return mcp.TextError("invalid arguments: path: %v", err), nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return errorResult(d, "report: create directory for %s: %v", target, err), nil
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return errorResult(d, "report: write %s: %v", target, err), nil
	}

	text := fmt.Sprintf("Wrote %s (%s, %s) for scan %s: %d finding(s) (%s).\nNothing else was modified.\n",
		target, format, humanBytes(int64(len(data))), scan.ID, len(scan.Findings), severityLine(scan.Findings))
	payload := map[string]any{
		"path":     target,
		"format":   format,
		"bytes":    len(data),
		"scanId":   scan.ID,
		"findings": len(scan.Findings),
		"critical": countSeverity(scan.Findings, model.SeverityCritical),
		"high":     countSeverity(scan.Findings, model.SeverityHigh),
	}
	return result(d, text, payload), nil
}

func reportFormat(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "md", "markdown":
		return report.FormatMarkdown, nil
	case "json":
		return report.FormatJSON, nil
	case "sarif":
		return report.FormatSARIF, nil
	case "html", "htm":
		return report.FormatHTML, nil
	default:
		return "", fmt.Errorf("format must be md, json, sarif or html (got %q)", v)
	}
}

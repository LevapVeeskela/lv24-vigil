package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type fixArgs struct {
	FindingID string `json:"findingId"`
	ScanID    string `json:"scanId"`
	Apply     bool   `json:"apply"`
}

func registerFix(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_fix",
		Title: "Propose or apply a fix for a Vigil finding",
		Description: "Ask the configured model for a validated unified diff that fixes one finding. " +
			"With apply=false (the default) nothing is written; with apply=true the diff is applied to the " +
			"working tree and never committed.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"findingId": mcp.Prop("string", "Finding ID (VGL-...), fingerprint (fp_...) or a unique prefix."),
			"scanId":    mcp.Prop("string", "Scan to look in. Defaults to the most recent scan."),
			"apply":     mcp.PropBool("Apply the proposed diff to the working tree. Defaults to false (dry run)."),
		}, "findingId"),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleFix(ctx, d, raw)
		},
	})
}

func handleFix(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args fixArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}
	if strings.TrimSpace(args.FindingID) == "" {
		return mcp.TextError("invalid arguments: findingId is required"), nil
	}

	scan, f, err := lookupFinding(d, args.ScanID, args.FindingID)
	if err != nil {
		return errorResult(d, "%v", err), nil
	}
	if !d.App.LLM {
		return mcp.TextError("vigil_fix needs a model: set VIGIL_PROVIDER, VIGIL_MODEL and VIGIL_API_KEY (or a local OLLAMA_HOST). " +
			"Use vigil_explain for the deterministic remediation in the meantime."), nil
	}
	if args.Apply && scan.Root != "" && !samePath(scan.Root, d.App.Root) {
		return errorResult(d, "refusing to apply a fix: the finding belongs to %s but this server is rooted at %s. "+
			"Run the MCP server from the repository that contains the finding.", scan.Root, d.App.Root), nil
	}

	fix, err := d.App.ProposeFix(ctx, *f)
	if err != nil {
		return errorResult(d, "fix proposal failed: %v", err), nil
	}
	if fix == nil || strings.TrimSpace(fix.Diff) == "" {
		return errorResult(d, "the model did not return an applicable diff for %s; fix it manually or ask again with more context.", findingID(*f)), nil
	}

	payload := map[string]any{
		"scanId":    scan.ID,
		"findingId": findingID(*f),
		"fix":       fix,
	}

	if args.Apply {
		if err := d.App.ApplyFix(ctx, fix); err != nil {
			text := fixMarkdown(*f, fix, false) + "\n**Apply failed:** " + err.Error() + "\n"
			res := result(d, text, payload)
			res.IsError = true
			return res, nil
		}
		return result(d, fixMarkdown(*f, fix, true), payload), nil
	}
	return result(d, fixMarkdown(*f, fix, false), payload), nil
}

func fixMarkdown(f model.Finding, fix *model.Fix, applied bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Fix for %s — %s\n\n", findingID(f), oneLine(f.Title))
	fmt.Fprintf(&b, "Location: `%s`\n\n", locationString(f.Location))
	if desc := strings.TrimSpace(fix.Description); desc != "" {
		b.WriteString(desc)
		b.WriteString("\n\n")
	}
	b.WriteString(fenced(fix.Diff, "diff"))
	b.WriteString("\n\n")
	if len(fix.Files) > 0 {
		fmt.Fprintf(&b, "**Files:** %s\n\n", strings.Join(fix.Files, ", "))
	}
	if applied {
		b.WriteString("**Applied:** yes, to the working tree only. Nothing was committed. " +
			"Review `git diff` and run the project tests before committing.\n")
	} else {
		b.WriteString("**Applied:** no (dry run). Review the diff and ask the user before calling vigil_fix with apply=true.\n")
	}
	return b.String()
}

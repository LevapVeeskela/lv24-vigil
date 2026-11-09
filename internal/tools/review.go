package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type reviewArgs struct {
	Path        string `json:"path"`
	Diff        string `json:"diff"`
	BaseRef     string `json:"baseRef"`
	ChangedOnly *bool  `json:"changedOnly"`
	UseLLM      *bool  `json:"useLlm"`
}

func registerReview(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_review",
		Title: "Review changed lines with Vigil",
		Description: "Scan only the added lines of a diff: the working-tree changes against a git ref, " +
			"or a unified diff supplied by the client. Returns a text summary and the full scan result.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"path":        mcp.Prop("string", "Directory or repository to review. Defaults to the server's project root."),
			"diff":        mcp.Prop("string", "Unified diff to review. When omitted, changed files are read from git."),
			"baseRef":     mcp.Prop("string", "Git ref to diff against (default HEAD)."),
			"changedOnly": mcp.PropBool("Review only changed files. Defaults to true; ignored when diff is supplied."),
			"useLlm":      mcp.PropBool("Use the configured model for triage. Omit to use the server default."),
		}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleReview(ctx, d, raw)
		},
	})
}

func handleReview(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args reviewArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	changedOnly := true
	if args.ChangedOnly != nil {
		changedOnly = *args.ChangedOnly
	}
	baseRef := strings.TrimSpace(args.BaseRef)
	if baseRef == "" {
		baseRef = "HEAD"
	}
	root, err := resolvePath(d, args.Path)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}

	res, err := d.App.Review(ctx, model.ScanRequest{
		Root:        root,
		Diff:        args.Diff,
		BaseRef:     baseRef,
		ChangedOnly: changedOnly,
		UseLLM:      args.UseLLM,
	})
	if err != nil {
		return errorResult(d, "review failed: %v. A changedOnly review needs a git repository; pass diff=... to review a patch instead.", err), nil
	}
	return result(d, reviewSummary(d, res, args, baseRef), res), nil
}

func reviewSummary(d Deps, res *model.ScanResult, args reviewArgs, baseRef string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Vigil review (quick) — %d new finding(s) on changed lines\n", len(res.Findings))
	fmt.Fprintf(&b, "Root: %s\n", res.Root)
	if strings.TrimSpace(args.Diff) != "" {
		b.WriteString("Input: unified diff supplied by the client\n")
	} else {
		fmt.Fprintf(&b, "Input: changed files against %s\n", baseRef)
	}
	fmt.Fprintf(&b, "Findings: %d (%s)\n", len(res.Findings), severityLine(res.Findings))
	fmt.Fprintf(&b, "Files: %d scanned, %d skipped in %d ms\n", res.Stats.FilesScanned, res.Stats.FilesSkipped, res.Stats.DurationMS)
	fmt.Fprintf(&b, "Model: %s\n", modelLine(d, res.Model))
	fmt.Fprintf(&b, "Warnings: %s\n", warningLine(res.Errors))

	if len(res.Findings) == 0 {
		b.WriteString("\nNo findings on the added lines.\n")
		if res.Stats.FilesScanned == 0 {
			fmt.Fprintf(&b, "No changed files were detected for %s; the diff may be empty or the path may not be a git repository.\n", baseRef)
		}
		return b.String()
	}

	const top = 20
	b.WriteString("\nFindings:\n")
	for i, f := range res.Findings {
		if i == top {
			fmt.Fprintf(&b, "  … and %d more\n", len(res.Findings)-top)
			break
		}
		fmt.Fprintf(&b, "  %d. %s\n", i+1, findingSummary(f))
	}
	first := findingID(res.Findings[0])
	fmt.Fprintf(&b, "\nNext: vigil_explain findingId=%s or vigil_fix findingId=%s (dry run).\n", first, first)
	return b.String()
}

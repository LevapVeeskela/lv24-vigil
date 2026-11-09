package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type verifyArgs struct {
	FindingID string   `json:"findingId"`
	ScanID    string   `json:"scanId"`
	Paths     []string `json:"paths"`
}

type verifyPayload struct {
	FindingID      string          `json:"findingId"`
	Fingerprint    string          `json:"fingerprint"`
	OriginalScanID string          `json:"originalScanId"`
	Root           string          `json:"root"`
	Paths          []string        `json:"paths"`
	Resolved       bool            `json:"resolved"`
	StillPresent   bool            `json:"stillPresent"`
	Inconclusive   bool            `json:"inconclusive,omitempty"`
	MatchKind      string          `json:"matchKind,omitempty"`
	Match          *model.Finding  `json:"match,omitempty"`
	FilesScanned   int             `json:"filesScanned"`
	Findings       int             `json:"findings"`
	Remaining      []model.Finding `json:"remaining"`
	Warnings       []string        `json:"warnings,omitempty"`
}

func registerVerify(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_verify",
		Title: "Verify that a Vigil finding is gone",
		Description: "Re-scan the finding's file (or explicit paths) with the deterministic rules and report " +
			"whether the same fingerprint is still present. Useful after a fix.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"findingId": mcp.Prop("string", "Finding ID (VGL-...), fingerprint (fp_...) or a unique prefix."),
			"scanId":    mcp.Prop("string", "Scan the finding belongs to. Defaults to the most recent scan."),
			"paths":     mcp.PropArray("Files to re-scan, relative to the scan root. Defaults to the finding's file."),
		}, "findingId"),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleVerify(ctx, d, raw)
		},
	})
}

func handleVerify(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args verifyArgs
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

	root := strings.TrimSpace(scan.Root)
	if root == "" {
		root = d.App.Root
	}
	paths := make([]string, 0, len(args.Paths))
	for _, p := range args.Paths {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		if strings.TrimSpace(f.Location.Path) == "" {
			return mcp.TextError("invalid arguments: the finding has no file path; pass paths explicitly"), nil
		}
		paths = []string{f.Location.Path}
	}

	// Verification ignores the baseline and the configured severity floor: the
	// question is whether the issue is still in the code, not whether it is
	// currently accepted.
	opts := d.App.Options(model.ScanRequest{
		Root:        root,
		Mode:        "quick",
		MinSeverity: model.SeverityInfo,
		MaxFindings: 10000,
		NoBaseline:  true,
	})
	scanRes, err := d.App.Scanner.ScanPaths(ctx, root, paths, opts)
	if err != nil {
		return errorResult(d, "verification scan failed: %v", err), nil
	}

	targetID := findingID(*f)
	targetFP := findingFingerprint(*f)

	var fpMatch, locMatch *model.Finding
	for i := range scanRes.Findings {
		cand := &scanRes.Findings[i]
		if strings.EqualFold(cand.ID, targetID) || strings.EqualFold(findingFingerprint(*cand), targetFP) {
			fpMatch = cand
			break
		}
	}
	if fpMatch == nil {
		for i := range scanRes.Findings {
			cand := &scanRes.Findings[i]
			if cand.RuleID == f.RuleID &&
				cand.Location.Path == f.Location.Path &&
				cand.Location.StartLine == f.Location.StartLine {
				locMatch = cand
				break
			}
		}
	}

	matchKind := ""
	switch {
	case fpMatch != nil:
		matchKind = "fingerprint"
	case locMatch != nil:
		matchKind = "location"
	}
	stillPresent := matchKind != ""

	payload := verifyPayload{
		FindingID:      targetID,
		Fingerprint:    targetFP,
		OriginalScanID: scan.ID,
		Root:           root,
		Paths:          paths,
		Resolved:       !stillPresent,
		StillPresent:   stillPresent,
		MatchKind:      matchKind,
		FilesScanned:   scanRes.Stats.FilesScanned,
		Findings:       len(scanRes.Findings),
		Remaining:      scanRes.Findings,
		Warnings:       scanRes.Errors,
	}
	// If nothing was scanned and the scanner reported errors (for example a
	// path outside the root), absence of the fingerprint proves nothing.
	if !stillPresent && scanRes.Stats.FilesScanned == 0 && len(scanRes.Errors) > 0 {
		payload.Resolved = false
		payload.Inconclusive = true
	}
	if fpMatch != nil {
		payload.Match = fpMatch
	} else if locMatch != nil {
		payload.Match = locMatch
	}

	return result(d, verifySummary(payload), payload), nil
}

func verifySummary(p verifyPayload) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Verification — %s (`%s`)\n\n", p.FindingID, p.Fingerprint)
	fmt.Fprintf(&b, "- **Original scan:** %s\n", p.OriginalScanID)
	fmt.Fprintf(&b, "- **Root:** %s\n", p.Root)
	fmt.Fprintf(&b, "- **Re-scanned:** %s\n", strings.Join(p.Paths, ", "))
	fmt.Fprintf(&b, "- **Files scanned:** %d; findings: %d\n\n", p.FilesScanned, p.Findings)

	if p.Match != nil {
		switch p.MatchKind {
		case "location":
			fmt.Fprintf(&b, "**Result: STILL PRESENT (changed evidence)** — the same rule still fires at `%s`, but the fingerprint changed, so the value was edited without removing the issue.\n", locationString(p.Match.Location))
		default:
			fmt.Fprintf(&b, "**Result: STILL PRESENT** — the finding fingerprint is still present at `%s`.\n", locationString(p.Match.Location))
		}
	} else if p.Inconclusive {
		b.WriteString("**Result: INCONCLUSIVE** — no files were scanned, so the missing fingerprint proves nothing. Check the paths and the warnings below.\n")
	} else {
		b.WriteString("**Result: RESOLVED** — the finding fingerprint no longer appears in the re-scan.\n")
	}

	if len(p.Remaining) > 0 {
		fmt.Fprintf(&b, "\nRemaining findings (%d):\n", len(p.Remaining))
		const top = 10
		for i, f := range p.Remaining {
			if i == top {
				fmt.Fprintf(&b, "  … and %d more\n", len(p.Remaining)-top)
				break
			}
			fmt.Fprintf(&b, "  %d. %s\n", i+1, findingSummary(f))
		}
	}
	if len(p.Warnings) > 0 {
		fmt.Fprintf(&b, "\nWarnings: %s\n", warningLine(p.Warnings))
	}
	return b.String()
}

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
)

type baselineArgs struct {
	Action    string `json:"action"`
	FindingID string `json:"findingId"`
	Reason    string `json:"reason"`
	ScanID    string `json:"scanId"`
}

func registerBaseline(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_baseline",
		Title: "Manage the Vigil suppression baseline",
		Description: "List, add, remove or clear accepted findings in the project baseline. " +
			"Adding requires a finding ID and a reason; removed entries stop being suppressed on the next scan.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"action":    mcp.PropEnum("Baseline operation. Defaults to list.", "list", "add", "remove", "clear"),
			"findingId": mcp.Prop("string", "Finding ID (VGL-...), fingerprint (fp_...) or a unique prefix. Required for add and remove."),
			"reason":    mcp.Prop("string", "Why the finding is accepted. Required for add."),
			"scanId":    mcp.Prop("string", "Scan to resolve the finding in. Defaults to the most recent scan."),
		}),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleBaseline(d, raw)
		},
	})
}

func handleBaseline(d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args baselineArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	action := strings.ToLower(strings.TrimSpace(args.Action))
	if action == "" {
		action = "list"
	}
	path, err := baselinePath(d)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	switch action {
	case "list":
		return baselineList(d, path)
	case "add":
		return baselineAdd(d, path, args)
	case "remove":
		return baselineRemove(d, path, args)
	case "clear":
		return baselineClear(d, path)
	default:
		return mcp.TextError("invalid arguments: action must be list, add, remove or clear (got %q)", args.Action), nil
	}
}

func baselinePath(d Deps) (string, error) {
	p := strings.TrimSpace(d.App.Config.Scan.Baseline)
	if p == "" {
		p = scanner.DefaultBaselineFile
	}
	if filepath.IsAbs(p) {
		return "", fmt.Errorf("baseline path %q must be relative to the project root", p)
	}
	resolved, err := safepath.Resolve(d.App.Root, p)
	if err != nil {
		return "", fmt.Errorf("path %q: %w", p, err)
	}
	return resolved, nil
}

func baselineList(d Deps, path string) (*mcp.CallToolResult, error) {
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	var out strings.Builder
	fmt.Fprintf(&out, "Baseline: %s\n", path)
	fmt.Fprintf(&out, "Version: %d\n", b.Version)
	fmt.Fprintf(&out, "Entries: %d fingerprint(s), %d finding(s)\n", len(b.Fingerprints), len(b.Findings))
	if len(b.Fingerprints) == 0 && len(b.Findings) == 0 {
		out.WriteString("\nThe baseline is empty: every finding is reported.\n")
	} else {
		if len(b.Findings) > 0 {
			out.WriteString("\nFindings:\n")
			for _, f := range b.Findings {
				reason := strings.TrimSpace(f.Reason)
				if reason == "" {
					reason = "(no reason recorded)"
				}
				fmt.Fprintf(&out, "  %s  %s\n", f.ID, reason)
			}
		}
		if len(b.Fingerprints) > 0 {
			out.WriteString("\nFingerprints:\n")
			for _, fp := range b.Fingerprints {
				fmt.Fprintf(&out, "  %s\n", fp)
			}
		}
	}

	payload := map[string]any{
		"path":         path,
		"version":      b.Version,
		"fingerprints": b.Fingerprints,
		"findings":     b.Findings,
	}
	return result(d, out.String(), payload), nil
}

func baselineAdd(d Deps, path string, args baselineArgs) (*mcp.CallToolResult, error) {
	id := strings.TrimSpace(args.FindingID)
	if id == "" {
		return mcp.TextError("invalid arguments: findingId is required for baseline add"), nil
	}
	reason := strings.TrimSpace(args.Reason)
	if reason == "" {
		return mcp.TextError("invalid arguments: a reason is required for baseline add (why is this finding accepted?)"), nil
	}

	_, f, err := lookupFinding(d, args.ScanID, id)
	if err != nil {
		return errorResult(d, "%v", err), nil
	}
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	wantID := findingID(*f)
	wantFP := findingFingerprint(*f)
	hadEntry, hadFingerprint := false, false
	for _, e := range b.Findings {
		if strings.EqualFold(e.ID, wantID) {
			hadEntry = true
			break
		}
	}
	for _, fp := range b.Fingerprints {
		if strings.EqualFold(fp, wantFP) {
			hadFingerprint = true
			break
		}
	}
	b.Add(*f, reason)
	if err := scanner.SaveBaseline(path, b); err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	var out strings.Builder
	switch {
	case hadEntry:
		fmt.Fprintf(&out, "Finding %s was already in the baseline; its recorded reason was kept.\n", wantID)
	case hadFingerprint:
		fmt.Fprintf(&out, "Finding %s was already suppressed by its fingerprint; recorded an explicit entry with your reason.\n", wantID)
	default:
		fmt.Fprintf(&out, "Added %s to the baseline.\n", wantID)
	}
	fmt.Fprintf(&out, "Fingerprint: %s\n", wantFP)
	fmt.Fprintf(&out, "Reason: %s\n", reason)
	fmt.Fprintf(&out, "Path: %s\n", path)
	fmt.Fprintf(&out, "Baseline now has %d finding(s) and %d fingerprint(s).\n", len(b.Findings), len(b.Fingerprints))

	payload := map[string]any{
		"path":         path,
		"added":        !hadEntry,
		"findingId":    wantID,
		"fingerprint":  wantFP,
		"reason":       reason,
		"findings":     len(b.Findings),
		"fingerprints": len(b.Fingerprints),
	}
	return result(d, out.String(), payload), nil
}

func baselineRemove(d Deps, path string, args baselineArgs) (*mcp.CallToolResult, error) {
	id := strings.TrimSpace(args.FindingID)
	if id == "" {
		return mcp.TextError("invalid arguments: findingId is required for baseline remove"), nil
	}
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	// Resolve the finding when a scan is available so the matching fingerprint
	// is removed too: leaving it behind would keep suppressing the finding.
	fingerprint := ""
	if _, f, ferr := lookupFinding(d, args.ScanID, id); ferr == nil {
		fingerprint = findingFingerprint(*f)
	}

	removedID := ""
	keptFindings := b.Findings[:0]
	for _, e := range b.Findings {
		if strings.EqualFold(e.ID, id) {
			removedID = e.ID
			continue
		}
		keptFindings = append(keptFindings, e)
	}
	b.Findings = keptFindings

	removedFP := ""
	keptFPs := b.Fingerprints[:0]
	for _, fp := range b.Fingerprints {
		if strings.EqualFold(fp, id) || (fingerprint != "" && strings.EqualFold(fp, fingerprint)) {
			removedFP = fp
			continue
		}
		keptFPs = append(keptFPs, fp)
	}
	b.Fingerprints = keptFPs

	if removedID == "" && removedFP == "" {
		return mcp.TextError("finding %q is not in the baseline %s (%d finding(s), %d fingerprint(s)); use action=list to see the entries", id, path, len(b.Findings), len(b.Fingerprints)), nil
	}
	if err := scanner.SaveBaseline(path, b); err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	var out strings.Builder
	fmt.Fprintf(&out, "Removed from baseline %s:\n", path)
	if removedID != "" {
		fmt.Fprintf(&out, "  finding %s\n", removedID)
	}
	if removedFP != "" {
		fmt.Fprintf(&out, "  fingerprint %s\n", removedFP)
	}
	fmt.Fprintf(&out, "Baseline now has %d finding(s) and %d fingerprint(s).\n", len(b.Findings), len(b.Fingerprints))

	payload := map[string]any{
		"path":         path,
		"removedId":    removedID,
		"removedFp":    removedFP,
		"findings":     len(b.Findings),
		"fingerprints": len(b.Fingerprints),
	}
	return result(d, out.String(), payload), nil
}

func baselineClear(d Deps, path string) (*mcp.CallToolResult, error) {
	if err := scanner.SaveBaseline(path, scanner.NewBaseline()); err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}
	text := fmt.Sprintf("Cleared the baseline at %s (wrote an empty version-%d baseline). Every finding is reported again.\n",
		path, scanner.BaselineVersion)
	return result(d, text, map[string]any{"path": path, "cleared": true}), nil
}

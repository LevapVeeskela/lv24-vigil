package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
)

const (
	// maxBaselineItems bounds one batch request. Validation is all-or-nothing,
	// so a larger batch would only hold more work in memory.
	maxBaselineItems = 50
	// maxBaselineTicketRunes bounds the ticket reference stored with an
	// acceptance, after control characters are stripped.
	maxBaselineTicketRunes = 128
	// maxBaselineReasonRunes bounds a free-text acceptance reason.
	maxBaselineReasonRunes = 2000
	// maxBaselineAux bounds the legacy fingerprint and expired-entry lists
	// returned by list; their totals are reported separately.
	maxBaselineAux = 500
)

type baselineArgs struct {
	Action      string         `json:"action"`
	FindingID   string         `json:"findingId"`
	Reason      string         `json:"reason"`
	ScanID      string         `json:"scanId"`
	Ticket      string         `json:"ticket"`
	Expires     string         `json:"expires"`
	Disposition string         `json:"disposition"`
	DryRun      *bool          `json:"dryRun"`
	Confirm     bool           `json:"confirm"`
	Items       []baselineItem `json:"items"`
	Offset      int            `json:"offset"`
	Limit       int            `json:"limit"`
}

// baselineItem is one add or remove in a batch. It carries its own action so a
// single call can mix acceptances and removals.
type baselineItem struct {
	Action      string `json:"action"`
	FindingID   string `json:"findingId"`
	Reason      string `json:"reason"`
	Ticket      string `json:"ticket"`
	Expires     string `json:"expires"`
	Disposition string `json:"disposition"`
}

// baselineItemResult is the per-item outcome of a batch. Status is one of
// added, already_present, removed, not_found or error.
type baselineItemResult struct {
	FindingID string `json:"findingId"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}

// baselinePreviewCounts is the impact of a proposed baseline change on the
// latest scan. Only findings the scan currently reports as active are counted,
// so an already-accepted finding is not double counted.
type baselinePreviewCounts struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// baselinePlan is one validated batch item, resolved against a scan.
type baselinePlan struct {
	index       int
	action      string
	raw         string
	reason      string
	entry       *scanner.BaselineFinding
	resolvedID  string
	fingerprint string
}

func registerBaseline(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_baseline",
		Title: "Manage the Vigil suppression baseline",
		Description: "List, add, remove, prune or clear accepted findings in the project baseline. " +
			"Adding requires a finding ID and a reason; an acceptance can carry a ticket, an expiry date, " +
			"a disposition, and the resolved finding's path and rule scope. dryRun previews the suppression impact without writing. " +
			"Batch validates up to 50 add/remove items before writing, reports per-item misses and " +
			"defaults to dryRun=true. Removed or expired entries stop suppressing on the next scan.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"action":    mcp.PropEnum("Baseline operation. Defaults to list. prune and batch default to dryRun=true.", "list", "add", "remove", "prune", "batch", "clear"),
			"findingId": mcp.Prop("string", "Finding ID (VGL-...), fingerprint (fp_...) or a unique prefix. Required for add and remove."),
			"reason":    mcp.Prop("string", "Why the finding is accepted. Required for add."),
			"scanId":    mcp.Prop("string", "Scan to resolve findings in and to preview the suppression impact. Defaults to the most recent scan."),
			"ticket": mcp.Prop("string",
				"Ticket or issue reference stored with the acceptance. Control characters are stripped and the value is capped at 128 characters."),
			"expires": mcp.Prop("string",
				"Expiry date in YYYY-MM-DD (UTC). The entry stops suppressing the next day; a past date is rejected on add."),
			"disposition": mcp.PropEnum(
				"Why the finding is accepted. A remediated finding must be removed from the baseline instead.",
				scanner.BaselineDispositionFalsePositive, scanner.BaselineDispositionAcceptedRisk, scanner.BaselineDispositionWontFix),
			"dryRun":  mcp.PropBool("Preview the change without writing. Defaults to true for batch and prune, false for add and remove."),
			"confirm": mcp.PropBool("Required for clear: confirm that the baseline is emptied."),
			"offset":  mcp.PropInt("List: number of findings to skip. Defaults to 0."),
			"limit":   mcp.PropInt("List: findings per page (default 50, capped at 500)."),
			"items": map[string]any{
				"type":        "array",
				"description": "Batch of add/remove items (max 50). Requires action=batch. A write requires dryRun=false; any invalid item leaves the baseline untouched.",
				"maxItems":    maxBaselineItems,
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"action":      mcp.PropEnum("add or remove.", "add", "remove"),
						"findingId":   mcp.Prop("string", "Finding ID, fingerprint or unique prefix."),
						"reason":      mcp.Prop("string", "Why the finding is accepted. Required for add."),
						"ticket":      mcp.Prop("string", "Ticket or issue reference (control characters stripped, 128 characters max)."),
						"expires":     mcp.Prop("string", "Expiry date in YYYY-MM-DD (UTC); a past date is rejected on add."),
						"disposition": mcp.PropEnum("Acceptance disposition.", scanner.BaselineDispositionFalsePositive, scanner.BaselineDispositionAcceptedRisk, scanner.BaselineDispositionWontFix),
					},
					"required":             []string{"action", "findingId"},
					"additionalProperties": false,
				},
			},
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
	if action != "list" && d.ReadOnly {
		return readOnlyResult(d, "vigil_baseline "+action), nil
	}
	path, err := baselinePath(d)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	switch action {
	case "list":
		return baselineList(d, path, args)
	case "add":
		if len(args.Items) > 0 {
			return typedResult(d, toolErrorf(CodeArgs, "items is only valid with action=batch")), nil
		}
		return baselineAdd(d, path, args)
	case "remove":
		if len(args.Items) > 0 {
			return typedResult(d, toolErrorf(CodeArgs, "items is only valid with action=batch")), nil
		}
		return baselineRemove(d, path, args)
	case "prune":
		return baselinePrune(d, path, args)
	case "batch":
		return baselineBatch(d, path, args)
	case "clear":
		if !args.Confirm {
			return typedResult(d, toolErrorf(CodeArgs,
				"clear empties the baseline; pass confirm=true after checking action=list")), nil
		}
		return baselineClear(d, path)
	default:
		return typedResult(d, toolErrorf(CodeArgs,
			"action must be list, add, remove, prune, batch or clear (got %q)", args.Action)), nil
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

func baselineList(d Deps, path string, args baselineArgs) (*mcp.CallToolResult, error) {
	if err := checkOffset(args.Offset); err != nil {
		return toolErrorResult(d, err), nil
	}
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	today := scanner.BaselineToday()
	limit := clampInt(args.Limit, 50, maxFindingsCap)
	start, end, page := window(len(b.Findings), args.Offset, limit)
	visible := b.Findings[start:end]
	safeFindings := make([]scanner.BaselineFinding, len(visible))
	for i, f := range visible {
		f.ID = sanitizeBaselineText(f.ID, 200)
		f.Fingerprint = sanitizeBaselineText(f.Fingerprint, 200)
		f.Reason = sanitizeBaselineReason(f.Reason)
		f.Ticket = sanitizeBaselineTicket(f.Ticket)
		f.Path = sanitizeBaselineText(f.Path, 512)
		f.RuleID = sanitizeBaselineText(f.RuleID, 200)
		f.Expires = sanitizeBaselineText(f.Expires, 32)
		f.Disposition = sanitizeBaselineText(f.Disposition, 32)
		safeFindings[i] = f
	}

	expired := make([]string, 0)
	for _, f := range b.Findings {
		if !f.Expired(today) {
			continue
		}
		label := f.ID
		if label == "" {
			label = f.Fingerprint
		}
		if label != "" {
			expired = append(expired, sanitizeBaselineText(label, 200))
		}
	}
	expiredTotal := len(expired)
	if len(expired) > maxBaselineAux {
		expired = expired[:maxBaselineAux]
	}
	fingerprints := b.Fingerprints
	if len(fingerprints) > maxBaselineAux {
		fingerprints = fingerprints[:maxBaselineAux]
	}
	safeFingerprints := make([]string, len(fingerprints))
	for i, fp := range fingerprints {
		safeFingerprints[i] = sanitizeBaselineText(fp, 200)
	}

	var out strings.Builder
	fmt.Fprintf(&out, "Baseline: %s\n", path)
	fmt.Fprintf(&out, "Version: %d\n", b.Version)
	fmt.Fprintf(&out, "Entries: %d fingerprint(s), %d finding(s)\n", len(b.Fingerprints), len(b.Findings))
	fmt.Fprintf(&out, "Page: %s\n", pageNote(page))
	if len(b.Fingerprints) == 0 && len(b.Findings) == 0 {
		out.WriteString("\nThe baseline is empty: every finding is reported.\n")
	} else {
		if len(b.Findings) > 0 && len(visible) == 0 {
			fmt.Fprintf(&out, "\nNo findings in this window; the baseline has %d finding(s).\n", len(b.Findings))
		}
		if len(visible) > 0 {
			out.WriteString("\nFindings:\n")
			for _, f := range safeFindings {
				label := f.ID
				if label == "" {
					label = f.Fingerprint
				}
				fmt.Fprintf(&out, "  %s  %s", oneLine(label), baselineReasonText(f))
				if f.Ticket != "" {
					fmt.Fprintf(&out, "  ticket=%s", sanitizeBaselineTicket(f.Ticket))
				}
				isExpired := f.Expired(today)
				if f.Expires != "" {
					fmt.Fprintf(&out, "  expires=%s", oneLine(f.Expires))
					if isExpired {
						out.WriteString(" (expired)")
					}
				}
				if f.Disposition != "" {
					fmt.Fprintf(&out, "  disposition=%s", oneLine(f.Disposition))
				}
				if f.Path != "" {
					fmt.Fprintf(&out, "  path=%s", oneLine(f.Path))
				}
				if f.RuleID != "" {
					fmt.Fprintf(&out, "  rule=%s", oneLine(f.RuleID))
				}
				out.WriteString("\n")
			}
		}
		if len(b.Fingerprints) > 0 {
			out.WriteString("\nFingerprints:\n")
			for _, fp := range safeFingerprints {
				fmt.Fprintf(&out, "  %s\n", fp)
			}
			if len(b.Fingerprints) > len(fingerprints) {
				fmt.Fprintf(&out, "  … and %d more fingerprint(s); the payload reports the total.\n", len(b.Fingerprints)-len(fingerprints))
			}
		}
	}
	if expiredTotal > 0 {
		fmt.Fprintf(&out, "\n%d expired entr%s no longer suppresses findings; action=prune removes %s.\n",
			expiredTotal, pluralWord(expiredTotal, "y", "ies"), pluralWord(expiredTotal, "it", "them"))
		if expiredTotal > len(expired) {
			fmt.Fprintf(&out, "Only the first %d expired entries are listed; the payload reports the total.\n", len(expired))
		}
	}

	payload := map[string]any{
		"path":              path,
		"version":           b.Version,
		"today":             today.Format(scanner.BaselineDateLayout),
		"fingerprints":      safeFingerprints,
		"fingerprintsTotal": len(b.Fingerprints),
		"findings":          safeFindings,
		"findingsTotal":     len(b.Findings),
		"page":              page,
		"expired":           expired,
		"expiredTotal":      expiredTotal,
	}
	return result(d, out.String(), payload), nil
}

func baselineAdd(d Deps, path string, args baselineArgs) (*mcp.CallToolResult, error) {
	id := strings.TrimSpace(args.FindingID)
	if id == "" {
		return typedResult(d, toolErrorf(CodeArgs, "findingId is required for baseline add")), nil
	}
	reason := sanitizeBaselineReason(args.Reason)
	if reason == "" {
		return typedResult(d, toolErrorf(CodeArgs, "a reason is required for baseline add (why is this finding accepted?)")), nil
	}
	ticket := sanitizeBaselineTicket(args.Ticket)
	expires, err := baselineExpiryArg(args.Expires, true)
	if err != nil {
		return toolErrorResult(d, err), nil
	}
	disposition, err := baselineDispositionArg(args.Disposition)
	if err != nil {
		return toolErrorResult(d, err), nil
	}

	_, f, lookupErr := lookupFinding(d, args.ScanID, id)
	if lookupErr != nil {
		return errorResult(d, "%v", lookupErr), nil
	}
	entry := baselineEntryFor(*f, reason, ticket, expires, disposition)

	b, err := scanner.LoadBaseline(path)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}
	hadEntry, hadFingerprint := baselineHasEntry(b, entry.ID, entry.Fingerprint)
	b.AddEntry(entry)
	stored := entry
	if found := findBaselineEntry(b, entry.ID, entry.Fingerprint); found != nil {
		stored = *found
	}

	dryRun := args.DryRun != nil && *args.DryRun
	if !dryRun {
		if err := scanner.SaveBaseline(path, b); err != nil {
			return errorResult(d, "baseline: %v", err), nil
		}
	}

	counts, warnings := baselineSuppressionPreview(d, b, args.ScanID)
	until := latestBaselineExpiry(b.Findings)

	var out strings.Builder
	displayID := sanitizeBaselineText(entry.ID, 200)
	if dryRun {
		fmt.Fprintf(&out, "Would add %s to the baseline (dry run: nothing was written).\n", displayID)
	} else {
		switch {
		case hadEntry:
			fmt.Fprintf(&out, "Added %s to the baseline (it was already there; its recorded reason was kept).\n", displayID)
		case hadFingerprint:
			fmt.Fprintf(&out, "Added %s to the baseline (already suppressed by its fingerprint; recorded an explicit entry with your reason).\n", displayID)
		default:
			fmt.Fprintf(&out, "Added %s to the baseline.\n", displayID)
		}
	}
	fmt.Fprintf(&out, "Fingerprint: %s\n", sanitizeBaselineText(entry.Fingerprint, 200))
	fmt.Fprintf(&out, "Reason: %s\n", sanitizeBaselineReason(stored.Reason))
	if stored.Ticket != "" {
		fmt.Fprintf(&out, "Ticket: %s\n", sanitizeBaselineTicket(stored.Ticket))
	}
	if stored.Expires != "" {
		fmt.Fprintf(&out, "Expires: %s\n", oneLine(stored.Expires))
	}
	if stored.Disposition != "" {
		fmt.Fprintf(&out, "Disposition: %s\n", oneLine(stored.Disposition))
	}
	if stored.Path != "" {
		fmt.Fprintf(&out, "Path: %s\n", oneLine(stored.Path))
	}
	fmt.Fprintf(&out, "Baseline now has %d finding(s) and %d fingerprint(s).\n", len(b.Findings), len(b.Fingerprints))
	out.WriteString(baselinePreviewText(counts, until, warnings))

	payload := map[string]any{
		"path":          path,
		"dryRun":        dryRun,
		"saved":         !dryRun,
		"added":         !hadEntry,
		"findingId":     displayID,
		"fingerprint":   sanitizeBaselineText(entry.Fingerprint, 200),
		"reason":        sanitizeBaselineReason(stored.Reason),
		"ticket":        sanitizeBaselineTicket(stored.Ticket),
		"expires":       stored.Expires,
		"disposition":   stored.Disposition,
		"findings":      len(b.Findings),
		"fingerprints":  len(b.Fingerprints),
		"wouldSuppress": counts,
		"until":         until,
		"warnings":      warnings,
	}
	return result(d, out.String(), payload), nil
}

func baselineRemove(d Deps, path string, args baselineArgs) (*mcp.CallToolResult, error) {
	id := strings.TrimSpace(args.FindingID)
	if id == "" {
		return typedResult(d, toolErrorf(CodeArgs, "findingId is required for baseline remove")), nil
	}
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	// Resolve the finding when a scan is available. A prefix is resolved to the
	// full ID and fingerprint there, which is what lets remove delete both the
	// named entry and its fingerprint mirror.
	resolvedID, fingerprint := "", ""
	if _, f, ferr := lookupFinding(d, args.ScanID, id); ferr == nil {
		resolvedID, fingerprint = findingID(*f), findingFingerprint(*f)
	}

	removedIDs, removedFPs := removeBaselineAcceptance(b, id, resolvedID, fingerprint)
	if len(removedIDs) == 0 && len(removedFPs) == 0 {
		return typedResult(d, toolErrorf(CodeNotFound,
			"finding %q is not in the baseline %s (%d finding(s), %d fingerprint(s)); use action=list to see the entries",
			id, path, len(b.Findings), len(b.Fingerprints))), nil
	}

	dryRun := args.DryRun != nil && *args.DryRun
	if !dryRun {
		if err := scanner.SaveBaseline(path, b); err != nil {
			return errorResult(d, "baseline: %v", err), nil
		}
	}

	counts, warnings := baselineSuppressionPreview(d, b, args.ScanID)
	until := latestBaselineExpiry(b.Findings)

	var out strings.Builder
	if dryRun {
		fmt.Fprintf(&out, "Would remove from baseline %s (dry run: nothing was written):\n", path)
	} else {
		fmt.Fprintf(&out, "Removed from baseline %s:\n", path)
	}
	for _, removedID := range removedIDs {
		fmt.Fprintf(&out, "  finding %s\n", sanitizeBaselineText(removedID, 200))
	}
	for _, removedFP := range removedFPs {
		fmt.Fprintf(&out, "  fingerprint %s\n", sanitizeBaselineText(removedFP, 200))
	}
	fmt.Fprintf(&out, "Baseline now has %d finding(s) and %d fingerprint(s).\n", len(b.Findings), len(b.Fingerprints))
	out.WriteString(baselinePreviewText(counts, until, warnings))

	payload := map[string]any{
		"path":                path,
		"dryRun":              dryRun,
		"saved":               !dryRun,
		"removedId":           firstString(removedIDs),
		"removedFp":           firstString(removedFPs),
		"removedIds":          removedIDs,
		"removedFingerprints": removedFPs,
		"findings":            len(b.Findings),
		"fingerprints":        len(b.Fingerprints),
		"wouldSuppress":       counts,
		"until":               until,
		"warnings":            warnings,
	}
	return result(d, out.String(), payload), nil
}

func baselinePrune(d Deps, path string, args baselineArgs) (*mcp.CallToolResult, error) {
	dryRun := true
	if args.DryRun != nil {
		dryRun = *args.DryRun
	}
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}
	removed := b.PruneExpired(scanner.BaselineToday())
	if removed == nil {
		removed = []scanner.BaselineFinding{}
	}
	if !dryRun && len(removed) > 0 {
		if err := scanner.SaveBaseline(path, b); err != nil {
			return errorResult(d, "baseline: %v", err), nil
		}
	}

	counts, warnings := baselineSuppressionPreview(d, b, args.ScanID)
	until := latestBaselineExpiry(b.Findings)

	safeRemoved := make([]scanner.BaselineFinding, len(removed))
	for i, entry := range removed {
		entry.ID = sanitizeBaselineText(entry.ID, 200)
		entry.Fingerprint = sanitizeBaselineText(entry.Fingerprint, 200)
		entry.Reason = sanitizeBaselineReason(entry.Reason)
		entry.Ticket = sanitizeBaselineTicket(entry.Ticket)
		entry.Path = sanitizeBaselineText(entry.Path, 512)
		entry.RuleID = sanitizeBaselineText(entry.RuleID, 200)
		entry.Expires = sanitizeBaselineText(entry.Expires, 32)
		safeRemoved[i] = entry
	}

	var out strings.Builder
	if dryRun {
		fmt.Fprintf(&out, "Would prune %d expired baseline entr%s from %s (dry run: nothing was written).\n",
			len(safeRemoved), pluralWord(len(safeRemoved), "y", "ies"), path)
	} else {
		fmt.Fprintf(&out, "Pruned %d expired baseline entr%s from %s.\n",
			len(safeRemoved), pluralWord(len(safeRemoved), "y", "ies"), path)
	}
	for _, entry := range safeRemoved {
		label := entry.ID
		if label == "" {
			label = entry.Fingerprint
		}
		fmt.Fprintf(&out, "  %s  expired %s\n", label, entry.Expires)
	}
	fmt.Fprintf(&out, "Remaining: %d finding(s), %d fingerprint(s).\n", len(b.Findings), len(b.Fingerprints))
	out.WriteString(baselinePreviewText(counts, until, warnings))

	payload := map[string]any{
		"path":          path,
		"dryRun":        dryRun,
		"saved":         !dryRun && len(removed) > 0,
		"pruned":        len(removed),
		"removed":       safeRemoved,
		"remaining":     len(b.Findings),
		"fingerprints":  len(b.Fingerprints),
		"wouldSuppress": counts,
		"until":         until,
		"warnings":      warnings,
	}
	return result(d, out.String(), payload), nil
}

func baselineBatch(d Deps, path string, args baselineArgs) (*mcp.CallToolResult, error) {
	if len(args.Items) == 0 {
		return typedResult(d, toolErrorf(CodeArgs, "items is required for action=batch")), nil
	}
	if len(args.Items) > maxBaselineItems {
		return typedResult(d, toolErrorf(CodeArgs,
			"batch accepts at most %d items (got %d)", maxBaselineItems, len(args.Items))), nil
	}
	dryRun := true
	if args.DryRun != nil {
		dryRun = *args.DryRun
	}
	b, err := scanner.LoadBaseline(path)
	if err != nil {
		return errorResult(d, "baseline: %v", err), nil
	}

	// Phase 1: validate every item before touching the baseline, so one bad
	// argument cannot leave a half-applied batch on disk.
	plans := make([]baselinePlan, 0, len(args.Items))
	for i, item := range args.Items {
		action := strings.ToLower(strings.TrimSpace(item.Action))
		if action != "add" && action != "remove" {
			return typedResult(d, toolErrorf(CodeArgs,
				"items[%d].action must be add or remove (got %q)", i, item.Action)), nil
		}
		raw := strings.TrimSpace(item.FindingID)
		if raw == "" {
			return typedResult(d, toolErrorf(CodeArgs, "items[%d].findingId is required", i)), nil
		}
		plan := baselinePlan{index: i, action: action, raw: raw}
		if action == "add" {
			reason := sanitizeBaselineReason(item.Reason)
			if reason == "" {
				return typedResult(d, toolErrorf(CodeArgs,
					"items[%d]: a reason is required for baseline add (why is this finding accepted?)", i)), nil
			}
			expires, err := baselineExpiryArg(item.Expires, true)
			if err != nil {
				return typedResult(d, prefixedToolError(err, fmt.Sprintf("items[%d].expires", i))), nil
			}
			disposition, err := baselineDispositionArg(item.Disposition)
			if err != nil {
				return typedResult(d, prefixedToolError(err, fmt.Sprintf("items[%d].disposition", i))), nil
			}
			plan.reason = reason
			plan.entry = &scanner.BaselineFinding{
				Reason:      reason,
				Ticket:      sanitizeBaselineTicket(item.Ticket),
				Expires:     expires,
				Disposition: disposition,
			}
		}
		plans = append(plans, plan)
	}

	// Phase 2: resolve each item. A missing finding is a per-item error, not a
	// request-level argument error.
	results := make([]baselineItemResult, len(args.Items))
	for i := range results {
		results[i].FindingID = oneLine(strings.TrimSpace(args.Items[i].FindingID))
	}
	itemFailures := 0
	for pi := range plans {
		plan := &plans[pi]
		if plan.action == "add" {
			_, f, lookupErr := lookupFinding(d, args.ScanID, plan.raw)
			if lookupErr != nil {
				results[plan.index].Status = "error"
				results[plan.index].Message = oneLine(lookupErr.Error())
				itemFailures++
				continue
			}
			entry := baselineEntryFor(*f, plan.reason, plan.entry.Ticket, plan.entry.Expires, plan.entry.Disposition)
			plan.entry = &entry
			plan.resolvedID, plan.fingerprint = entry.ID, entry.Fingerprint
			continue
		}
		if _, f, lookupErr := lookupFinding(d, args.ScanID, plan.raw); lookupErr == nil {
			plan.resolvedID, plan.fingerprint = findingID(*f), findingFingerprint(*f)
		}
	}

	if itemFailures > 0 {
		for i := range results {
			if results[i].Status == "error" {
				continue
			}
			results[i].Status = "error"
			results[i].Message = "not applied: the batch was rejected because another item failed"
		}
		return baselineBatchResult(d, path, b, dryRun, results, nil, false, args.ScanID)
	}

	// Phase 3: mutate in memory in item order and save once.
	addedEntries := make([]scanner.BaselineFinding, 0, len(plans))
	for _, plan := range plans {
		switch plan.action {
		case "add":
			hadEntry, hadFingerprint := baselineHasEntry(b, plan.entry.ID, plan.entry.Fingerprint)
			b.AddEntry(*plan.entry)
			addedEntries = append(addedEntries, *plan.entry)
			switch {
			case hadEntry:
				results[plan.index].Status = "already_present"
				results[plan.index].Message = "the recorded reason was kept"
			case hadFingerprint:
				results[plan.index].Status = "added"
				results[plan.index].Message = "already suppressed by fingerprint; recorded an explicit entry"
			default:
				results[plan.index].Status = "added"
			}
		case "remove":
			removedIDs, removedFPs := removeBaselineAcceptance(b, plan.raw, plan.resolvedID, plan.fingerprint)
			if len(removedIDs) == 0 && len(removedFPs) == 0 {
				results[plan.index].Status = "not_found"
				results[plan.index].Message = "not in the baseline"
				continue
			}
			results[plan.index].Status = "removed"
			results[plan.index].Message = removalMessage(removedIDs, removedFPs)
		}
	}

	saved := false
	if !dryRun {
		if err := scanner.SaveBaseline(path, b); err != nil {
			return errorResult(d, "baseline: %v", err), nil
		}
		saved = true
	}

	untilEntries := addedEntries
	if len(untilEntries) == 0 {
		untilEntries = b.Findings
	}
	return baselineBatchResult(d, path, b, dryRun, results, untilEntries, saved, args.ScanID)
}

// baselineBatchResult renders the shared batch payload and text.
func baselineBatchResult(d Deps, path string, b *scanner.Baseline, dryRun bool, results []baselineItemResult, untilEntries []scanner.BaselineFinding, saved bool, scanID string) (*mcp.CallToolResult, error) {
	counts, warnings := baselineSuppressionPreview(d, b, scanID)
	until := latestBaselineExpiry(untilEntries)
	if len(untilEntries) == 0 {
		until = latestBaselineExpiry(b.Findings)
	}

	var out strings.Builder
	switch {
	case saved:
		fmt.Fprintf(&out, "Applied %d baseline item(s) to %s.\n", len(results), path)
	case dryRun:
		fmt.Fprintf(&out, "Batch baseline preview (dry run: nothing was written):\n")
	default:
		fmt.Fprintf(&out, "Batch baseline update was rejected; nothing was written to %s:\n", path)
	}
	for _, res := range results {
		line := fmt.Sprintf("  %s  %s", res.FindingID, res.Status)
		if res.Message != "" {
			line += ": " + res.Message
		}
		fmt.Fprintf(&out, "%s\n", line)
	}
	fmt.Fprintf(&out, "Baseline now has %d finding(s) and %d fingerprint(s).\n", len(b.Findings), len(b.Fingerprints))
	out.WriteString(baselinePreviewText(counts, until, warnings))

	payload := map[string]any{
		"path":          path,
		"dryRun":        dryRun,
		"saved":         saved,
		"results":       results,
		"findings":      len(b.Findings),
		"fingerprints":  len(b.Fingerprints),
		"wouldSuppress": counts,
		"until":         until,
		"warnings":      warnings,
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

// baselineEntryFor builds the acceptance stored by add and batch - add.
func baselineEntryFor(f model.Finding, reason, ticket, expires, disposition string) scanner.BaselineFinding {
	return scanner.BaselineFinding{
		ID:          findingID(f),
		Fingerprint: findingFingerprint(f),
		RuleID:      strings.TrimSpace(f.RuleID),
		Path:        f.Location.Path,
		Reason:      reason,
		Ticket:      ticket,
		Expires:     expires,
		Disposition: disposition,
	}
}

// baselineHasEntry reports whether the baseline already carries the finding by
// ID or fingerprint. It must run before AddEntry, which merges the new entry.
func baselineHasEntry(b *scanner.Baseline, id, fingerprint string) (hadEntry, hadFingerprint bool) {
	for _, entry := range b.Findings {
		if id != "" && strings.EqualFold(entry.ID, id) {
			hadEntry = true
		}
		if fingerprint != "" && strings.EqualFold(entry.Fingerprint, fingerprint) {
			hadFingerprint = true
		}
	}
	for _, fp := range b.Fingerprints {
		if fingerprint != "" && strings.EqualFold(fp, fingerprint) {
			hadFingerprint = true
		}
	}
	return hadEntry, hadFingerprint
}

// findBaselineEntry returns the stored entry for id/fingerprint, if any.
func findBaselineEntry(b *scanner.Baseline, id, fingerprint string) *scanner.BaselineFinding {
	for i := range b.Findings {
		entry := &b.Findings[i]
		if id != "" && strings.EqualFold(entry.ID, id) {
			return entry
		}
		if fingerprint != "" && strings.EqualFold(entry.Fingerprint, fingerprint) {
			return entry
		}
	}
	return nil
}

// removeBaselineAcceptance deletes every acceptance that identifies the
// requested finding: entries whose ID is the raw value or the scan-resolved ID,
// entries whose fingerprint is the raw value or the scan-resolved fingerprint,
// and fingerprint-only mirrors of removed entries. It also drops the matching
// top-level compatibility fingerprints. The returned slices list what was
// removed so a caller can report it accurately.
func removeBaselineAcceptance(b *scanner.Baseline, raw, resolvedID, fingerprint string) ([]string, []string) {
	matches := func(entry scanner.BaselineFinding) bool {
		if entry.ID != "" && (strings.EqualFold(entry.ID, raw) || (resolvedID != "" && strings.EqualFold(entry.ID, resolvedID))) {
			return true
		}
		if entry.Fingerprint != "" && (strings.EqualFold(entry.Fingerprint, raw) || (fingerprint != "" && strings.EqualFold(entry.Fingerprint, fingerprint))) {
			return true
		}
		return false
	}

	matched := make([]scanner.BaselineFinding, 0, 2)
	kept := make([]scanner.BaselineFinding, 0, len(b.Findings))
	for _, entry := range b.Findings {
		if matches(entry) {
			matched = append(matched, entry)
			continue
		}
		kept = append(kept, entry)
	}

	// A removed entry can be mirrored by a separate fingerprint-only entry;
	// leaving that behind keeps the finding accepted.
	if len(matched) > 0 {
		removeSet := make(map[string]bool, len(matched))
		for _, entry := range matched {
			if entry.Fingerprint != "" {
				removeSet[strings.ToLower(entry.Fingerprint)] = true
			}
		}
		mirrors := kept[:0]
		for _, entry := range kept {
			if entry.Fingerprint != "" && removeSet[strings.ToLower(entry.Fingerprint)] {
				matched = append(matched, entry)
				continue
			}
			mirrors = append(mirrors, entry)
		}
		b.Findings = mirrors
	} else {
		b.Findings = kept
	}

	removedIDs := make([]string, 0, len(matched))
	removedFPs := make([]string, 0, len(matched))
	drop := map[string]bool{strings.ToLower(raw): true}
	if fingerprint != "" {
		drop[strings.ToLower(fingerprint)] = true
	}
	for _, entry := range matched {
		if entry.ID != "" {
			removedIDs = append(removedIDs, entry.ID)
		}
		if entry.Fingerprint != "" {
			removedFPs = append(removedFPs, entry.Fingerprint)
			drop[strings.ToLower(entry.Fingerprint)] = true
		}
	}
	keptFPs := b.Fingerprints[:0]
	for _, fp := range b.Fingerprints {
		if !drop[strings.ToLower(fp)] {
			keptFPs = append(keptFPs, fp)
		}
	}
	b.Fingerprints = keptFPs
	return removedIDs, removedFPs
}

// baselineSuppressionPreview counts the findings of a scan that the proposed
// baseline still suppresses. A missing scan is not an error: previews stay
// available, with a warning instead of counts.
func baselineSuppressionPreview(d Deps, b *scanner.Baseline, scanID string) (baselinePreviewCounts, []string) {
	counts := baselinePreviewCounts{}
	res, err := loadScan(d, scanID)
	if err != nil {
		return counts, []string{"no stored scan: suppression counts are unavailable; run vigil_scan first"}
	}
	for _, f := range res.Findings {
		if !b.MatchFinding(f).Matched {
			continue
		}
		counts.Total++
		switch f.Severity {
		case model.SeverityCritical:
			counts.Critical++
		case model.SeverityHigh:
			counts.High++
		case model.SeverityMedium:
			counts.Medium++
		case model.SeverityLow:
			counts.Low++
		}
	}
	return counts, nil
}

func baselinePreviewText(counts baselinePreviewCounts, until string, warnings []string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Suppression preview: %d finding(s) in the latest scan (critical %d, high %d, medium %d, low %d).\n",
		counts.Total, counts.Critical, counts.High, counts.Medium, counts.Low)
	fmt.Fprintf(&out, "Acceptance valid until: %s.\n", until)
	for _, warning := range warnings {
		fmt.Fprintf(&out, "Warning: %s.\n", oneLine(warning))
	}
	return out.String()
}

// latestBaselineExpiry returns the latest explicit expiry among entries, or
// "never" when none of them expires.
func latestBaselineExpiry(entries []scanner.BaselineFinding) string {
	latest := ""
	for _, entry := range entries {
		if entry.Expires == "" {
			continue
		}
		if latest == "" || entry.Expires > latest {
			latest = entry.Expires
		}
	}
	if latest == "" {
		return "never"
	}
	return latest
}

// baselineExpiryArg validates an expiry argument and returns the canonical
// date. rejectPast is set for acceptances: an already-expired acceptance is a
// mistake, while a stored expired entry is pruned instead.
func baselineExpiryArg(value string, rejectPast bool) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", nil
	}
	date, err := scanner.ParseBaselineDate(v)
	if err != nil {
		return "", toolErrorf(CodeArgs, "expires: %v", err)
	}
	if rejectPast {
		today := scanner.BaselineToday()
		if date.Before(today) {
			return "", toolErrorf(CodeArgs, "expires %s is in the past (today is %s)",
				date.Format(scanner.BaselineDateLayout), today.Format(scanner.BaselineDateLayout))
		}
	}
	return date.Format(scanner.BaselineDateLayout), nil
}

// baselineDispositionArg validates an acceptance disposition.
func baselineDispositionArg(value string) (string, error) {
	disposition, err := scanner.ParseBaselineDisposition(value)
	if err != nil {
		return "", toolErrorf(CodeArgs, "disposition: %v", err)
	}
	return disposition, nil
}

// prefixedToolError adds a field name to a typed argument error.
func prefixedToolError(err error, field string) *ToolError {
	te := asToolError(err)
	if te == nil {
		return toolErrorf(CodeArgs, "%s: %v", field, err)
	}
	return toolErrorf(CodeArgs, "%s: %s", field, te.Message)
}

// sanitizeBaselineTicket strips control characters and caps the ticket at 128
// characters so untrusted input cannot inject structure into reports.
func sanitizeBaselineTicket(value string) string {
	return sanitizeBaselineText(value, maxBaselineTicketRunes)
}

// sanitizeBaselineReason strips control characters and caps a free-text reason
// so a baseline file cannot inject lines or Markdown into a tool response.
func sanitizeBaselineReason(value string) string {
	return sanitizeBaselineText(value, maxBaselineReasonRunes)
}

func sanitizeBaselineText(value string, max int) string {
	stripped := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	stripped = strings.TrimSpace(stripped)
	if stripped == "" {
		return ""
	}
	runes := []rune(stripped)
	if len(runes) > max {
		return string(runes[:max])
	}
	return stripped
}

func baselineReasonText(entry scanner.BaselineFinding) string {
	reason := sanitizeBaselineReason(entry.Reason)
	if reason == "" {
		return "(no reason recorded)"
	}
	return truncateRunes(reason, 300)
}

func removalMessage(ids, fingerprints []string) string {
	parts := make([]string, 0, 2)
	if len(ids) > 0 {
		parts = append(parts, "finding "+ids[0])
	}
	if len(fingerprints) > 0 {
		parts = append(parts, "fingerprint "+fingerprints[0])
	}
	if len(parts) == 0 {
		return ""
	}
	return "removed " + strings.Join(parts, " and ")
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func pluralWord(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

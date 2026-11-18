package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

// Fix modes. apply=true is the deprecated 0.10 spelling of mode=apply.
const (
	fixModePropose = "propose"
	fixModeApply   = "apply"
)

type fixArgs struct {
	FindingID  string `json:"findingId"`
	Path       string `json:"path"`
	Line       int    `json:"line"`
	ScanID     string `json:"scanId"`
	Apply      bool   `json:"apply"`
	Mode       string `json:"mode"`
	FixID      string `json:"fixId"`
	DiffSHA256 string `json:"diffSha256"`
}

func registerFix(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_fix",
		Title: "Propose or apply a fix for a Vigil finding",
		Description: "Propose a validated unified diff for one finding, then apply exactly that diff after a " +
			"human reviewed it. mode=propose (the default) writes nothing and returns fixId, diffSha256 and " +
			"expiresAt. mode=apply requires those values, verifies every target file is unchanged and applies " +
			"the stored diff to the working tree; it never commits. apply=true is a deprecated alias for " +
			"mode=apply and is unbound only when the server enables the unsafe escape hatch.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"findingId":  mcp.Prop("string", "Finding ID (VGL-...), fingerprint (fp_...) or a unique prefix."),
			"path":       mcp.Prop("string", "Repository-relative path of the finding; use with line instead of findingId."),
			"line":       mcp.PropInt("Line number within path. Omit to match the only finding on that path."),
			"scanId":     mcp.Prop("string", "Scan to look in. Defaults to the most recent scan."),
			"mode":       mcp.PropEnum("propose returns a diff and a fixId without writing; apply applies a reviewed proposal.", fixModePropose, fixModeApply),
			"fixId":      mcp.Prop("string", "Proposal ID returned by mode=propose. Required for mode=apply."),
			"diffSha256": mcp.Prop("string", "SHA-256 of the proposed diff. Required for mode=apply."),
			"apply":      mcp.PropBool("Deprecated: true means mode=apply and still needs fixId and diffSha256. Defaults to false."),
		}),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleFix(ctx, d, raw)
		},
	})
}

func handleFix(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	if d.ReadOnly {
		return readOnlyResult(d, "vigil_fix"), nil
	}
	if d.Offline {
		return offlineResult(d, "vigil_fix"), nil
	}
	var args fixArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}
	mode, err := fixMode(args)
	if err != nil {
		return toolErrorResult(d, err), nil
	}
	if mode == fixModeApply {
		if strings.TrimSpace(args.FixID) == "" || strings.TrimSpace(args.DiffSHA256) == "" {
			if !d.UnsafeUnboundFix {
				return typedResult(d, toolErrorf(CodeFixUnbound,
					"mode=apply needs the fixId and diffSha256 returned by mode=propose. Propose the fix first, "+
						"show the diff to the user, then apply that exact proposal. Proposing and applying in one "+
						"call is disabled; pass --unsafe-unbound-fix only for a deliberate 0.10 compatibility run.")), nil
			}
			return proposeAndApplyUnbound(ctx, d, args), nil
		}
		return applyStoredProposal(ctx, d, args), nil
	}
	return proposeFix(ctx, d, args), nil
}

// fixMode resolves mode and the deprecated apply flag. An explicit mode wins,
// but asking for propose and apply at the same time is a caller bug.
func fixMode(args fixArgs) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(args.Mode))
	switch mode {
	case "":
		if args.Apply {
			return fixModeApply, nil
		}
		return fixModePropose, nil
	case fixModePropose:
		if args.Apply {
			return "", toolErrorf(CodeArgs, "mode=propose conflicts with apply=true; omit apply or use mode=apply")
		}
		return fixModePropose, nil
	case fixModeApply:
		return fixModeApply, nil
	default:
		return "", toolErrorf(CodeArgs, "mode %q is not supported (use propose or apply)", args.Mode)
	}
}

// proposeFix generates a diff, binds it to a pending proposal and returns the
// review handle. It never writes source files.
func proposeFix(ctx context.Context, d Deps, args fixArgs) *mcp.CallToolResult {
	scan, f, _, err := resolveFinding(d, args.ScanID, findingRef{
		FindingID: args.FindingID,
		Path:      args.Path,
		Line:      args.Line,
	})
	if err != nil {
		return toolErrorResult(d, err)
	}
	if err := deterministicFixGate(scan, *f); err != nil {
		return toolErrorResult(d, err)
	}
	if !d.App.LLM {
		return mcp.TextError("vigil_fix needs a model: set VIGIL_PROVIDER, VIGIL_MODEL and VIGIL_API_KEY (or a local OLLAMA_HOST). " +
			"Use vigil_explain for the deterministic remediation in the meantime.")
	}

	fix, err := d.App.ProposeFix(ctx, *f)
	if err != nil {
		return errorResult(d, "fix proposal failed: %v", err)
	}
	if fix == nil || strings.TrimSpace(fix.Diff) == "" {
		return errorResult(d, "the model did not return an applicable diff for %s; fix it manually or ask again with more context.", findingID(*f))
	}
	targets, err := targetsFromDiff(d.App.Root, fix.Diff)
	if err != nil {
		return toolErrorResult(d, err)
	}

	createdAt := time.Now().UTC()
	proposal := &pendingProposal{
		Version:     pendingProposalVersion,
		FixID:       proposalID(fix.Diff, createdAt),
		FindingID:   findingID(*f),
		ScanID:      scan.ID,
		Root:        d.App.Root,
		Description: fix.Description,
		Diff:        fix.Diff,
		DiffSHA256:  sha256Hex(fix.Diff),
		Files:       fix.Files,
		Targets:     targets,
		CreatedAt:   createdAt,
		ExpiresAt:   createdAt.Add(pendingProposalTTL),
	}
	if err := savePending(d.App.Root, proposal); err != nil {
		return errorResult(d, "fix proposal could not be stored: %v", err)
	}
	cleanupPending(d.App.Root, createdAt)

	payload := map[string]any{
		"scanId":     scan.ID,
		"findingId":  findingID(*f),
		"mode":       fixModePropose,
		"fixId":      proposal.FixID,
		"diffSha256": proposal.DiffSHA256,
		"expiresAt":  proposal.ExpiresAt,
		"targets":    proposal.Targets,
		"applied":    false,
		"fix":        fix,
	}
	return result(d, proposalMarkdown(*f, fix, proposal), payload)
}

// applyStoredProposal applies only the diff stored for a reviewed proposal.
// The model is never called and the diff is never regenerated.
func applyStoredProposal(ctx context.Context, d Deps, args fixArgs) *mcp.CallToolResult {
	proposal, err := loadPending(d.App.Root, strings.TrimSpace(args.FixID))
	if err != nil {
		return toolErrorResult(d, err)
	}
	if !samePath(proposal.Root, d.App.Root) {
		return toolErrorResult(d, toolErrorf(CodeFileChanged,
			"proposal %s was created for %s but this server is rooted at %s; apply it from the repository it was proposed in",
			proposal.FixID, proposal.Root, d.App.Root))
	}
	if scanID := strings.TrimSpace(args.ScanID); scanID != "" && !strings.EqualFold(scanID, proposal.ScanID) {
		return toolErrorResult(d, toolErrorf(CodeFixMismatch,
			"proposal %s belongs to scan %s, not %s", proposal.FixID, proposal.ScanID, scanID))
	}

	scan, f, err := lookupFinding(d, proposal.ScanID, proposal.FindingID)
	if err != nil {
		return toolErrorResult(d, toolErrorf(CodeFixNotFound,
			"proposal %s refers to finding %s, which is no longer in scan %s: %v",
			proposal.FixID, proposal.FindingID, proposal.ScanID, err))
	}
	if !strings.EqualFold(findingID(*f), proposal.FindingID) {
		return toolErrorResult(d, toolErrorf(CodeFixMismatch,
			"proposal %s belongs to finding %s, not %s", proposal.FixID, proposal.FindingID, findingID(*f)))
	}
	if requested := strings.TrimSpace(args.FindingID); requested != "" {
		if _, requestedFinding, rerr := lookupFinding(d, proposal.ScanID, requested); rerr != nil {
			return toolErrorResult(d, rerr)
		} else if !strings.EqualFold(findingID(*requestedFinding), proposal.FindingID) {
			return toolErrorResult(d, toolErrorf(CodeFixMismatch,
				"proposal %s belongs to finding %s, not %s", proposal.FixID, proposal.FindingID, findingID(*requestedFinding)))
		}
	}
	if err := deterministicFixGate(scan, *f); err != nil {
		return toolErrorResult(d, err)
	}

	now := time.Now().UTC()
	if err := pendingUsable(proposal, now); err != nil {
		return toolErrorResult(d, err)
	}
	if got := strings.TrimSpace(args.DiffSHA256); got != proposal.DiffSHA256 {
		return toolErrorResult(d, toolErrorf(CodeFixMismatch,
			"diffSha256 %q does not match proposal %s; use the value returned by mode=propose",
			got, proposal.FixID))
	}
	if err := verifyPendingTargets(d.App.Root, proposal); err != nil {
		return toolErrorResult(d, err)
	}

	release, err := claimPending(d.App.Root, proposal.FixID)
	if err != nil {
		return toolErrorResult(d, err)
	}
	defer release()

	if err := markPendingConsumed(d.App.Root, proposal, now); err != nil {
		return errorResult(d, "%v", err)
	}
	fix := &model.Fix{
		Description: proposal.Description,
		Diff:        proposal.Diff,
		Files:       proposal.Files,
	}
	if err := d.App.ApplyFix(ctx, fix); err != nil {
		return toolErrorResult(d, toolErrorf(CodeFixConsumed,
			"applying proposal %s failed: %v. The proposal is now consumed and cannot be retried; propose the fix again.",
			proposal.FixID, err))
	}

	payload := map[string]any{
		"scanId":          scan.ID,
		"findingId":       findingID(*f),
		"applied":         true,
		"fixId":           proposal.FixID,
		"diffSha256":      proposal.DiffSHA256,
		"verifiedTargets": sortedKeys(proposal.Targets),
	}
	return result(d, appliedMarkdown(*f, fix, proposal), payload)
}

// proposeAndApplyUnbound is the deprecated 0.10 path: propose then apply in one
// call. It requires the explicit --unsafe-unbound-fix opt-in and always warns.
func proposeAndApplyUnbound(ctx context.Context, d Deps, args fixArgs) *mcp.CallToolResult {
	scan, f, _, err := resolveFinding(d, args.ScanID, findingRef{
		FindingID: args.FindingID,
		Path:      args.Path,
		Line:      args.Line,
	})
	if err != nil {
		return toolErrorResult(d, err)
	}
	if err := deterministicFixGate(scan, *f); err != nil {
		return toolErrorResult(d, err)
	}
	if scan.Root != "" && !samePath(scan.Root, d.App.Root) {
		return errorResult(d, "refusing to apply a fix: the finding belongs to %s but this server is rooted at %s. "+
			"Run the MCP server from the repository that contains the finding.", scan.Root, d.App.Root)
	}
	if !d.App.LLM {
		return mcp.TextError("vigil_fix needs a model: set VIGIL_PROVIDER, VIGIL_MODEL and VIGIL_API_KEY (or a local OLLAMA_HOST). " +
			"Use vigil_explain for the deterministic remediation in the meantime.")
	}
	fix, err := d.App.ProposeFix(ctx, *f)
	if err != nil {
		return errorResult(d, "fix proposal failed: %v", err)
	}
	if fix == nil || strings.TrimSpace(fix.Diff) == "" {
		return errorResult(d, "the model did not return an applicable diff for %s; fix it manually or ask again with more context.", findingID(*f))
	}

	targets, terr := targetsFromDiff(d.App.Root, fix.Diff)
	if terr != nil {
		return toolErrorResult(d, terr)
	}
	if err := d.App.ApplyFix(ctx, fix); err != nil {
		return errorResult(d, "%s\n**Apply failed:** %v\n", fixMarkdown(*f, fix, false), err)
	}
	createdAt := time.Now().UTC()
	payload := map[string]any{
		"scanId":          scan.ID,
		"findingId":       findingID(*f),
		"applied":         true,
		"fixId":           proposalID(fix.Diff, createdAt),
		"diffSha256":      sha256Hex(fix.Diff),
		"verifiedTargets": sortedKeys(targets),
		"warning":         unsafeUnboundWarning,
		"fix":             fix,
	}
	return result(d, fixMarkdown(*f, fix, true)+"\n**Warning:** "+unsafeUnboundWarning+"\n", payload)
}

const unsafeUnboundWarning = "unsafe unbound apply: the diff was applied without a reviewed proposal. " +
	"This is the 0.10 behaviour and is disabled by default; restart the server without " +
	"--unsafe-unbound-fix and use mode=propose then mode=apply."

func proposalMarkdown(f model.Finding, fix *model.Fix, p *pendingProposal) string {
	var b strings.Builder
	b.WriteString(fixMarkdown(f, fix, false))
	fmt.Fprintf(&b, "\n**Proposal:** `%s`\n", p.FixID)
	fmt.Fprintf(&b, "**diffSha256:** `%s`\n", p.DiffSHA256)
	fmt.Fprintf(&b, "**Expires:** %s\n", p.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "**Targets:** %s\n", strings.Join(sortedKeys(p.Targets), ", "))
	fmt.Fprintf(&b, "\nShow this diff to the user. To apply exactly this diff, call `vigil_fix` with "+
		"`mode=apply`, `fixId=%s` and `diffSha256=%s` before it expires.\n", p.FixID, p.DiffSHA256)
	return b.String()
}

func appliedMarkdown(f model.Finding, fix *model.Fix, p *pendingProposal) string {
	var b strings.Builder
	b.WriteString(fixMarkdown(f, fix, true))
	fmt.Fprintf(&b, "\n**Proposal:** `%s`\n", p.FixID)
	fmt.Fprintf(&b, "**diffSha256:** `%s`\n", p.DiffSHA256)
	fmt.Fprintf(&b, "**Verified targets:** %s\n", strings.Join(sortedKeys(p.Targets), ", "))
	return b.String()
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
		b.WriteString("**Applied:** no (dry run). Nothing was written. Review the diff and ask the user before applying it.\n")
	}
	return b.String()
}

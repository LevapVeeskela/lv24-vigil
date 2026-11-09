package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type explainArgs struct {
	FindingID string `json:"findingId"`
	ScanID    string `json:"scanId"`
}

func registerExplain(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_explain",
		Title: "Explain a Vigil finding",
		Description: "Explain one finding: what the rule detected, why it matters, an exploit scenario and " +
			"the remediation direction. Uses the configured model when available; otherwise returns the " +
			"deterministic rule description and remediation.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"findingId": mcp.Prop("string", "Finding ID (VGL-...), fingerprint (fp_...) or a unique prefix."),
			"scanId":    mcp.Prop("string", "Scan to look in. Defaults to the most recent scan."),
		}, "findingId"),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleExplain(ctx, d, raw)
		},
	})
}

func handleExplain(ctx context.Context, d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args explainArgs
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

	var b strings.Builder
	b.WriteString("# Finding explanation\n\n")
	b.WriteString(deterministicFindingMarkdown(*f))

	llmUsed := false
	var note string
	if !d.App.LLM {
		note = "No model is configured, so this is the deterministic rule output. Set VIGIL_PROVIDER, VIGIL_MODEL and VIGIL_API_KEY (or a local OLLAMA_HOST) to get an exploit narrative and a tailored explanation."
	} else {
		explanation, xerr := d.App.Explain(ctx, *f)
		if xerr != nil {
			note = fmt.Sprintf("The model explanation is unavailable: %v", xerr)
		} else {
			llmUsed = true
			b.WriteString("\n### Model analysis\n\n")
			b.WriteString(strings.TrimSpace(explanation))
			b.WriteString("\n")
		}
	}
	if note != "" {
		fmt.Fprintf(&b, "\n> Note: %s\n", note)
	}
	if scan.Root != "" && !samePath(scan.Root, d.App.Root) {
		fmt.Fprintf(&b, "\n> Note: the finding came from scan root %s, but model file context is read from %s.\n", scan.Root, d.App.Root)
	}

	payload := map[string]any{
		"scanId":      scan.ID,
		"finding":     f,
		"llm":         llmUsed,
		"explanation": strings.TrimSpace(b.String()),
	}
	if note != "" {
		payload["note"] = note
	}
	return result(d, b.String(), payload), nil
}

// deterministicFindingMarkdown renders everything the deterministic engine
// knows about a finding. It never contains a raw credential: rules mask
// evidence before it reaches a Finding.
func deterministicFindingMarkdown(f model.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s — %s\n\n", findingID(f), oneLine(f.Title))
	fmt.Fprintf(&b, "- **Severity:** %s\n", displaySeverity(f.Severity))
	if f.Confidence != "" {
		fmt.Fprintf(&b, "- **Confidence:** %s\n", f.Confidence)
	}
	if f.Category != "" {
		fmt.Fprintf(&b, "- **Category:** %s\n", f.Category)
	}
	if f.RuleID != "" {
		fmt.Fprintf(&b, "- **Rule:** %s\n", f.RuleID)
	}
	fmt.Fprintf(&b, "- **Location:** `%s`\n", locationString(f.Location))
	if f.Source != "" {
		fmt.Fprintf(&b, "- **Source:** %s\n", f.Source)
	}
	fmt.Fprintf(&b, "- **Fingerprint:** `%s`\n", findingFingerprint(f))
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "- **CWE:** %s\n", strings.Join(f.CWE, ", "))
	}
	if len(f.OWASP) > 0 {
		fmt.Fprintf(&b, "- **OWASP:** %s\n", strings.Join(f.OWASP, ", "))
	}

	if d := strings.TrimSpace(f.Description); d != "" {
		b.WriteString("\n### What the rule found\n\n")
		b.WriteString(oneLine(d))
		b.WriteString("\n")
	}
	if ev := strings.TrimSpace(f.Evidence); ev != "" {
		b.WriteString("\n### Evidence\n\n")
		b.WriteString(fenced(ev, ""))
		b.WriteString("\n")
	}
	if f.LLM != nil {
		b.WriteString("\n### Model triage\n\n")
		if f.LLM.Verdict != "" {
			fmt.Fprintf(&b, "- **Verdict:** %s\n", f.LLM.Verdict)
		}
		if f.LLM.Severity != "" {
			fmt.Fprintf(&b, "- **Suggested severity:** %s\n", f.LLM.Severity)
		}
		if f.LLM.Confidence > 0 {
			fmt.Fprintf(&b, "- **Model confidence:** %.2f\n", f.LLM.Confidence)
		}
		if r := strings.TrimSpace(f.LLM.Reasoning); r != "" {
			b.WriteString("\n" + r + "\n")
		}
		if e := strings.TrimSpace(f.LLM.Exploit); e != "" {
			b.WriteString("\n**Exploit scenario:** " + e + "\n")
		}
		if r := strings.TrimSpace(f.LLM.Remediation); r != "" {
			b.WriteString("\n**Suggested remediation:** " + r + "\n")
		}
	}
	if r := strings.TrimSpace(f.Remediation); r != "" {
		b.WriteString("\n### Remediation\n\n")
		b.WriteString(r)
		b.WriteString("\n")
	}
	if len(f.References) > 0 {
		b.WriteString("\n### References\n\n")
		for _, ref := range f.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
	}
	return b.String()
}

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/store"
)

type statusScan struct {
	ID           string    `json:"id"`
	StartedAt    time.Time `json:"startedAt"`
	Mode         string    `json:"mode"`
	Findings     int       `json:"findings"`
	Critical     int       `json:"critical"`
	High         int       `json:"high"`
	DurationMS   int64     `json:"durationMs"`
	FilesScanned int       `json:"filesScanned"`
}

type statusPayload struct {
	Version     string      `json:"version"`
	Root        string      `json:"root,omitempty"`
	Provider    string      `json:"provider,omitempty"`
	Model       string      `json:"model,omitempty"`
	BaseURL     string      `json:"baseUrl,omitempty"`
	LLM         bool        `json:"llm"`
	APIKey      string      `json:"apiKey"`
	Rules       int         `json:"rules"`
	Categories  []string    `json:"categories"`
	StoreDir    string      `json:"storeDir,omitempty"`
	LastScan    *statusScan `json:"lastScan"`
	Warnings    []string    `json:"warnings"`
	ConfigFiles []string    `json:"configFiles,omitempty"`
	Hint        string      `json:"hint,omitempty"`
}

func registerStatus(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_status",
		Title: "Show Vigil status",
		Description: "Report the engine version, project root, model configuration (with the key redacted), " +
			"rule count, categories, store directory, the last scan summary and startup warnings.",
		InputSchema: mcp.ObjectSchema(map[string]any{}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleStatus(d, raw)
		},
	})
}

func handleStatus(d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	var args struct{}
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}
	payload := statusPayloadFor(d)
	text, err := jsonText(payload)
	if err != nil {
		return errorResult(d, "status: %v", err), nil
	}
	return result(d, text, payload), nil
}

func statusPayloadFor(d Deps) statusPayload {
	p := statusPayload{
		Version:    d.Version,
		LLM:        false,
		APIKey:     "not set",
		Categories: []string{},
		Warnings:   []string{},
	}
	if d.App == nil {
		p.Hint = "vigil is not initialised: no app runtime is attached to this MCP server"
		return p
	}

	p.Root = d.App.Root
	p.Provider = d.App.Config.Provider
	p.Model = d.App.Config.Model
	p.BaseURL = redactURL(d.App.Config.BaseURL)
	p.LLM = d.App.LLM
	if d.App.Config.APIKey != "" {
		p.APIKey = "configured"
	}
	p.ConfigFiles = append(p.ConfigFiles, d.App.Config.ConfigFiles...)

	metas := d.App.Registry.Metas()
	p.Rules = len(metas)
	p.Categories = categoriesFromMetas(metas)
	p.StoreDir = d.App.Store.Dir()
	p.Warnings = append(p.Warnings, d.App.Warnings...)

	if !d.App.LLM {
		p.Hint = "No model is configured: deterministic rules only. Set VIGIL_PROVIDER, VIGIL_MODEL and VIGIL_API_KEY " +
			"(or OLLAMA_HOST) for triage, deep review, fixes and threat models."
	}

	if last, err := d.App.LastScan(); err == nil {
		p.LastScan = summarizeScan(last)
	}
	return p
}

func summarizeScan(res *model.ScanResult) *statusScan {
	if res == nil {
		return nil
	}
	s := &statusScan{
		ID:           res.ID,
		StartedAt:    res.StartedAt,
		Mode:         res.Mode,
		Findings:     len(res.Findings),
		DurationMS:   res.Stats.DurationMS,
		FilesScanned: res.Stats.FilesScanned,
	}
	for _, f := range res.Findings {
		switch f.Severity {
		case model.SeverityCritical:
			s.Critical++
		case model.SeverityHigh:
			s.High++
		}
	}
	return s
}

func categoriesFromMetas(metas []model.RuleMeta) []string {
	seen := make(map[model.Category]bool, len(metas))
	out := make([]string, 0, len(metas))
	for _, m := range metas {
		if m.Category == "" || seen[m.Category] {
			continue
		}
		seen[m.Category] = true
		out = append(out, string(m.Category))
	}
	sort.Strings(out)
	return out
}

type historyArgs struct {
	Limit int `json:"limit"`
}

type historyPayload struct {
	Count int             `json:"count"`
	Scans []store.Summary `json:"scans"`
}

func registerHistory(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_history",
		Title: "List stored Vigil scans",
		Description: "List the most recent stored scans with their finding, critical and high counts. " +
			"Scan IDs can be passed to vigil_explain, vigil_fix, vigil_report and vigil_verify.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"limit": mcp.PropInt("Maximum number of scans to list (default 10, capped at 100)."),
		}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleHistory(d, raw)
		},
	})
}

func handleHistory(d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args historyArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	limit := clampInt(args.Limit, 10, 100)
	summaries, err := d.App.Store.List(limit)
	if err != nil {
		return errorResult(d, "history: %v", err), nil
	}

	var b strings.Builder
	if len(summaries) == 0 {
		b.WriteString("No stored scans yet. Run vigil_scan to create one.\n")
	} else {
		fmt.Fprintf(&b, "Recent scans (%d, newest first):\n\n", len(summaries))
		w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTARTED (UTC)\tFINDINGS\tCRITICAL\tHIGH")
		for _, s := range summaries {
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\n",
				s.ID, formatScanTime(s.StartedAt), s.Findings, s.Critical, s.High)
		}
		_ = w.Flush()
		fmt.Fprintf(&b, "\nStore: %s\n", d.App.Store.Dir())
	}

	payload := historyPayload{Count: len(summaries), Scans: summaries}
	return result(d, b.String(), payload), nil
}

func formatScanTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

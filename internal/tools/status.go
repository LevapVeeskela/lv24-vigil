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
	ReadOnly    bool        `json:"readOnly"`
	Offline     bool        `json:"offline"`
	Network     string      `json:"network"`
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
			"rule count, categories, store directory, the effective read-only and offline modes, the network " +
			"posture, the last scan summary and startup warnings.",
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
		ReadOnly:   d.ReadOnly,
		Offline:    d.Offline,
		Categories: []string{},
		Warnings:   []string{},
	}
	if d.App == nil {
		p.Network = "none"
		p.Hint = "vigil is not initialised: no app runtime is attached to this MCP server"
		return p
	}

	p.Root = d.App.Root
	p.Provider = d.App.Config.Provider
	p.Model = d.App.Config.Model
	p.BaseURL = redactURL(d.App.Config.BaseURL)
	p.LLM = d.App.LLM
	p.Network = networkPosture(d)
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
	if d.ReadOnly {
		p.Hint = strings.TrimSpace(p.Hint + " Read-only mode is on: vigil_fix is hidden and baseline, source and report writes are rejected.")
	}
	if d.Offline {
		p.Hint = strings.TrimSpace(p.Hint + " Offline mode is on: no model or OSV calls are made.")
	}

	if last, err := d.App.LastScan(); err == nil {
		p.LastScan = summarizeScan(last)
	}
	return p
}

// networkPosture names every outbound channel the server can open. It is
// computed from the effective runtime, not from the flags alone, so a model
// that failed to initialise does not claim egress.
func networkPosture(d Deps) string {
	if d.Offline || d.App == nil {
		return "none"
	}
	parts := make([]string, 0, 2)
	if d.App.LLM {
		parts = append(parts, "model")
	}
	if d.App.Config.Scan.OSV {
		parts = append(parts, "osv")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "+")
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
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

type historyPayload struct {
	Count      int             `json:"count"`
	Total      int             `json:"total"`
	HasMore    bool            `json:"hasMore"`
	NextOffset *int            `json:"nextOffset,omitempty"`
	Page       *pageInfo       `json:"page,omitempty"`
	Scans      []store.Summary `json:"scans"`
}

func registerHistory(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_history",
		Title: "List stored Vigil scans",
		Description: "List stored scans, newest first, with their finding, critical and high counts. " +
			"The response is windowed: limit is the page size (default 10, capped at 100) and offset " +
			"selects the page; the page object states total, hasMore and nextOffset. Scan IDs can be " +
			"passed to vigil_explain, vigil_fix, vigil_report and vigil_verify.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"offset": mcp.PropInt("Zero-based scan offset for paging. Start with 0, then pass page.nextOffset from the previous result."),
			"limit":  mcp.PropInt("Maximum number of scans in this window (default 10, capped at 100)."),
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
	if err := checkOffset(args.Offset); err != nil {
		return errorResult(d, "%v", err), nil
	}

	limit := clampInt(args.Limit, 10, 100)
	// List(0) is the cheapest existing way to learn the honest total: the
	// store already prunes its history, so this is one directory read.
	all, err := d.App.Store.List(0)
	if err != nil {
		return errorResult(d, "history: %v", err), nil
	}
	start, end, page := window(len(all), args.Offset, limit)
	summaries := all[start:end]

	var b strings.Builder
	if len(all) == 0 {
		b.WriteString("No stored scans yet. Run vigil_scan to create one.\n")
	} else {
		fmt.Fprintf(&b, "Recent scans (newest first) — %s\n\n", pageNote(page))
		if len(summaries) == 0 {
			b.WriteString("No scans in this window.\n")
		} else {
			w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTARTED (UTC)\tFINDINGS\tCRITICAL\tHIGH")
			for _, s := range summaries {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\n",
					s.ID, formatScanTime(s.StartedAt), s.Findings, s.Critical, s.High)
			}
			_ = w.Flush()
		}
		fmt.Fprintf(&b, "\nStore: %s\n", d.App.Store.Dir())
	}

	payload := historyPayload{
		Count:      len(summaries),
		Total:      page.Total,
		HasMore:    page.HasMore,
		NextOffset: page.NextOffset,
		Page:       &page,
		Scans:      summaries,
	}
	return result(d, b.String(), payload), nil
}

func formatScanTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

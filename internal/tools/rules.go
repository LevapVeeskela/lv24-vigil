package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

type rulesArgs struct {
	Category string `json:"category"`
	Language string `json:"language"`
	Severity string `json:"severity"`
	Query    string `json:"query"`
}

func registerRules(srv *mcp.Server, d Deps) {
	srv.AddTool(mcp.Tool{
		Name:  "vigil_rules",
		Title: "List Vigil detection rules",
		Description: "List the deterministic detection rules with their severity, category, languages and title. " +
			"Optionally filter by category, language, severity or a free-text query.",
		InputSchema: mcp.ObjectSchema(map[string]any{
			"category": mcp.PropEnum("Only rules in this category.", categoryNames()...),
			"language": mcp.Prop("string", "Only rules that apply to this language (for example go, python, javascript, yaml). Generic rules are included."),
			"severity": mcp.PropEnum("Only rules with this base severity.", "critical", "high", "medium", "low", "info"),
			"query":    mcp.Prop("string", "Case-insensitive text matched against the ID, title, description, tags, CWE and OWASP fields."),
		}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
		Handler: func(ctx context.Context, raw json.RawMessage) (*mcp.CallToolResult, error) {
			return handleRules(d, raw)
		},
	})
}

func handleRules(d Deps, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if errRes := appReady(d); errRes != nil {
		return errRes, nil
	}
	var args rulesArgs
	if errRes := decodeArgs(raw, &args); errRes != nil {
		return errRes, nil
	}

	severity, err := parseSeverityArg(args.Severity)
	if err != nil {
		return mcp.TextError("invalid arguments: %v", err), nil
	}
	category := strings.ToLower(strings.TrimSpace(args.Category))
	if category != "" && !containsFold(categoryNames(), category) {
		return mcp.TextError("invalid arguments: unknown category %q (use one of: %s)", args.Category, strings.Join(categoryNames(), ", ")), nil
	}
	language := strings.ToLower(strings.TrimSpace(args.Language))
	query := strings.ToLower(strings.TrimSpace(args.Query))

	metas := d.App.Registry.Metas()
	filtered := make([]model.RuleMeta, 0, len(metas))
	for _, m := range metas {
		if severity != "" && m.Severity != severity {
			continue
		}
		if category != "" && strings.ToLower(string(m.Category)) != category {
			continue
		}
		if language != "" && !ruleSupportsLanguage(m, language) {
			continue
		}
		if !ruleMatchesQuery(m, query) {
			continue
		}
		filtered = append(filtered, m)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Vigil rules: %d of %d\n", len(filtered), len(metas))
	filters := make([]string, 0, 4)
	if category != "" {
		filters = append(filters, "category="+category)
	}
	if language != "" {
		filters = append(filters, "language="+language)
	}
	if severity != "" {
		filters = append(filters, "severity="+string(severity))
	}
	if query != "" {
		filters = append(filters, "query="+query)
	}
	if len(filters) > 0 {
		fmt.Fprintf(&b, "Filters: %s\n", strings.Join(filters, ", "))
	}
	b.WriteString("\n")

	if len(filtered) == 0 {
		b.WriteString("No rules match these filters.\n")
	} else {
		w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSEVERITY\tCATEGORY\tLANGUAGES\tTITLE")
		for _, m := range filtered {
			langs := "all"
			if len(m.Languages) > 0 {
				langs = strings.Join(m.Languages, ",")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				m.ID, displaySeverity(m.Severity), m.Category, langs, truncateRunes(oneLine(m.Title), 100))
		}
		_ = w.Flush()
	}

	payload := map[string]any{
		"count": len(filtered),
		"total": len(metas),
		"rules": filtered,
	}
	return result(d, b.String(), payload), nil
}

func categoryNames() []string {
	return []string{
		string(model.CategorySecrets),
		string(model.CategoryInjection),
		string(model.CategoryAuth),
		string(model.CategoryCrypto),
		string(model.CategoryConfig),
		string(model.CategoryCI),
		string(model.CategoryDependency),
		string(model.CategoryWeb),
		string(model.CategoryLogic),
		string(model.CategoryAntiRE),
	}
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func ruleSupportsLanguage(m model.RuleMeta, language string) bool {
	if len(m.Languages) == 0 {
		return true
	}
	for _, l := range m.Languages {
		if strings.EqualFold(l, language) {
			return true
		}
	}
	return false
}

func ruleMatchesQuery(m model.RuleMeta, query string) bool {
	if query == "" {
		return true
	}
	fields := []string{m.ID, m.Title, m.Description, string(m.Severity), string(m.Category)}
	fields = append(fields, m.Languages...)
	fields = append(fields, m.CWE...)
	fields = append(fields, m.OWASP...)
	fields = append(fields, m.Tags...)
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), query) {
			return true
		}
	}
	return false
}

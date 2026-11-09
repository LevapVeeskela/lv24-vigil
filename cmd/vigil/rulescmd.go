package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

func runRules(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("rules")
	category := fs.String("category", "", "filter by category (secrets, injection, auth, ...)")
	language := fs.String("language", "", "filter by declared language (go, python, javascript, ...)")
	severity := fs.String("severity", "", "filter by severity")
	query := fs.String("query", "", "search ID, title, description, tags and CWE")
	asJSON := fs.Bool("json", false, "emit the rules as JSON")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, `Usage: vigil rules [flags]

Flags:
  --category C    filter by category
  --language L    filter by declared language
  --severity S    filter by severity
  --query Q       search ID, title, description, tags and CWE
  --json          emit JSON
`)
		return nil
	}
	if err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("rules takes no arguments (got %q)", positional[0])
	}

	metas := rules.Default().Metas()
	wantCategory := strings.ToLower(strings.TrimSpace(*category))
	wantLanguage := strings.ToLower(strings.TrimSpace(*language))
	wantQuery := strings.ToLower(strings.TrimSpace(*query))

	var wantSeverity model.Severity
	if strings.TrimSpace(*severity) != "" {
		wantSeverity, err = parseSeverity(*severity)
		if err != nil {
			return fmt.Errorf("--severity: %w", err)
		}
	}

	filtered := make([]model.RuleMeta, 0, len(metas))
	for _, meta := range metas {
		if wantCategory != "" && strings.ToLower(string(meta.Category)) != wantCategory {
			continue
		}
		if wantSeverity != "" && meta.Severity != wantSeverity {
			continue
		}
		if wantLanguage != "" && !hasLanguage(meta, wantLanguage) {
			continue
		}
		if wantQuery != "" && !matchesQuery(meta, wantQuery) {
			continue
		}
		filtered = append(filtered, meta)
	}

	if *asJSON {
		data, err := json.MarshalIndent(filtered, "", "  ")
		if err != nil {
			return fmt.Errorf("encode rules: %w", err)
		}
		data = append(data, '\n')
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("write rules: %w", err)
		}
		return nil
	}

	if len(filtered) == 0 {
		fmt.Fprintf(stdout, "no rules match these filters (%d rules available)\n", len(metas))
		return nil
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tTITLE")
	for _, meta := range filtered {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", meta.ID, strings.ToUpper(string(meta.Severity)), meta.Category, oneLine(meta.Title))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}

	if len(filtered) == len(metas) {
		fmt.Fprintf(stdout, "\n%d rules\n", len(metas))
	} else {
		fmt.Fprintf(stdout, "\n%d of %d rules\n", len(filtered), len(metas))
	}
	return nil
}

func hasLanguage(meta model.RuleMeta, want string) bool {
	for _, lang := range meta.Languages {
		if strings.EqualFold(lang, want) {
			return true
		}
	}
	return false
}

func matchesQuery(meta model.RuleMeta, query string) bool {
	fields := []string{meta.ID, meta.Title, meta.Description, string(meta.Severity), string(meta.Category)}
	fields = append(fields, meta.Tags...)
	fields = append(fields, meta.CWE...)
	fields = append(fields, meta.OWASP...)
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

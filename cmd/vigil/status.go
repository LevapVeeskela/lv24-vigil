package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/version"
)

// statusReport is the stable JSON shape emitted by `vigil status --json`.
// Fields are never omitted so scripts can rely on them.
type statusReport struct {
	Version          string            `json:"version"`
	Commit           string            `json:"commit"`
	Date             string            `json:"date"`
	GoVersion        string            `json:"goVersion"`
	Root             string            `json:"root"`
	Provider         string            `json:"provider"`
	Model            string            `json:"model"`
	BaseURL          string            `json:"baseUrl"`
	APIKeySet        bool              `json:"apiKeySet"`
	LLM              bool              `json:"llm"`
	LLMStatus        string            `json:"llmStatus"`
	Rules            int               `json:"rules"`
	ScanStore        string            `json:"scanStore"`
	Baseline         string            `json:"baseline"`
	LastScan         *statusScan       `json:"lastScan"`
	ConfigFiles      []string          `json:"configFiles"`
	UserConfig       string            `json:"userConfig"`
	UserConfigExists bool              `json:"userConfigExists"`
	Sources          map[string]string `json:"sources"`
	Warnings         []string          `json:"warnings"`
}

type statusScan struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"startedAt"`
	Findings  int       `json:"findings"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
}

func runStatus(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("status")
	asJSON := fs.Bool("json", false, "emit a stable JSON object")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, "Usage: vigil status [--json]\n\nShows the resolved provider, model, rules and last scan.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("status takes no arguments (got %q)", positional[0])
	}

	a, err := buildApp(".", stderr)
	if err != nil {
		return err
	}
	defer a.Close()

	sources := make(map[string]string, len(a.Config.Sources))
	for key, value := range a.Config.Sources {
		sources[key] = value
	}

	baseline, baselineErr := baselinePath(a)
	report := statusReport{
		Version:     version.Version,
		Commit:      version.Commit,
		Date:        version.Date,
		GoVersion:   runtime.Version(),
		Root:        a.Root,
		Provider:    a.Config.Provider,
		Model:       a.Config.Model,
		BaseURL:     config.RedactURL(a.Config.BaseURL),
		APIKeySet:   a.Config.APIKey != "",
		LLM:         a.LLM,
		LLMStatus:   llmStatus(a.LLM, a.Config.Provider),
		Rules:       len(a.Registry.Metas()),
		ScanStore:   a.Store.Dir(),
		Baseline:    baseline,
		ConfigFiles: append([]string{}, a.Config.ConfigFiles...),
		Sources:     sources,
		Warnings:    append([]string{}, a.Warnings...),
	}

	if baselineErr != nil {
		report.Warnings = append(report.Warnings, "baseline: "+baselineErr.Error())
	}
	if userPath, err := config.UserConfigPath(); err == nil {
		report.UserConfig = userPath
		if _, statErr := os.Stat(userPath); statErr == nil {
			report.UserConfigExists = true
		} else if !errors.Is(statErr, os.ErrNotExist) {
			report.Warnings = append(report.Warnings, fmt.Sprintf("user config %s: %v", userPath, statErr))
		}
	} else {
		report.Warnings = append(report.Warnings, "user config path: "+err.Error())
	}

	res, lastErr := a.LastScan()
	switch {
	case lastErr == nil:
		report.LastScan = &statusScan{
			ID:        res.ID,
			StartedAt: res.StartedAt,
			Findings:  len(res.Findings),
			Critical:  countSeverity(res.Findings, model.SeverityCritical),
			High:      countSeverity(res.Findings, model.SeverityHigh),
		}
	case !errors.Is(lastErr, os.ErrNotExist):
		report.Warnings = append(report.Warnings, "last scan: "+lastErr.Error())
	}

	if *asJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("encode status: %w", err)
		}
		data = append(data, '\n')
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("write status: %w", err)
		}
		return nil
	}

	printStatus(stdout, report)
	return nil
}

func llmStatus(available bool, provider string) string {
	switch {
	case available:
		return "available"
	case provider != "":
		return "configured but unavailable (see warnings)"
	default:
		return "not configured (deterministic rules only)"
	}
}

// statusValue appends the source of a resolved value (config path or env var)
// when one is known. A missing source means the built-in default.
func statusValue(value, source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return value
	}
	return value + " · " + source
}

func countSeverity(findings []model.Finding, severity model.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == severity {
			n++
		}
	}
	return n
}

func printStatus(w io.Writer, s statusReport) {
	fmt.Fprintln(w, version.String())
	row := func(label, value string) {
		fmt.Fprintf(w, "  %-10s %s\n", label, value)
	}
	row("root", s.Root)

	provider := s.Provider
	if provider == "" {
		provider = "not configured"
	}
	row("provider", statusValue(provider, s.Sources["provider"]))
	modelName := s.Model
	if modelName == "" {
		modelName = "not configured"
	}
	row("model", statusValue(modelName, s.Sources["model"]))
	if s.BaseURL != "" {
		row("base url", statusValue(s.BaseURL, s.Sources["base_url"]))
	}
	key := "not set"
	if s.APIKeySet {
		key = "set (value hidden)"
	}
	row("api key", statusValue(key, s.Sources["api_key"]))
	row("llm", s.LLMStatus)
	row("rules", fmt.Sprintf("%d", s.Rules))
	row("scans", s.ScanStore)
	row("baseline", s.Baseline)

	if s.LastScan == nil {
		row("last scan", "none (run `vigil scan`)")
	} else {
		summary := fmt.Sprintf("%s · %d findings", s.LastScan.ID, s.LastScan.Findings)
		if s.LastScan.Critical > 0 || s.LastScan.High > 0 {
			summary += fmt.Sprintf(" (%d critical, %d high)", s.LastScan.Critical, s.LastScan.High)
		}
		if !s.LastScan.StartedAt.IsZero() {
			summary += " · " + s.LastScan.StartedAt.UTC().Format(time.RFC3339)
		}
		row("last scan", summary)
	}

	if len(s.ConfigFiles) == 0 {
		row("config", "none (run `vigil init` to create .vigil.yaml)")
	} else {
		for i, file := range s.ConfigFiles {
			label := "config"
			if i > 0 {
				label = ""
			}
			row(label, file)
		}
	}
	if s.UserConfig != "" && !s.UserConfigExists {
		row("user config", s.UserConfig+" (not found)")
	}

	if len(s.Warnings) == 0 {
		row("warnings", "none")
		return
	}
	for i, warning := range s.Warnings {
		label := "warnings"
		if i > 0 {
			label = ""
		}
		row(label, warning)
	}
}

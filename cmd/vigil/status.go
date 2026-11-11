package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
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
	// ConfigError is set when the configuration could not be loaded. The
	// rest of the report is then limited to what is known without it.
	ConfigError *statusConfigError `json:"configError"`
}

// statusConfigError describes a configuration that failed to load. It never
// carries the offending value, which may be a secret or a credentialed URL.
type statusConfigError struct {
	File    string `json:"file"`
	Key     string `json:"key"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
}

// errStatusConfig makes `vigil status` exit non-zero after it has printed a
// report for a configuration that does not load.
var errStatusConfig = errors.New("status: the configuration does not load; see configError")

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

	// Diagnose the configuration before building the app: a status command
	// that dies on the very problem it should explain helps nobody.
	if _, cfgErr := config.Load("."); cfgErr != nil {
		report := degradedStatus(cfgErr)
		if err := writeStatus(stdout, report, *asJSON); err != nil {
			return err
		}
		return errStatusConfig
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

	return writeStatus(stdout, report, *asJSON)
}

func writeStatus(w io.Writer, report statusReport, asJSON bool) error {
	if asJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("encode status: %w", err)
		}
		data = append(data, '\n')
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("write status: %w", err)
		}
		return nil
	}
	printStatus(w, report)
	return nil
}

// degradedStatus is the report for a configuration that does not load: the
// build facts, the rule count, the user config location and the error with a
// concrete fix. Model, store and baseline are unknown without a config.
func degradedStatus(cfgErr error) statusReport {
	root, err := filepath.Abs(".")
	if err != nil {
		root = "."
	}
	report := statusReport{
		Version:     version.Version,
		Commit:      version.Commit,
		Date:        version.Date,
		GoVersion:   runtime.Version(),
		Root:        root,
		LLMStatus:   "unknown (configuration not loaded)",
		Rules:       len(rules.Default().Metas()),
		ConfigFiles: []string{},
		Sources:     map[string]string{},
		Warnings:    []string{},
	}
	userPath, pathErr := config.UserConfigPath()
	if pathErr == nil {
		report.UserConfig = userPath
		if _, statErr := os.Stat(userPath); statErr == nil {
			report.UserConfigExists = true
		}
	}
	report.ConfigError = describeConfigError(cfgErr, userPath)
	return report
}

// projectKeyEnv names the environment variable that replaces a key a project
// file may not set. An empty value means the key lives in the user config only.
var projectKeyEnv = map[string]string{
	"api_key":              "VIGIL_API_KEY",
	"base_url":             "VIGIL_BASE_URL",
	"command":              "VIGIL_COMMAND",
	"command_env":          "",
	"command_prompt_mode":  "VIGIL_COMMAND_PROMPT_MODE",
	"command_output":       "VIGIL_COMMAND_OUTPUT",
	"scan.osv_base_url":    "VIGIL_OSV_BASE_URL",
	"scan.follow_symlinks": "",
}

// describeConfigError turns a load error into a report entry with a fix. The
// fix names keys, files and variables only, never the configured value.
func describeConfigError(err error, userPath string) *statusConfigError {
	out := &statusConfigError{Message: err.Error()}
	var keyErr *config.ProjectKeyError
	if !errors.As(err, &keyErr) {
		out.Fix = "Fix or remove the configuration file named in the message, then run `vigil doctor` again."
		return out
	}
	out.File, out.Key = keyErr.File, keyErr.Key
	if keyErr.Key == "output.path" || keyErr.Key == "scan.baseline" {
		out.Fix = fmt.Sprintf("Change %s in %s to a relative path inside the project (no absolute path, no .., not under .git).", keyErr.Key, keyErr.File)
		return out
	}
	user := "the user config"
	if userPath != "" {
		user = fmt.Sprintf("the user config (%s)", userPath)
	}
	env, known := projectKeyEnv[keyErr.Key]
	switch {
	case known && env != "":
		out.Fix = fmt.Sprintf("Remove %s from %s. Set it in %s or with the %s environment variable; in CI, set %s as a GitHub Actions `env:` entry or a GitLab CI `variables:` entry.",
			keyErr.Key, keyErr.File, user, env, env)
		if keyErr.Key == "api_key" {
			out.Fix += " Store the key as a CI secret and rotate it if it was ever committed."
		}
	default:
		out.Fix = fmt.Sprintf("Remove %s from %s and set it in %s; a committed project file may not set it.", keyErr.Key, keyErr.File, user)
	}
	return out
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

	if s.ConfigError != nil {
		// Provider, model, store and baseline are unknown without a loaded
		// config; printing defaults here would describe a setup that is not
		// the user's.
		row("rules", fmt.Sprintf("%d", s.Rules))
		if s.UserConfig != "" {
			state := "found"
			if !s.UserConfigExists {
				state = "not found"
			}
			row("user config", s.UserConfig+" ("+state+")")
		}
		row("config", "ERROR — "+s.ConfigError.Message)
		row("fix", s.ConfigError.Fix)
		return
	}

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

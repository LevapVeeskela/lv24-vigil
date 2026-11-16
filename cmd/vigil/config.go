package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/config"
)

// errConfigInvalid is returned after a configuration problem has been printed
// with its file, key, message and fix. It carries no detail of its own so the
// value (which may be a secret) is never repeated on stderr.
var errConfigInvalid = errors.New("the configuration is invalid")

const configUsage = `Usage: vigil config <command>

Commands:
  validate [path] [--json]   load the user and project config like a scan does
  show [--json]              print the effective configuration and its sources

The user config is <config dir>/vigil/config.yaml (VIGIL_CONFIG overrides it).
The project config is .vigil.yaml, .vigil.yml or vigil.yaml in the scanned
directory. Precedence is defaults < user config < project config < environment.
Secrets are always redacted; no API key is ever printed.
`

// configIssue is the stable JSON shape of one configuration failure. It never
// carries the offending value.
type configIssue struct {
	File    string `json:"file"`
	Key     string `json:"key"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
}

type configValidateReport struct {
	OK    bool         `json:"ok"`
	Files []string     `json:"files"`
	Error *configIssue `json:"error"`
}

type configShowReport struct {
	Files   []string       `json:"files"`
	Entries []config.Entry `json:"entries"`
	Error   *configIssue   `json:"error"`
}

func runConfig(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("config requires a subcommand (validate or show)")
	}
	switch args[0] {
	case "validate", "check":
		return runConfigValidate(args[1:], stdout)
	case "show", "print":
		return runConfigShow(args[1:], stdout)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, configUsage)
		return nil
	default:
		return fmt.Errorf("unknown config subcommand %q (use validate or show)", args[0])
	}
}

// runConfigValidate loads the configuration exactly like a scan does, without
// opening the scan store or contacting a model.
func runConfigValidate(args []string, stdout io.Writer) error {
	fs := newFlagSet("config validate")
	asJSON := fs.Bool("json", false, "emit a stable JSON object")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, configUsage)
		return nil
	}
	if err != nil {
		return fmt.Errorf("config validate: %w", err)
	}
	if len(positional) > 1 {
		return fmt.Errorf("config validate takes at most one path (got %d)", len(positional))
	}

	root := "."
	if len(positional) == 1 {
		root = positional[0]
	}
	abs, err := app.ResolveRoot(root)
	if err != nil {
		return fmt.Errorf("config validate: %w", err)
	}

	cfg, cfgErr := config.Load(abs)
	userPath, _ := config.UserConfigPath()
	report := configValidateReport{
		OK:    cfgErr == nil,
		Files: append([]string{}, cfg.ConfigFiles...),
	}
	var issue *configIssue
	if cfgErr != nil {
		issue = describeConfigIssue(cfgErr, userPath)
		report.Error = issue
	}

	switch {
	case *asJSON:
		if err := writeConfigJSON(stdout, report); err != nil {
			return fmt.Errorf("config validate: %w", err)
		}
	case issue == nil:
		fmt.Fprintln(stdout, "config OK")
		printConfigFiles(stdout, report.Files)
	default:
		printConfigIssue(stdout, issue, report.Files)
	}

	if cfgErr != nil {
		return errConfigInvalid
	}
	return nil
}

// runConfigShow prints the effective configuration and where every value came
// from. Secret-looking values are redacted before they reach the writer.
func runConfigShow(args []string, stdout io.Writer) error {
	fs := newFlagSet("config show")
	asJSON := fs.Bool("json", false, "emit a stable JSON object")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, configUsage)
		return nil
	}
	if err != nil {
		return fmt.Errorf("config show: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("config show takes no arguments (got %q)", positional[0])
	}

	cfg, cfgErr := config.Load(".")
	report := configShowReport{
		Files:   append([]string{}, cfg.ConfigFiles...),
		Entries: []config.Entry{},
	}
	if cfgErr != nil {
		userPath, _ := config.UserConfigPath()
		report.Error = describeConfigIssue(cfgErr, userPath)
	} else {
		report.Entries = cfg.Entries()
	}

	if *asJSON {
		if err := writeConfigJSON(stdout, report); err != nil {
			return fmt.Errorf("config show: %w", err)
		}
		if cfgErr != nil {
			return errConfigInvalid
		}
		return nil
	}
	if cfgErr != nil {
		printConfigIssue(stdout, report.Error, report.Files)
		return errConfigInvalid
	}

	printConfigShow(stdout, report.Files, report.Entries)
	return nil
}

func printConfigFiles(w io.Writer, files []string) {
	if len(files) == 0 {
		fmt.Fprintln(w, "  files   none (defaults and environment only)")
		return
	}
	for _, file := range files {
		fmt.Fprintf(w, "  file    %s\n", file)
	}
}

func printConfigIssue(w io.Writer, issue *configIssue, files []string) {
	fmt.Fprintln(w, "config error")
	fmt.Fprintf(w, "  file    %s\n", orUnknown(issue.File))
	fmt.Fprintf(w, "  key     %s\n", orUnknown(issue.Key))
	fmt.Fprintf(w, "  message %s\n", issue.Message)
	fmt.Fprintf(w, "  fix     %s\n", issue.Fix)
	for _, file := range files {
		fmt.Fprintf(w, "  loaded  %s\n", file)
	}
}

func printConfigShow(w io.Writer, files []string, entries []config.Entry) {
	if len(files) == 0 {
		fmt.Fprintln(w, "config files: none (defaults and environment only)")
	} else {
		fmt.Fprintln(w, "config files (in precedence order):")
		for _, file := range files {
			fmt.Fprintf(w, "  %s\n", file)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "effective configuration (defaults < user config < project config < env):")
	width := 0
	for _, entry := range entries {
		if len(entry.Key) > width {
			width = len(entry.Key)
		}
	}
	for _, entry := range entries {
		value := entry.Value
		if value == "" {
			value = "(empty)"
		}
		fmt.Fprintf(w, "  %-*s  %-28s %s\n", width, entry.Key, value, entry.Source)
	}
}

func writeConfigJSON(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}
	return nil
}

// describeConfigIssue reuses the status configError and adds the file for the
// errors that are not tied to a key (unreadable or unparseable YAML).
func describeConfigIssue(err error, userPath string) *configIssue {
	described := describeConfigError(err, userPath)
	file := described.File
	if file == "" {
		file = configFileFromMessage(described.Message)
	}
	fix := described.Fix
	if described.Key == "" {
		// describeConfigError's generic fix talks about `vigil doctor`; this
		// command has the more direct re-check.
		fix = "Fix or remove the YAML file named in the message, then run `vigil config validate` again."
	}
	return &configIssue{
		File:    file,
		Key:     described.Key,
		Message: described.Message,
		Fix:     fix,
	}
}

// configFileFromMessage recovers the path from loader errors such as
// "parse config <path>: yaml: ..." and "config <path> is not a regular file".
// A path ends at the first ": " or " is " that follows the "config " marker,
// which keeps a Windows drive prefix (C:\) intact.
func configFileFromMessage(message string) string {
	const marker = "config "
	start := strings.Index(message, marker)
	if start < 0 {
		return ""
	}
	rest := message[start+len(marker):]
	end := len(rest)
	for _, boundary := range []string{": ", " is "} {
		if cut := strings.Index(rest, boundary); cut >= 0 && cut < end {
			end = cut
		}
	}
	return strings.TrimSpace(rest[:end])
}

func orUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "(unknown)"
	}
	return v
}

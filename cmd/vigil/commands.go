package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
)

// stdinReader is swapped by tests that exercise --diff -.
var stdinReader io.Reader = os.Stdin

// stringList is a repeatable flag that also accepts comma-separated values:
// --include '*.go,*.ts' --include '*.py' yields three patterns.
type stringList []string

func (s *stringList) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

// newFlagSet returns a quiet flag set. Parsing errors are returned to the
// caller instead of being printed twice; usage is printed only for -h.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseFlagSet parses flags that may appear before or after positional
// arguments, so both `vigil scan --mode quick .` and `vigil scan . --mode quick`
// work. Everything after a bare "--" is positional.
func parseFlagSet(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if rest[0] == "--" {
			return append(positional, rest[1:]...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// buildApp resolves configuration and wires the runtime. Diagnostics go to
// stderr only: stdout may be a report or the MCP protocol stream.
func buildApp(root string, stderr io.Writer) (*app.App, error) {
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return app.New(root, logger)
}

func printWarnings(w io.Writer, warnings []string) {
	for _, warning := range warnings {
		warning = strings.TrimSpace(warning)
		if warning != "" {
			fmt.Fprintf(w, "vigil: warning: %s\n", warning)
		}
	}
}

// signalContext cancels on SIGINT/SIGTERM so scans and the MCP server stop
// cleanly instead of dying mid-write.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// canonicalFormat validates a report format and returns its canonical name.
func canonicalFormat(v string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(v))
	f = strings.TrimPrefix(f, ".")
	switch f {
	case "", "md", "markdown":
		return "md", nil
	case "json":
		return "json", nil
	case "sarif":
		return "sarif", nil
	case "html", "htm":
		return "html", nil
	default:
		return "", fmt.Errorf("unsupported format %q (use md, json, sarif or html)", v)
	}
}

func parseSeverity(v string) (model.Severity, error) {
	sev, ok := model.ParseSeverity(v)
	if !ok {
		return "", fmt.Errorf("%q is not a severity (use low, medium, high or critical)", v)
	}
	return sev, nil
}

// useColor decides whether the human summary may use ANSI escapes. --color
// always wins; auto requires a real terminal and an unset NO_COLOR.
func useColor(mode string, w io.Writer) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "always":
		return true
	case "never":
		return false
	default:
		return isTerminal(w) && os.Getenv("NO_COLOR") == ""
	}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func severityColor(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "\x1b[1;31m"
	case model.SeverityHigh:
		return "\x1b[31m"
	case model.SeverityMedium:
		return "\x1b[33m"
	case model.SeverityLow:
		return "\x1b[36m"
	case model.SeverityInfo:
		return "\x1b[90m"
	default:
		return ""
	}
}

func paint(s, code string, enabled bool) string {
	if !enabled || code == "" {
		return s
	}
	return code + s + "\x1b[0m"
}

// resolveConfigOutputPath resolves a relative output.path from configuration
// against the project root and rejects a symlinked escape. An absolute path is
// only accepted from a trusted user config; the config loader rejects one in a
// project file. A CLI --output is user input and is not passed through here.
func resolveConfigOutputPath(root, path string) (string, error) {
	if path == "" || path == "-" {
		return path, nil
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	resolved, err := safepath.Resolve(root, path)
	if err != nil {
		return "", fmt.Errorf("output.path %q: %w", path, err)
	}
	return resolved, nil
}

// writeFile writes a report or document with the conventional 0644 mode. It
// writes a temporary file in the destination directory and renames it into
// place, so a pre-existing symlink or hardlink cannot redirect the write to a
// different file.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vigil-write-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmpName := tmp.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	remove = false
	return nil
}

func formatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

// scanError turns a cancelled context into a readable message instead of
// surfacing "context canceled" from deep inside the scanner.
func scanError(name string, err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s cancelled", name)
	}
	return err
}

// displayPath shortens an absolute path below the current directory for
// summaries, keeping the absolute path when it is outside.
func displayPath(path string) string {
	if path == "" {
		return path
	}
	cwd, err := os.Getwd()
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(cwd, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	if rel == "." {
		return "."
	}
	return rel
}

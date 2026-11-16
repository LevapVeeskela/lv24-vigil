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
	"runtime"
	"strings"
	"syscall"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/config"
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
// JUnit can only be rendered from a stored scan, so asking for it here points
// at the command that produces it instead of guessing.
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
	case "junit":
		return "", fmt.Errorf("unsupported format %q: JUnit is report-only: use vigil report --format junit", v)
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

// guardProjectOutputPath refuses to let an output.path that comes from a
// project file replace a file that is not a Vigil report. The project file is
// committed by whoever owns the repository, and a scan must never modify
// source files: without this a cloned repository could point output.path at
// app.py and have a plain "vigil scan" overwrite it. A path from the user
// config, the environment or --output is the user's own choice.
func guardProjectOutputPath(source, configured, resolved string) error {
	if source == "" || strings.HasPrefix(source, "env:") {
		return nil
	}
	if userPath, err := config.UserConfigPath(); err == nil && samePathFold(source, userPath) {
		return nil
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, _ := io.ReadFull(f, head)
	if looksLikeVigilReport(head[:n]) {
		return nil
	}
	return fmt.Errorf("output.path %q (set in %s) would overwrite a file that is not a Vigil report; remove the file, change output.path, or pass --output to choose the target yourself", configured, source)
}

// looksLikeVigilReport recognises the head of a report in any format this
// command writes, so a report path is replaced by the next scan as usual.
func looksLikeVigilReport(head []byte) bool {
	text := string(head)
	trimmed := strings.TrimLeft(text, "\ufeff \t\r\n")
	switch {
	case strings.HasPrefix(trimmed, "# Vigil security report"):
		return true
	case strings.Contains(text, "<title>Vigil security report"):
		return true
	case strings.HasPrefix(trimmed, "{") && strings.Contains(text, `"schemaVersion"`):
		return true
	case strings.HasPrefix(trimmed, "{") && strings.Contains(text, `"$schema"`) && strings.Contains(text, "sarif"):
		return true
	default:
		return false
	}
}

func samePathFold(a, b string) bool {
	ca, errA := filepath.Abs(a)
	cb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(ca), filepath.Clean(cb))
	}
	return filepath.Clean(ca) == filepath.Clean(cb)
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

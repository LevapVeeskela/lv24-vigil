package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/report"
)

// scanOptions holds the flags shared by `vigil scan` and `vigil review`.
type scanOptions struct {
	path        string
	mode        string
	changed     bool
	base        string
	diff        string
	noLLM       bool
	deep        bool
	threatModel bool
	include     stringList
	exclude     stringList
	rules       stringList
	disable     stringList
	minSeverity string
	maxFindings int
	noBaseline  bool
	format      string
	output      string
	failOn      string
	quiet       bool
	color       string
}

func registerScanFlags(fs *flag.FlagSet, o *scanOptions, review bool) {
	fs.StringVar(&o.path, "path", "", "directory to scan (default .)")
	fs.StringVar(&o.mode, "mode", "", "scan depth: quick, standard or deep")
	if !review {
		fs.BoolVar(&o.changed, "changed", false, "scan only files changed against --base")
	}
	fs.StringVar(&o.base, "base", o.base, "git ref for --changed and --diff")
	fs.StringVar(&o.diff, "diff", "", "unified diff file to scan (\"-\" for stdin)")
	fs.BoolVar(&o.noLLM, "no-llm", false, "deterministic rules only")
	fs.BoolVar(&o.deep, "deep", false, "run the deep LLM review")
	fs.BoolVar(&o.threatModel, "threat-model", false, "generate a threat model during the scan")
	fs.Var(&o.include, "include", "only scan matching globs (repeatable, comma-separated)")
	fs.Var(&o.exclude, "exclude", "skip matching globs (repeatable, comma-separated)")
	fs.Var(&o.rules, "rules", "run only these rule IDs (repeatable, comma-separated)")
	fs.Var(&o.disable, "disable", "skip these rule IDs (repeatable, comma-separated)")
	fs.StringVar(&o.minSeverity, "min-severity", "", "low, medium, high or critical")
	fs.IntVar(&o.maxFindings, "max-findings", 0, "cap the number of findings (0 = config default)")
	fs.BoolVar(&o.noBaseline, "no-baseline", false, "ignore the suppression baseline")
	fs.StringVar(&o.format, "format", "", "report format: md, json, sarif or html")
	fs.StringVar(&o.output, "output", "", "write the report to a file (\"-\" for stdout)")
	fs.StringVar(&o.failOn, "fail-on", "", "exit 2 when a finding at or above this severity exists")
	fs.BoolVar(&o.quiet, "quiet", false, "skip the human summary")
	fs.StringVar(&o.color, "color", "", "colorize the summary: auto, always or never")
}

func runScan(args []string, stdout, stderr io.Writer) error {
	return runScanLike("scan", args, false, stdout, stderr)
}

func runScanLike(name string, args []string, review bool, stdout, stderr io.Writer) error {
	o := &scanOptions{}
	if review {
		o.base = "HEAD"
	}
	fs := newFlagSet(name)
	registerScanFlags(fs, o, review)
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printScanUsage(stdout, name, review)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	root, err := o.resolvePath(positional)
	if err != nil {
		return err
	}
	failOn, err := o.failOnSeverity()
	if err != nil {
		return err
	}

	a, err := buildApp(root, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	printWarnings(stderr, a.Warnings)

	req, err := o.request(a.Root)
	if err != nil {
		return err
	}
	format, err := canonicalFormat(firstNonEmpty(o.format, a.Config.Output.Format))
	if err != nil {
		return err
	}
	outputPath := firstNonEmpty(o.output, a.Config.Output.Path)
	color := useColor(firstNonEmpty(o.color, a.Config.Output.Color), stdout)
	if o.threatModel && !a.LLM {
		fmt.Fprintln(stderr, "vigil: warning: --threat-model needs a configured model; skipping the threat model")
	}
	if (o.deep || strings.EqualFold(req.Mode, "deep")) && !a.LLM {
		fmt.Fprintln(stderr, "vigil: warning: deep review needs a configured model; scanning with deterministic rules only")
	}

	ctx, stop := signalContext()
	defer stop()

	var res *model.ScanResult
	if review {
		res, err = a.Review(ctx, req)
	} else {
		res, err = a.Scan(ctx, req)
	}
	if err != nil {
		return scanError(name, err)
	}

	if !o.quiet && format == "md" {
		printSummary(stdout, name, res, color, outputPath)
	}

	data, err := report.Render(format, res, report.Options{Color: color, ShowFix: a.Config.Output.ShowFix})
	if err != nil {
		return err
	}
	if outputPath == "" || outputPath == "-" {
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	} else {
		if err := writeFile(outputPath, data); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote %s\n", outputPath)
	}

	if failOn != "" && hasFindingsAtLeast(res.Findings, failOn) {
		return ErrFindings
	}
	return nil
}

func (o *scanOptions) resolvePath(positional []string) (string, error) {
	if len(positional) > 1 {
		return "", fmt.Errorf("expected at most one path, got %d", len(positional))
	}
	if len(positional) == 1 {
		if o.path != "" && o.path != positional[0] {
			return "", fmt.Errorf("path given twice (%q and %q)", o.path, positional[0])
		}
		return positional[0], nil
	}
	if o.path != "" {
		return o.path, nil
	}
	return ".", nil
}

func (o *scanOptions) request(root string) (model.ScanRequest, error) {
	req := model.ScanRequest{
		Root:         root,
		Mode:         strings.TrimSpace(o.mode),
		ChangedOnly:  o.changed,
		BaseRef:      strings.TrimSpace(o.base),
		DeepReview:   o.deep,
		ThreatModel:  o.threatModel,
		Include:      append([]string(nil), o.include...),
		Exclude:      append([]string(nil), o.exclude...),
		OnlyRules:    append([]string(nil), o.rules...),
		DisableRules: append([]string(nil), o.disable...),
		MaxFindings:  o.maxFindings,
		NoBaseline:   o.noBaseline,
	}
	if o.noLLM {
		disabled := false
		req.UseLLM = &disabled
	}
	if o.deep && req.Mode == "" {
		req.Mode = "deep"
	}
	if o.minSeverity != "" {
		sev, err := parseSeverity(o.minSeverity)
		if err != nil {
			return req, fmt.Errorf("--min-severity: %w", err)
		}
		req.MinSeverity = sev
	}
	if strings.TrimSpace(o.diff) != "" {
		diff, err := readDiff(o.diff)
		if err != nil {
			return req, err
		}
		req.Diff = diff
	}
	return req, nil
}

func (o *scanOptions) failOnSeverity() (model.Severity, error) {
	if strings.TrimSpace(o.failOn) == "" {
		return "", nil
	}
	sev, err := parseSeverity(o.failOn)
	if err != nil {
		return "", fmt.Errorf("--fail-on: %w", err)
	}
	return sev, nil
}

func readDiff(source string) (string, error) {
	if source == "-" {
		data, err := io.ReadAll(stdinReader)
		if err != nil {
			return "", fmt.Errorf("read diff from stdin: %w", err)
		}
		if strings.TrimSpace(string(data)) == "" {
			return "", errors.New("--diff -: stdin is empty; pipe a unified diff or pass a file")
		}
		return string(data), nil
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return "", fmt.Errorf("read diff %s: %w", source, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return "", fmt.Errorf("diff file %s is empty", source)
	}
	return string(data), nil
}

func hasFindingsAtLeast(findings []model.Finding, min model.Severity) bool {
	for _, f := range findings {
		if f.Severity.AtLeast(min) {
			return true
		}
	}
	return false
}

// printSummary prints a compact human overview. It deliberately does not repeat
// the full report: only the counts and the ten most severe findings.
func printSummary(w io.Writer, title string, res *model.ScanResult, color bool, outputPath string) {
	mode := res.Mode
	if mode == "" {
		mode = "standard"
	}
	modelName := "deterministic rules only"
	if res.Model != nil && (res.Model.Provider != "" || res.Model.Model != "") {
		modelName = strings.TrimPrefix(strings.TrimSpace(res.Model.Provider+"/"+res.Model.Model), "/")
	}
	reportTarget := "stdout"
	if outputPath != "" && outputPath != "-" {
		reportTarget = outputPath
	}

	fmt.Fprintf(w, "vigil %s · %s\n", title, displayPath(res.Root))
	fmt.Fprintf(w, "  mode      %s\n", mode)
	fmt.Fprintf(w, "  model     %s\n", modelName)
	fmt.Fprintf(w, "  files     %d scanned, %d skipped\n", res.Stats.FilesScanned, res.Stats.FilesSkipped)
	fmt.Fprintf(w, "  duration  %s\n", formatDuration(res.Stats.DurationMS))
	fmt.Fprintf(w, "  findings  %s\n", severitySummary(res.Stats.BySeverity))
	fmt.Fprintf(w, "  report    %s\n", reportTarget)

	if len(res.Findings) == 0 {
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintln(w)
	limit := len(res.Findings)
	if limit > 10 {
		limit = 10
	}
	for _, f := range res.Findings[:limit] {
		label := fmt.Sprintf("%-8s", strings.ToUpper(string(f.Severity)))
		label = paint(label, severityColor(f.Severity), color)
		location := f.Location.Path
		if f.Location.StartLine > 0 {
			location = fmt.Sprintf("%s:%d", location, f.Location.StartLine)
		}
		fmt.Fprintf(w, "  %s %s  %s — %s\n", label, location, f.RuleID, oneLine(f.Title))
	}
	if len(res.Findings) > limit {
		fmt.Fprintf(w, "  … %d more in the report\n", len(res.Findings)-limit)
	}
	fmt.Fprintln(w)
}

func severitySummary(counts map[model.Severity]int) string {
	order := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func printScanUsage(w io.Writer, name string, review bool) {
	changed := "  --changed              scan only files changed against --base\n"
	if review {
		changed = ""
	}
	fmt.Fprintf(w, `Usage: vigil %s [path] [flags]

Scans a repository or directory with deterministic rules and, when a model is
configured, LLM triage.

Flags:
  --path DIR             scan root (default .)
%s  --base REF             git ref to diff against (default HEAD)
  --diff FILE            scan added lines from a unified diff ("-" = stdin)
  --mode MODE            quick, standard or deep
  --no-llm               deterministic rules only
  --deep                 run the deep LLM review
  --threat-model         generate a threat model during the scan
  --include GLOB         only scan matching files (repeatable, comma-separated)
  --exclude GLOB         skip matching files (repeatable, comma-separated)
  --rules ID[,ID]        run only these rules
  --disable ID[,ID]      skip these rules
  --min-severity LEVEL   low, medium, high or critical
  --max-findings N       cap the number of findings
  --no-baseline          ignore the suppression baseline
  --format FMT           md, json, sarif or html
  --output FILE          write the report to FILE ("-" = stdout)
  --fail-on LEVEL        exit 2 when a finding at or above LEVEL exists
  --quiet                skip the human summary
  --color MODE           auto, always or never
`, name, changed)
}

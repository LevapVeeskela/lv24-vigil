package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/osv"
)

// dependencyLimitations is the honest coverage statement printed with every
// audit. It is deliberately blunt: OSV has no zero-day feed.
var dependencyLimitations = []string{
	"Known public OSV advisories only. An unpublished, private or zero-day vulnerability is not covered.",
	"No matching advisory does not establish that a package is safe.",
	"Only exact versions from supported manifests and lockfiles are queried; runtime-resolved, vendored or dynamically installed packages may differ.",
	"Advisory applicability to a forked, backported or vendor-patched build is not established.",
	"No package manager runs, no files are written and no telemetry is sent. The only network request is the OSV querybatch call.",
}

type dependencyAuditReport struct {
	Root        string          `json:"root"`
	Packages    []osv.Package   `json:"packages"`
	Findings    []model.Finding `json:"findings"`
	Errors      []string        `json:"errors"`
	Limitations []string        `json:"limitations"`
}

func runDependencies(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("dependencies")
	flagPath := fs.String("path", "", "directory to audit (default .); a positional path also works")
	includeDev := fs.Bool("include-dev", true, "include dev dependencies")
	maxPackages := fs.Int("max-packages", osv.DefaultMaxPackages, "maximum distinct packages to query")
	baseURL := fs.String("osv-base-url", "", "OSV API root (default from config or https://api.osv.dev)")
	format := fs.String("format", "md", "output format: md or json")
	failOn := fs.String("fail-on", "", "exit 2 when a finding at or above this severity exists")

	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, `Usage: vigil dependencies [path] [flags]

Reads supported manifests and lockfiles, then queries the public OSV.dev
database for the exact package versions found. Known public advisories only:
no match does not mean safe, and zero-day vulnerabilities are not covered.

Flags:
  --path DIR              directory to audit (default .); a positional path also works
  --include-dev           include dev dependencies (default true)
  --max-packages N        maximum distinct packages to query (default 200, cap 1000)
  --osv-base-url URL      OSV API root (default from config or https://api.osv.dev)
  --format md|json        output format (default md)
  --fail-on LEVEL         exit 2 when a finding at or above LEVEL exists
`)
		return nil
	}
	if err != nil {
		return fmt.Errorf("dependencies: %w", err)
	}

	root, err := resolveDependenciesPath(positional, *flagPath)
	if err != nil {
		return err
	}
	if *maxPackages <= 0 {
		return fmt.Errorf("dependencies: --max-packages must be a positive integer (default %d, cap %d)", osv.DefaultMaxPackages, osv.MaxAllowedPackages)
	}
	if *maxPackages > osv.MaxAllowedPackages {
		*maxPackages = osv.MaxAllowedPackages
	}
	formatName := strings.ToLower(strings.TrimSpace(*format))
	if formatName != "md" && formatName != "json" {
		return fmt.Errorf("dependencies: --format must be md or json (got %q)", *format)
	}
	var failSeverity model.Severity
	if strings.TrimSpace(*failOn) != "" {
		failSeverity, err = parseSeverity(*failOn)
		if err != nil {
			return fmt.Errorf("dependencies: --fail-on: %w", err)
		}
	}

	cfg, err := config.Load(root)
	if err != nil {
		return fmt.Errorf("dependencies: %w", err)
	}
	opts := osv.DefaultOptions()
	opts.MaxPackages = *maxPackages
	opts.IncludeDev = *includeDev
	if endpoint := firstNonEmpty(*baseURL, cfg.Scan.OSVBaseURL); endpoint != "" {
		opts.BaseURL = endpoint
	}

	ctx, stop := signalContext()
	defer stop()
	audit, auditErr := osv.Audit(ctx, root, opts)
	if auditErr != nil && audit == nil {
		return fmt.Errorf("dependencies: %w", auditErr)
	}
	if audit == nil {
		audit = &osv.AuditResult{}
	}
	report := dependencyAuditReport{
		Root:        root,
		Packages:    nonNilDependencyPackages(audit.Packages),
		Findings:    nonNilDependencyFindings(audit.Findings),
		Errors:      append([]string{}, audit.Errors...),
		Limitations: append([]string{}, dependencyLimitations...),
	}
	if auditErr != nil {
		report.Errors = append(report.Errors, auditErr.Error())
	}

	switch formatName {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("dependencies: encode report: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "%s\n", data); err != nil {
			return fmt.Errorf("dependencies: write report: %w", err)
		}
	default:
		printDependencyReport(stdout, report, *includeDev, *maxPackages)
	}

	if failSeverity != "" && hasFindingsAtLeast(report.Findings, failSeverity) {
		return ErrFindings
	}
	return nil
}

func resolveDependenciesPath(positional []string, flagPath string) (string, error) {
	if len(positional) > 1 {
		return "", fmt.Errorf("dependencies: expected at most one path, got %d", len(positional))
	}
	p := flagPath
	if len(positional) == 1 {
		if p != "" && p != positional[0] {
			return "", fmt.Errorf("dependencies: path given twice (%q and %q)", p, positional[0])
		}
		p = positional[0]
	}
	if p == "" {
		p = "."
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("dependencies: resolve %q: %w", p, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("dependencies: %q does not exist or is not readable", abs)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("dependencies: %q is not a directory", abs)
	}
	return abs, nil
}

func printDependencyReport(w io.Writer, report dependencyAuditReport, includeDev bool, maxPackages int) {
	dev := "dev dependencies included"
	if !includeDev {
		dev = "dev dependencies excluded"
	}
	fmt.Fprintln(w, "vigil dependencies — known public advisories only")
	fmt.Fprintf(w, "  root      %s\n", report.Root)
	fmt.Fprintf(w, "  packages  %d queried (%s, max %d)\n", len(report.Packages), dev, maxPackages)
	fmt.Fprintf(w, "  findings  %s\n", dependencySeverityLine(report.Findings))
	if len(report.Errors) > 0 {
		fmt.Fprintf(w, "  warnings  %s\n", strings.Join(report.Errors, "; "))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Known public advisories only; no match does not mean safe. Zero-day,")
	fmt.Fprintln(w, "private and unpublished advisories are not covered.")
	if len(report.Findings) == 0 {
		if len(report.Packages) == 0 {
			fmt.Fprintln(w, "\nNo supported dependency manifests were found. Nothing was queried.")
		} else if len(report.Errors) > 0 {
			fmt.Fprintln(w, "\nThe query reported warnings, so coverage is incomplete.")
		} else {
			fmt.Fprintln(w, "\nNo known public advisory matched the queried packages.")
		}
		return
	}
	fmt.Fprintln(w)
	for i, f := range report.Findings {
		if i >= 20 {
			fmt.Fprintf(w, "  ... and %d more (use --format json for the full list)\n", len(report.Findings)-i)
			break
		}
		location := f.Location.Path
		if f.Location.StartLine > 0 {
			location = fmt.Sprintf("%s:%d", location, f.Location.StartLine)
		}
		fmt.Fprintf(w, "  %-8s %s — %s\n", strings.ToUpper(string(f.Severity)), f.Title, location)
	}
}

func dependencySeverityLine(findings []model.Finding) string {
	order := []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo}
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	parts := make([]string, 0, len(order))
	for _, s := range order {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, counts[s]))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func nonNilDependencyPackages(in []osv.Package) []osv.Package {
	if in == nil {
		return []osv.Package{}
	}
	return in
}

func nonNilDependencyFindings(in []model.Finding) []model.Finding {
	if in == nil {
		return []model.Finding{}
	}
	return in
}

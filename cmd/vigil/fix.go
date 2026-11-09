package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/model"
)

func runFix(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("fix")
	scanID := fs.String("scan", "", "scan ID that contains the finding (default: last scan)")
	apply := fs.Bool("apply", false, "apply the proposed diff to the working tree")
	root := fs.String("root", ".", "project root")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, `Usage: vigil fix FINDING_ID [--scan ID] [--apply] [--root DIR]

Asks the configured model for a minimal fix, prints the description and the
unified diff, and optionally applies it. Vigil never commits.
`)
		return nil
	}
	if err != nil {
		return fmt.Errorf("fix: %w", err)
	}
	if len(positional) != 1 {
		return errors.New("usage: vigil fix FINDING_ID [--scan ID] [--apply] [--root DIR]")
	}
	findingID := positional[0]

	a, err := buildApp(*root, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	printWarnings(stderr, a.Warnings)

	res, err := loadScan(a, *scanID)
	if err != nil {
		return err
	}
	finding, err := findFinding(res, findingID)
	if err != nil {
		return err
	}

	location := finding.Location.Path
	if finding.Location.StartLine > 0 {
		location = fmt.Sprintf("%s:%d", location, finding.Location.StartLine)
	}
	fmt.Fprintf(stdout, "%s %s · %s\n%s\n\n", finding.ID, strings.ToUpper(string(finding.Severity)), location, oneLine(finding.Title))

	ctx, stop := signalContext()
	defer stop()

	fix, err := a.ProposeFix(ctx, finding)
	if err != nil {
		return err
	}
	if fix == nil {
		return errors.New("the model returned no fix")
	}
	if desc := strings.TrimSpace(fix.Description); desc != "" {
		fmt.Fprintf(stdout, "Fix: %s\n\n", desc)
	}
	if strings.TrimSpace(fix.Diff) == "" {
		if *apply {
			return errors.New("refusing to apply: the proposed fix is empty")
		}
		fmt.Fprintln(stdout, "No diff was proposed for this finding.")
		return nil
	}

	fmt.Fprintln(stdout, strings.TrimRight(fix.Diff, "\n"))
	fmt.Fprintln(stdout)

	if *apply {
		if err := a.ApplyFix(ctx, fix); err != nil {
			return fmt.Errorf("apply fix: %w", err)
		}
		fmt.Fprintln(stdout, "applied")
		fmt.Fprintln(stdout, "The change is in your working tree; nothing was committed.")
		return nil
	}
	fmt.Fprintf(stdout, "Apply with: vigil fix %s --scan %s --apply\n", finding.ID, res.ID)
	return nil
}

// loadScan returns the requested scan, or the most recent one. Both errors are
// rewritten so a first-time user sees the next command to run.
func loadScan(a *app.App, id string) (*model.ScanResult, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		res, err := a.LastScan()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("no scans found; run `vigil scan` first")
			}
			return nil, fmt.Errorf("load last scan: %w", err)
		}
		return res, nil
	}
	res, err := a.GetScan(id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("scan %q not found; run `vigil scan` or check `vigil status`", id)
		}
		return nil, fmt.Errorf("load scan %s: %w", id, err)
	}
	return res, nil
}

// findFinding resolves an exact ID, a case-insensitive ID or a unique prefix.
// Suppressed findings are searchable too: they are still real issues that a
// user may want to fix or un-baseline.
func findFinding(res *model.ScanResult, id string) (model.Finding, error) {
	want := strings.TrimSpace(id)
	if want == "" {
		return model.Finding{}, errors.New("empty finding ID")
	}
	candidates := make([]model.Finding, 0, len(res.Findings)+len(res.Suppressed))
	candidates = append(candidates, res.Findings...)
	candidates = append(candidates, res.Suppressed...)

	for _, f := range candidates {
		if f.ID == want {
			return f, nil
		}
	}
	for _, f := range candidates {
		if strings.EqualFold(f.ID, want) {
			return f, nil
		}
	}

	var matches []model.Finding
	upper := strings.ToUpper(want)
	for _, f := range candidates {
		if strings.HasPrefix(strings.ToUpper(f.ID), upper) {
			matches = append(matches, f)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return model.Finding{}, fmt.Errorf("finding %q not found in scan %s; run `vigil scan` to refresh it", id, res.ID)
	default:
		ids := make([]string, 0, len(matches))
		for _, f := range matches {
			ids = append(ids, f.ID)
		}
		return model.Finding{}, fmt.Errorf("finding ID %q is ambiguous: %s", id, strings.Join(ids, ", "))
	}
}

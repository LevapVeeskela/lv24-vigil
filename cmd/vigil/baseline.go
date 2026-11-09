package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
)

func runBaseline(args []string, stdout, stderr io.Writer) error {
	sub := "list"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest = args[0], args[1:]
	}

	a, err := buildApp(".", stderr)
	if err != nil {
		return err
	}
	defer a.Close()

	switch sub {
	case "list":
		return baselineList(a, rest, stdout)
	case "add":
		return baselineAdd(a, rest, stdout)
	case "remove", "rm", "delete":
		return baselineRemove(a, rest, stdout)
	case "clear", "reset":
		return baselineClear(a, rest, stdout)
	default:
		return fmt.Errorf("unknown baseline subcommand %q (use list, add, remove or clear)", sub)
	}
}

func baselineList(a *app.App, args []string, stdout io.Writer) error {
	fs := newFlagSet("baseline list")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printBaselineUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("baseline list: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("baseline list takes no arguments (got %q)", positional[0])
	}

	path := baselinePath(a)
	baseline, err := scanner.LoadBaseline(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "baseline: %s\n", path)
	if len(baseline.Findings) == 0 && len(baseline.Fingerprints) == 0 {
		fmt.Fprintln(stdout, "  empty (no suppressed findings)")
		return nil
	}
	fmt.Fprintf(stdout, "  %d accepted finding(s), %d fingerprint(s)\n", len(baseline.Findings), len(baseline.Fingerprints))
	for _, entry := range baseline.Findings {
		reason := strings.TrimSpace(entry.Reason)
		if reason == "" {
			reason = "-"
		}
		fmt.Fprintf(stdout, "  %s  %s\n", entry.ID, reason)
	}
	return nil
}

func baselineAdd(a *app.App, args []string, stdout io.Writer) error {
	fs := newFlagSet("baseline add")
	reason := fs.String("reason", "", "why the finding is accepted")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printBaselineUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("baseline add: %w", err)
	}
	if len(positional) != 1 {
		return errors.New("usage: vigil baseline add FINDING_ID [--reason TEXT]")
	}

	path := baselinePath(a)
	baseline, err := scanner.LoadBaseline(path)
	if err != nil {
		return err
	}

	id := positional[0]
	// Enrich with a stored finding when possible: that also records the
	// fingerprint, so the entry survives small line moves.
	if finding, ok := lookupFinding(a, id); ok {
		id = finding.ID
		baseline.Add(finding, *reason)
	}
	if !baselineHasID(baseline, id) {
		baseline.Findings = append(baseline.Findings, scanner.BaselineFinding{
			ID:     id,
			Reason: strings.TrimSpace(*reason),
		})
	}

	if err := scanner.SaveBaseline(path, baseline); err != nil {
		return err
	}
	if strings.TrimSpace(*reason) != "" {
		fmt.Fprintf(stdout, "added %s to %s (%s)\n", id, path, strings.TrimSpace(*reason))
	} else {
		fmt.Fprintf(stdout, "added %s to %s\n", id, path)
	}
	return nil
}

func baselineRemove(a *app.App, args []string, stdout io.Writer) error {
	fs := newFlagSet("baseline remove")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printBaselineUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("baseline remove: %w", err)
	}
	if len(positional) != 1 {
		return errors.New("usage: vigil baseline remove FINDING_ID")
	}

	path := baselinePath(a)
	baseline, err := scanner.LoadBaseline(path)
	if err != nil {
		return err
	}

	id := positional[0]
	// A baseline entry may have a fingerprint next to its ID. Removing only the
	// ID would leave the finding suppressed, so resolve the fingerprint from
	// scan history as well.
	fingerprint := ""
	if finding, ok := lookupFinding(a, id); ok {
		id = finding.ID
		fingerprint = finding.Fingerprint
		if fingerprint == "" {
			fingerprint = finding.ComputeFingerprint()
		}
	}

	kept := make([]scanner.BaselineFinding, 0, len(baseline.Findings))
	removed := false
	for _, entry := range baseline.Findings {
		if strings.EqualFold(entry.ID, id) {
			removed = true
			continue
		}
		kept = append(kept, entry)
	}
	if !removed {
		return fmt.Errorf("baseline entry %q not found in %s; run `vigil baseline list`", id, path)
	}
	baseline.Findings = kept
	if fingerprint != "" {
		baseline.Fingerprints = removeString(baseline.Fingerprints, fingerprint)
	}

	if err := scanner.SaveBaseline(path, baseline); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "removed %s from %s\n", id, path)
	return nil
}

func baselineClear(a *app.App, args []string, stdout io.Writer) error {
	fs := newFlagSet("baseline clear")
	yes := fs.Bool("yes", false, "confirm clearing the baseline")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printBaselineUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("baseline clear: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("baseline clear takes no arguments (got %q)", positional[0])
	}
	if !*yes {
		return errors.New("refusing to clear the baseline; pass --yes to confirm")
	}

	path := baselinePath(a)
	if err := scanner.SaveBaseline(path, scanner.NewBaseline()); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "cleared %s\n", path)
	return nil
}

// baselinePath resolves the configured baseline file against the project root.
func baselinePath(a *app.App) string {
	path := strings.TrimSpace(a.Config.Scan.Baseline)
	if path == "" {
		path = scanner.DefaultBaselineFile
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(a.Root, path)
	}
	return filepath.Clean(path)
}

// lookupFinding searches the last scan and then recent history for a finding.
// History matters for `baseline remove`: the issue may already be fixed, so it
// is no longer in the newest scan even though its fingerprint is still stored.
func lookupFinding(a *app.App, id string) (model.Finding, bool) {
	last, lastErr := a.LastScan()
	if lastErr == nil {
		if finding, err := findFinding(last, id); err == nil {
			return finding, true
		}
	}

	summaries, err := a.Store.List(20)
	if err != nil {
		return model.Finding{}, false
	}
	for _, summary := range summaries {
		if lastErr == nil && summary.ID == last.ID {
			continue
		}
		res, err := a.Store.Get(summary.ID)
		if err != nil {
			continue
		}
		if finding, err := findFinding(res, id); err == nil {
			return finding, true
		}
	}
	return model.Finding{}, false
}

func baselineHasID(baseline *scanner.Baseline, id string) bool {
	for _, entry := range baseline.Findings {
		if strings.EqualFold(entry.ID, id) {
			return true
		}
	}
	return false
}

func removeString(values []string, want string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if value != want {
			kept = append(kept, value)
		}
	}
	return kept
}

func printBaselineUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: vigil baseline [list|add|remove|clear]

  vigil baseline list
  vigil baseline add FINDING_ID [--reason TEXT]
  vigil baseline remove FINDING_ID
  vigil baseline clear --yes

The baseline file is <root>/<scan.baseline> (default .vigil-baseline.json).
Accepted findings stay in reports as suppressed findings but no longer fail
--fail-on.
`)
}

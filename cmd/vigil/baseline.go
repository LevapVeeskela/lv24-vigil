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
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
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
		return baselineRemove(a, rest, stdout, stderr)
	case "prune":
		return baselinePrune(a, rest, stdout)
	case "clear", "reset":
		return baselineClear(a, rest, stdout)
	default:
		return fmt.Errorf("unknown baseline subcommand %q (use list, add, remove, prune or clear)", sub)
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

	path, err := baselinePath(a)
	if err != nil {
		return err
	}
	baseline, err := scanner.LoadBaseline(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "baseline: %s\n", path)
	if len(baseline.Findings) == 0 && len(baseline.Fingerprints) == 0 {
		fmt.Fprintln(stdout, "  empty (no suppressed findings)")
		return nil
	}
	// Legacy fingerprints are materialized into entries at load time, so the
	// entry count already covers both channels without double counting.
	fmt.Fprintf(stdout, "  %d accepted finding(s)\n", len(baseline.Findings))
	today := scanner.BaselineToday()
	for _, entry := range baseline.Findings {
		reason := strings.TrimSpace(entry.Reason)
		if reason == "" {
			reason = "-"
		}
		label := entry.ID
		if label == "" {
			label = entry.Fingerprint
		}
		if label == "" {
			label = "(unnamed)"
		}
		fields := []string{label, reason}
		if entry.Ticket != "" {
			fields = append(fields, "ticket="+entry.Ticket)
		}
		if entry.Expires != "" {
			expiry := "expires=" + entry.Expires
			if entry.Expired(today) {
				expiry += " (expired)"
			}
			fields = append(fields, expiry)
		}
		if entry.Path != "" {
			fields = append(fields, "path="+entry.Path)
		}
		if entry.RuleID != "" {
			fields = append(fields, "rule="+entry.RuleID)
		}
		fmt.Fprintf(stdout, "  %s\n", strings.Join(fields, "  "))
	}
	return nil
}

func baselineAdd(a *app.App, args []string, stdout io.Writer) error {
	fs := newFlagSet("baseline add")
	reason := fs.String("reason", "", "why the finding is accepted")
	ticket := fs.String("ticket", "", "ticket or issue reference for the acceptance")
	expires := fs.String("expires", "", "expiry date in YYYY-MM-DD (UTC)")
	scope := fs.String("path", "", "only suppress findings at this project-relative path")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printBaselineUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("baseline add: %w", err)
	}
	if len(positional) != 1 {
		return errors.New("usage: vigil baseline add FINDING_ID [--reason TEXT] [--ticket TEXT] [--expires YYYY-MM-DD] [--path PATH]")
	}

	expiresValue, err := baselineExpiryFlag(*expires)
	if err != nil {
		return fmt.Errorf("baseline add: %w", err)
	}
	scopeValue, err := baselineScopeFlag(*scope)
	if err != nil {
		return fmt.Errorf("baseline add: %w", err)
	}

	path, err := baselinePath(a)
	if err != nil {
		return err
	}
	baseline, err := scanner.LoadBaseline(path)
	if err != nil {
		return err
	}

	id := positional[0]
	entry := scanner.BaselineFinding{
		ID:      id,
		Reason:  strings.TrimSpace(*reason),
		Ticket:  strings.TrimSpace(*ticket),
		Expires: expiresValue,
		Path:    scopeValue,
	}
	// Enrich with a stored finding when possible: that also records the
	// fingerprint, so the entry survives small line moves.
	if finding, ok := lookupFinding(a, id); ok {
		id = finding.ID
		entry.ID = id
		entry.RuleID = strings.TrimSpace(finding.RuleID)
		fingerprint := finding.Fingerprint
		if fingerprint == "" {
			fingerprint = finding.ComputeFingerprint()
		}
		entry.Fingerprint = fingerprint
		if scopeValue != "" && !sameScopePath(scopeValue, finding.Location.Path) {
			return fmt.Errorf("baseline add: finding %s is at %s, not %s", id, finding.Location.Path, scopeValue)
		}
	}
	baseline.AddEntry(entry)

	if err := scanner.SaveBaseline(path, baseline); err != nil {
		return err
	}
	if entry.Reason != "" {
		fmt.Fprintf(stdout, "added %s to %s (%s)\n", id, path, entry.Reason)
	} else {
		fmt.Fprintf(stdout, "added %s to %s\n", id, path)
	}
	if entry.Ticket != "" {
		fmt.Fprintf(stdout, "ticket: %s\n", entry.Ticket)
	}
	if entry.Expires != "" {
		fmt.Fprintf(stdout, "expires: %s\n", entry.Expires)
	}
	if entry.Path != "" {
		fmt.Fprintf(stdout, "path: %s\n", entry.Path)
	}
	return nil
}

func baselinePrune(a *app.App, args []string, stdout io.Writer) error {
	fs := newFlagSet("baseline prune")
	dryRun := fs.Bool("dry-run", false, "report expired entries without removing them")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printBaselineUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("baseline prune: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("baseline prune takes no arguments (got %q)", positional[0])
	}

	path, err := baselinePath(a)
	if err != nil {
		return err
	}
	baseline, err := scanner.LoadBaseline(path)
	if err != nil {
		return err
	}
	removed := baseline.PruneExpired(scanner.BaselineToday())
	if *dryRun {
		fmt.Fprintf(stdout, "would prune %d expired baseline entr%s from %s\n",
			len(removed), plural(len(removed), "y", "ies"), path)
	} else {
		if len(removed) > 0 {
			if err := scanner.SaveBaseline(path, baseline); err != nil {
				return err
			}
		}
		fmt.Fprintf(stdout, "pruned %d expired baseline entr%s from %s\n",
			len(removed), plural(len(removed), "y", "ies"), path)
	}
	for _, entry := range removed {
		label := entry.ID
		if label == "" {
			label = entry.Fingerprint
		}
		fmt.Fprintf(stdout, "  %s  expired %s\n", label, entry.Expires)
	}
	return nil
}

func baselineRemove(a *app.App, args []string, stdout, stderr io.Writer) error {
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

	path, err := baselinePath(a)
	if err != nil {
		return err
	}
	baseline, err := scanner.LoadBaseline(path)
	if err != nil {
		return err
	}

	id := positional[0]
	// A baseline entry may carry a fingerprint next to its ID, and a version-1
	// fingerprint is stored as a fingerprint-only entry. Resolve the finding so
	// every acceptance for it is removed, not just the entry that matched by ID.
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
	removedFingerprints := make([]string, 0, 2)
	for _, entry := range baseline.Findings {
		if !baselineEntryMatches(entry, id, fingerprint) {
			kept = append(kept, entry)
			continue
		}
		removed = true
		if entry.Fingerprint != "" {
			removedFingerprints = append(removedFingerprints, entry.Fingerprint)
		}
	}
	if !removed {
		return fmt.Errorf("baseline entry %q not found in %s; run `vigil baseline list`", id, path)
	}
	// A version-2 entry can be mirrored by a separate fingerprint-only entry.
	// Drop every surviving entry that carries a fingerprint of a removed entry,
	// otherwise the finding stays accepted after a successful-looking remove.
	kept = removeEntriesByFingerprints(kept, removedFingerprints)

	// A version-1 ID entry carries no fingerprint, and without a stored scan no
	// fingerprint resolves. When that ID entry was the only named entry, the
	// single remaining legacy fingerprint entry is its top-level mirror; drop it
	// too rather than reporting success while it keeps suppressing the finding.
	droppedLegacy := ""
	if fingerprint == "" && len(kept) == 1 && isLegacyFingerprintEntry(kept[0]) {
		droppedLegacy = kept[0].Fingerprint
		kept = nil
	}
	baseline.Findings = kept
	// Fingerprints stay in the legacy list as a compatibility mirror, so drop
	// every one that belonged to a removed entry plus the requested value and
	// the fingerprint resolved from scan history. A stale mirror entry would be
	// materialized back into an acceptance on the next load.
	removeFingerprints := append(removedFingerprints, id)
	if fingerprint != "" {
		removeFingerprints = append(removeFingerprints, fingerprint)
	}
	if droppedLegacy != "" {
		removeFingerprints = append(removeFingerprints, droppedLegacy)
	}
	for _, removedFingerprint := range removeFingerprints {
		baseline.Fingerprints = removeStringFold(baseline.Fingerprints, removedFingerprint)
	}

	if err := scanner.SaveBaseline(path, baseline); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "removed %s from %s\n", id, path)
	if droppedLegacy != "" {
		fmt.Fprintf(stdout, "removed legacy fingerprint %s from %s\n", droppedLegacy, path)
	}
	if fingerprint == "" {
		for _, entry := range kept {
			if !isLegacyFingerprintEntry(entry) {
				continue
			}
			fmt.Fprintf(stderr, "baseline remove: warning: legacy fingerprint %s in %s may still suppress this finding; run `vigil baseline remove %s` to drop it\n",
				entry.Fingerprint, path, entry.Fingerprint)
		}
	}
	return nil
}

// removeEntriesByFingerprints drops every entry whose fingerprint is in
// fingerprints (case-insensitively).
func removeEntriesByFingerprints(entries []scanner.BaselineFinding, fingerprints []string) []scanner.BaselineFinding {
	if len(entries) == 0 || len(fingerprints) == 0 {
		return entries
	}
	kept := make([]scanner.BaselineFinding, 0, len(entries))
	for _, entry := range entries {
		if entry.Fingerprint == "" || !matchesAnyFingerprint(fingerprints, entry.Fingerprint) {
			kept = append(kept, entry)
		}
	}
	return kept
}

func matchesAnyFingerprint(fingerprints []string, want string) bool {
	for _, fingerprint := range fingerprints {
		if strings.EqualFold(fingerprint, want) {
			return true
		}
	}
	return false
}

// legacyFingerprintEntryReason mirrors the reason scanner.LoadBaseline gives a
// version-1 top-level fingerprint materialized as an entry.
const legacyFingerprintEntryReason = "legacy fingerprint"

func isLegacyFingerprintEntry(entry scanner.BaselineFinding) bool {
	return entry.ID == "" && entry.Fingerprint != "" && entry.Reason == legacyFingerprintEntryReason
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

	path, err := baselinePath(a)
	if err != nil {
		return err
	}
	if err := scanner.SaveBaseline(path, scanner.NewBaseline()); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "cleared %s\n", path)
	return nil
}

// baselinePath resolves the configured baseline file against the project root.
// The path is always confined to the root (including through symlinks); an
// absolute path is rejected even in the user config so the baseline cannot be
// used as an arbitrary-file read or write primitive.
func baselinePath(a *app.App) (string, error) {
	path := strings.TrimSpace(a.Config.Scan.Baseline)
	if path == "" {
		path = scanner.DefaultBaselineFile
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("baseline path %q must be relative to the project root", path)
	}
	resolved, err := safepath.Resolve(a.Root, path)
	if err != nil {
		return "", fmt.Errorf("baseline path %q: %w", path, err)
	}
	return resolved, nil
}

// baselineExpiryFlag validates --expires and returns the canonical date.
func baselineExpiryFlag(value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", nil
	}
	date, err := scanner.ParseBaselineDate(v)
	if err != nil {
		return "", fmt.Errorf("--expires: %w", err)
	}
	today := scanner.BaselineToday()
	if date.Before(today) {
		return "", fmt.Errorf("--expires %s is in the past (today is %s)",
			date.Format(scanner.BaselineDateLayout), today.Format(scanner.BaselineDateLayout))
	}
	return date.Format(scanner.BaselineDateLayout), nil
}

// baselineScopeFlag validates --path. The scope is only compared with finding
// paths, so it must be project-relative and cannot point above the root.
func baselineScopeFlag(value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", nil
	}
	if filepath.IsAbs(v) || strings.HasPrefix(v, "/") || (len(v) > 1 && v[1] == ':') {
		return "", fmt.Errorf("--path %q must be relative to the project root", value)
	}
	v = filepath.ToSlash(filepath.Clean(v))
	if v == "." || v == ".." || strings.HasPrefix(v, "../") {
		return "", fmt.Errorf("--path %q must name a file inside the project", value)
	}
	return v, nil
}

func sameScopePath(a, b string) bool {
	normalize := func(value string) string {
		value = filepath.ToSlash(filepath.Clean(strings.TrimSpace(value)))
		return strings.TrimPrefix(value, "./")
	}
	return strings.EqualFold(normalize(a), normalize(b))
}

func plural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
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

// baselineEntryMatches reports whether id or fingerprint identifies entry. The
// argument itself may be a fingerprint: version-1 fingerprints are stored as
// fingerprint-only entries, and fingerprint comparison is case-insensitive.
func baselineEntryMatches(entry scanner.BaselineFinding, id, fingerprint string) bool {
	if id != "" && strings.EqualFold(entry.ID, id) {
		return true
	}
	if id != "" && entry.Fingerprint != "" && strings.EqualFold(entry.Fingerprint, id) {
		return true
	}
	return fingerprint != "" && entry.Fingerprint != "" && strings.EqualFold(entry.Fingerprint, fingerprint)
}

func removeStringFold(values []string, want string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if !strings.EqualFold(value, want) {
			kept = append(kept, value)
		}
	}
	return kept
}

func printBaselineUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: vigil baseline [list|add|remove|prune|clear]

  vigil baseline list
  vigil baseline add FINDING_ID [--reason TEXT] [--ticket TEXT] [--expires YYYY-MM-DD] [--path PATH]
  vigil baseline remove FINDING_ID
  vigil baseline prune [--dry-run]
  vigil baseline clear --yes

The baseline file is <root>/<scan.baseline> (default .vigil-baseline.json).
Accepted findings stay in reports as suppressed findings but no longer fail
--fail-on. An entry with --expires stops suppressing after that UTC date;
baseline prune removes expired entries.
`)
}

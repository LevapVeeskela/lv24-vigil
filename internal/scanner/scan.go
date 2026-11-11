// Package scanner walks a repository, selects the files that should be
// inspected, runs the deterministic rules with a worker pool and applies
// baselines and unified-diff filtering.
//
// The scanner is read-only: it never executes or modifies the code it scans.
package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/gitutil"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
)

const (
	// EngineName identifies deterministic rule scans in reports and history.
	EngineName = "vigil-rules"
	// EngineVersion is the default version stamped on scan results.
	EngineVersion = "0.1.0-dev"

	defaultConcurrency = 4
	maxConcurrency     = 32
)

// Options controls a scan. The zero value is usable: Root defaults to the
// current directory, Concurrency to 4, MaxFileBytes to 2 MiB, Mode to
// "standard" and MinSeverity to "low".
type Options struct {
	Root         string
	Mode         string // quick|standard|deep
	ChangedOnly  bool
	BaseRef      string
	Diff         string
	Include      []string
	Exclude      []string
	OnlyRules    []string
	DisableRules []string
	MinSeverity  model.Severity // empty defaults to "low"
	MaxFindings  int            // 0 = unlimited; callers normally pass 200
	Concurrency  int            // 0 defaults to 4, capped at 32
	MaxFileBytes int64          // 0 defaults to 2 MiB
	FollowLinks  bool
	BaselinePath string // relative to Root; empty uses .vigil-baseline.json
	NoBaseline   bool
	OSV          bool
}

// Scanner runs a rule registry over files.
type Scanner struct {
	reg    *rules.Registry
	logger *slog.Logger
}

// New builds a scanner. A nil registry scans nothing; a nil logger discards
// diagnostics.
func New(reg *rules.Registry, logger *slog.Logger) *Scanner {
	if reg == nil {
		reg = rules.NewRegistry()
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Scanner{reg: reg, logger: logger}
}

// Scan resolves Root, selects files (whole tree, changed files or added diff
// lines) and runs the rules over them.
func (s *Scanner) Scan(ctx context.Context, opts Options) (*model.ScanResult, error) {
	started := time.Now().UTC()
	root, err := resolveRoot(opts.Root)
	if err != nil {
		return nil, err
	}
	opts.Root = root

	switch {
	case strings.TrimSpace(opts.Diff) != "":
		files, skipped, errs, err := buildDiffFiles(ctx, root, opts)
		if err != nil {
			return nil, err
		}
		return s.scanFiles(ctx, files, opts, skipped, errs, started)
	case opts.ChangedOnly:
		paths, err := gitutil.ChangedFiles(ctx, root, opts.BaseRef)
		if err != nil {
			return nil, err
		}
		return s.ScanPaths(ctx, root, filterChangedPaths(paths, opts), opts)
	default:
		walked, err := walkFiles(ctx, root, opts)
		if err != nil {
			return nil, err
		}
		return s.scanFiles(ctx, walked.files, opts, walked.skipped, walked.errs, started)
	}
}

// ScanFiles runs the selected rules over files that the caller has already
// loaded. It is used by the MCP review path and by fix verification.
func (s *Scanner) ScanFiles(ctx context.Context, files []*rules.File, opts Options) (*model.ScanResult, error) {
	started := time.Now().UTC()
	if strings.TrimSpace(opts.Root) != "" {
		if abs, err := filepath.Abs(opts.Root); err == nil {
			opts.Root = filepath.Clean(abs)
		}
	}
	return s.scanFiles(ctx, files, opts, 0, nil, started)
}

// ScanPaths scans exactly the given paths, relative to root (absolute paths
// inside root are accepted too). Size, binary and language handling still
// applies; ignore/include patterns do not, because the caller has already made
// an explicit selection.
func (s *Scanner) ScanPaths(ctx context.Context, root string, paths []string, opts Options) (*model.ScanResult, error) {
	started := time.Now().UTC()
	rootAbs, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}
	opts.Root = rootAbs

	maxBytes := effectiveMaxFileBytes(opts.MaxFileBytes)
	var (
		files   []*rules.File
		skipped int
		errs    []string
	)
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		absPath, relPath, ok := resolveInput(rootAbs, p)
		if !ok {
			skipped++
			errs = append(errs, fmt.Sprintf("skip %q: outside scan root", p))
			continue
		}
		if seen[relPath] {
			continue
		}
		seen[relPath] = true
		f, err := loadFile(absPath, relPath, maxBytes, opts.FollowLinks)
		if err != nil {
			skipped++
			if !isSkipError(err) && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Sprintf("read %s: %v", relPath, err))
			}
			continue
		}
		files = append(files, f)
	}
	return s.scanFiles(ctx, files, opts, skipped, errs, started)
}

func (s *Scanner) scanFiles(ctx context.Context, input []*rules.File, opts Options, skipped int, initialErrors []string, started time.Time) (*model.ScanResult, error) {
	if started.IsZero() {
		started = time.Now().UTC()
	}
	files, prepSkipped := prepareInputFiles(input)
	skipped += prepSkipped

	selected := s.selectedRules(opts)
	res := &model.ScanResult{
		StartedAt: started,
		Root:      opts.Root,
		Mode:      modeOrDefault(opts.Mode),
		Engine:    EngineName,
		Version:   EngineVersion,
	}
	res.Errors = append(res.Errors, initialErrors...)

	res.Stats.FilesScanned = len(files)
	res.Stats.FilesSkipped = skipped
	res.Stats.RulesRun = len(selected)
	for _, f := range files {
		res.Stats.BytesScanned += int64(len(f.Content))
	}

	findings, ruleErrs, runErr := s.runRules(ctx, files, selected, opts.Concurrency)
	res.Errors = append(res.Errors, ruleErrs...)
	findings = dedupeFindings(findings)

	kept, suppressed, baselineErrs := applyBaseline(findings, opts)
	res.Errors = append(res.Errors, baselineErrs...)

	min := opts.MinSeverity
	if min == "" {
		min = model.SeverityLow
	}
	kept = filterBySeverity(kept, min)

	model.SortFindings(kept)
	model.SortFindings(suppressed)
	if opts.MaxFindings > 0 && len(kept) > opts.MaxFindings {
		kept = kept[:opts.MaxFindings]
	}

	res.Findings = kept
	res.Suppressed = suppressed
	res.Stats.BySeverity = map[model.Severity]int{}
	res.Stats.ByCategory = map[model.Category]int{}
	for _, f := range kept {
		res.Stats.BySeverity[f.Severity]++
		res.Stats.ByCategory[f.Category]++
	}

	finished := time.Now().UTC()
	res.FinishedAt = finished
	res.Stats.DurationMS = finished.Sub(started).Milliseconds()
	res.ID = newScanID()

	if runErr != nil {
		return res, runErr
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	return res, nil
}

// filterChangedPaths applies the same hard-skip directories and include/exclude
// patterns as a normal walk. Changed mode gets its paths from git, so without
// this a repository's own .vigil history, node_modules or generated bundles
// would be scanned as if they were source.
func filterChangedPaths(paths []string, opts Options) []string {
	excludes := append(defaultExcludePatterns(), opts.Exclude...)
	matcher := newIgnoreMatcher(excludes, opts.Include)
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if hasHardSkipSegment(p) || matcher.ignored(p, false) || !matcher.included(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (s *Scanner) selectedRules(opts Options) []rules.Rule {
	if s == nil || s.reg == nil {
		return nil
	}
	return s.reg.Filter(opts.OnlyRules, opts.DisableRules)
}

// runRules executes every selected rule against every file using a bounded
// worker pool. A panic in one rule is converted into an error entry; it never
// aborts the rest of the scan.
func (s *Scanner) runRules(ctx context.Context, files []*rules.File, selected []rules.Rule, concurrency int) ([]model.Finding, []string, error) {
	if len(files) == 0 || len(selected) == 0 {
		return nil, nil, nil
	}

	workers := concurrency
	if workers <= 0 {
		workers = defaultConcurrency
	}
	if workers > maxConcurrency {
		workers = maxConcurrency
	}
	if workers > len(files) {
		workers = len(files)
	}

	type job struct {
		index int
		file  *rules.File
	}
	type outcome struct {
		index    int
		findings []model.Finding
		errs     []string
	}

	jobs := make(chan job)
	outs := make(chan outcome)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				out := outcome{index: j.index}
				for _, rule := range selected {
					if ctx.Err() != nil {
						break
					}
					found, err := safeCheck(rule, j.file)
					if err != nil {
						out.errs = append(out.errs, err.Error())
						if s.logger != nil {
							s.logger.Debug("rule check failed", "error", err)
						}
						continue
					}
					out.findings = append(out.findings, found...)
				}
				outs <- out
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i, f := range files {
			select {
			case jobs <- job{index: i, file: f}:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(outs)
	}()

	outcomes := make([]outcome, len(files))
	for out := range outs {
		outcomes[out.index] = out
	}

	var findings []model.Finding
	var errs []string
	for _, out := range outcomes {
		findings = append(findings, out.findings...)
		errs = append(errs, out.errs...)
	}
	return findings, errs, ctx.Err()
}

func safeCheck(rule rules.Rule, f *rules.File) (findings []model.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rule %s panicked on %s: %v", rule.Meta().ID, f.Path, r)
			findings = nil
		}
	}()
	return rule.Check(f), nil
}

func prepareInputFiles(input []*rules.File) ([]*rules.File, int) {
	out := make([]*rules.File, 0, len(input))
	skipped := 0
	for _, f := range input {
		if f == nil {
			skipped++
			continue
		}
		f.Path = filepath.ToSlash(f.Path)
		if f.Content == nil && f.Lines != nil {
			f.Content = []byte(strings.Join(f.Lines, "\n"))
		}
		if len(f.Lines) == 0 && len(f.Content) > 0 {
			f.Lines = splitLines(f.Content)
		}
		for i := range f.Lines {
			f.Lines[i] = strings.TrimSuffix(f.Lines[i], "\r")
		}
		if f.Language == "" {
			f.Language = DetectLanguage(f.Path)
		}
		f.Size = len(f.Content)
		out = append(out, f)
	}
	return out, skipped
}

func dedupeFindings(in []model.Finding) []model.Finding {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]model.Finding, 0, len(in))
	for i := range in {
		f := in[i]
		f.Normalize()
		if f.ID != "" {
			if _, ok := seen[f.ID]; ok {
				continue
			}
			seen[f.ID] = struct{}{}
		}
		out = append(out, f)
	}
	return out
}

// MergeFindings adds findings produced outside the rule engine (OSV
// advisories) to res after the rule-level gates: disabled rules and the
// baseline. Without it such findings could not be accepted into the baseline.
// The caller re-applies the minimum severity, sort, cap and stats once all
// findings are in.
func MergeFindings(res *model.ScanResult, extra []model.Finding, opts Options) {
	if res == nil || len(extra) == 0 {
		return
	}
	disabled := make(map[string]bool, len(opts.DisableRules))
	for _, id := range opts.DisableRules {
		disabled[strings.ToUpper(strings.TrimSpace(id))] = true
	}
	filtered := make([]model.Finding, 0, len(extra))
	for _, f := range extra {
		if !disabled[strings.ToUpper(f.RuleID)] {
			filtered = append(filtered, f)
		}
	}

	kept, suppressed, errs := applyBaseline(filtered, opts)
	for _, e := range errs {
		if !containsString(res.Errors, e) {
			res.Errors = append(res.Errors, e)
		}
	}
	res.Findings = append(res.Findings, kept...)
	res.Suppressed = append(res.Suppressed, suppressed...)
	model.SortFindings(res.Suppressed)
}

func filterBySeverity(in []model.Finding, min model.Severity) []model.Finding {
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		if f.Severity.AtLeast(min) {
			out = append(out, f)
		}
	}
	return out
}

func applyBaseline(findings []model.Finding, opts Options) (kept, suppressed []model.Finding, errs []string) {
	if opts.NoBaseline {
		return findings, nil, nil
	}

	path := strings.TrimSpace(opts.BaselinePath)
	if path == "" {
		if strings.TrimSpace(opts.Root) == "" {
			return findings, nil, nil
		}
		path = DefaultBaselineFile
	}
	if filepath.IsAbs(path) {
		return findings, nil, []string{fmt.Sprintf("baseline %s: path must be relative to the scan root", path)}
	}
	if strings.TrimSpace(opts.Root) != "" {
		resolved, err := safepath.Resolve(opts.Root, path)
		if err != nil {
			return findings, nil, []string{fmt.Sprintf("baseline %s: %v", path, err)}
		}
		path = resolved
	}

	baseline, err := LoadBaseline(path)
	if err != nil {
		// A corrupt baseline must not hide real findings: fail open and report.
		return findings, nil, []string{fmt.Sprintf("baseline %s: %v", path, err)}
	}
	if baseline.empty() {
		return findings, nil, nil
	}

	kept = make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		matched, reason := baseline.Match(f)
		if !matched {
			kept = append(kept, f)
			continue
		}
		f.Suppressed = true
		f.SuppressWhy = reason
		suppressed = append(suppressed, f)
	}
	return kept, suppressed, nil
}

func modeOrDefault(mode string) string {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return "standard"
	}
	return mode
}

func newScanID() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "scan_" + time.Now().UTC().Format("20060102T150405") + "_" +
			fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	}
	return "scan_" + time.Now().UTC().Format("20060102T150405") + "_" + hex.EncodeToString(b[:])
}

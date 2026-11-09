// Package app wires configuration, the rule registry, the scanner, the LLM
// analyzer and the scan store into one object used by the CLI and the MCP
// server. It is the only place that knows the full pipeline.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/analysis"
	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/gitutil"
	"github.com/levapveeskela/lv24-vigil/internal/llm"
	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/osv"
	"github.com/levapveeskela/lv24-vigil/internal/rules"
	"github.com/levapveeskela/lv24-vigil/internal/scanner"
	"github.com/levapveeskela/lv24-vigil/internal/store"
	"github.com/levapveeskela/lv24-vigil/internal/version"
)

// App is a ready-to-use Vigil runtime.
type App struct {
	Root     string
	Config   config.Config
	Registry *rules.Registry
	Scanner  *scanner.Scanner
	Analyzer *analysis.Analyzer
	Store    *store.Store
	Logger   *slog.Logger

	// LLM reports whether a model client was configured successfully.
	LLM bool
	// Model describes the configured model, when LLM is true.
	Model *model.ModelInfo
	// Warnings from startup (for example an LLM that could not initialise).
	Warnings []string
}

// New resolves root, loads configuration and builds every component. An LLM
// that is configured but unreachable is a warning, not an error: deterministic
// scanning must keep working.
func New(root string, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	abs, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(abs)
	if err != nil {
		return nil, err
	}
	reg := rules.Default()
	sc := scanner.New(reg, logger)
	st, err := store.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("open scan store: %w", err)
	}

	a := &App{
		Root:     abs,
		Config:   cfg,
		Registry: reg,
		Scanner:  sc,
		Store:    st,
		Logger:   logger,
	}
	a.Analyzer = analysis.New(cfg, nil, logger)

	if cfg.LLMEnabled() {
		client, err := llm.New(cfg, logger)
		if err != nil {
			a.Warnings = append(a.Warnings, "LLM disabled: "+err.Error())
			logger.Warn("LLM disabled", "error", err)
		} else {
			a.Analyzer = analysis.New(cfg, client, logger)
			a.LLM = true
			// The base URL is stored for display and reports, so redact any
			// userinfo or key-shaped query parameter before it is persisted.
			a.Model = &model.ModelInfo{
				Provider: cfg.Provider,
				Model:    cfg.Model,
				BaseURL:  config.RedactURL(cfg.BaseURL),
			}
		}
	}
	return a, nil
}

func resolveRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("root %s: %w", abs, err)
	}
	if !info.IsDir() {
		abs = filepath.Dir(abs)
	}
	return abs, nil
}

// Options returns the scanner options derived from config plus a request.
func (a *App) Options(req model.ScanRequest) scanner.Options {
	mode := req.Mode
	if mode == "" {
		mode = a.Config.Scan.Mode
	}
	minSev := req.MinSeverity
	if minSev == "" {
		minSev, _ = model.ParseSeverity(a.Config.Scan.MinSeverity)
	}
	maxFindings := req.MaxFindings
	if maxFindings == 0 {
		maxFindings = a.Config.Scan.MaxFindings
	}
	concurrency := req.Concurrency
	if concurrency == 0 {
		concurrency = a.Config.Scan.Concurrency
	}
	root := req.Root
	if root == "" {
		root = a.Root
	}
	baseline := req.BaselinePath
	if baseline == "" {
		baseline = a.Config.Scan.Baseline
	}
	return scanner.Options{
		Root:         root,
		Mode:         mode,
		ChangedOnly:  req.ChangedOnly,
		BaseRef:      req.BaseRef,
		Diff:         req.Diff,
		Include:      append(append([]string(nil), a.Config.Scan.Include...), req.Include...),
		Exclude:      append(append([]string(nil), a.Config.Scan.Exclude...), req.Exclude...),
		OnlyRules:    req.OnlyRules,
		DisableRules: append(append([]string(nil), a.Config.Scan.DisableRules...), req.DisableRules...),
		MinSeverity:  minSev,
		MaxFindings:  maxFindings,
		Concurrency:  concurrency,
		MaxFileBytes: a.Config.Scan.MaxFileBytes,
		FollowLinks:  a.Config.Scan.FollowLinks,
		BaselinePath: baseline,
		NoBaseline:   req.NoBaseline,
		OSV:          a.Config.Scan.OSV,
	}
}

// Scan runs the full pipeline: deterministic rules, then optional LLM triage,
// deep review and threat model. LLM failures are recorded as warnings and never
// hide deterministic findings.
func (a *App) Scan(ctx context.Context, req model.ScanRequest) (*model.ScanResult, error) {
	useLLM := a.LLM
	if req.UseLLM != nil {
		useLLM = *req.UseLLM && a.LLM
	}
	opts := a.Options(req)
	res, err := a.Scanner.Scan(ctx, opts)
	if err != nil {
		return nil, err
	}
	res.Version = version.Version
	res.Model = a.Model

	if opts.OSV {
		osvOpts := osv.DefaultOptions()
		if a.Config.Scan.OSVBaseURL != "" {
			osvOpts.BaseURL = a.Config.Scan.OSVBaseURL
		}
		osvFindings, oerr := osv.Scan(ctx, opts.Root, osvOpts)
		if oerr != nil {
			res.Errors = append(res.Errors, "osv: "+oerr.Error())
		}
		res.Findings = append(res.Findings, osvFindings...)
	}

	if useLLM {
		if len(res.Findings) > 0 {
			triaged, tstats, terr := a.Analyzer.TriageWithStats(ctx, res.Findings, opts.Root)
			if terr != nil {
				res.Errors = append(res.Errors, "llm triage: "+terr.Error())
			}
			res.Stats.LLMCalls += tstats.Batches + tstats.Retries
			if tstats.Missing > 0 {
				a.Logger.Warn("triage left findings without a judgement",
					"missing", tstats.Missing, "judged", tstats.Judged, "batches", tstats.Batches)
			}
			res.Findings = triaged
		}

		deep := req.DeepReview || a.Config.Scan.DeepReview || opts.Mode == "deep"
		if deep {
			files, ferr := a.Scanner.CollectFiles(ctx, opts)
			if ferr != nil {
				res.Errors = append(res.Errors, "collect files for deep review: "+ferr.Error())
			} else {
				newFindings, derr := a.Analyzer.DeepReview(ctx, opts.Root, files, res.Findings)
				if derr != nil {
					res.Errors = append(res.Errors, "llm deep review: "+derr.Error())
				}
				res.Findings = append(res.Findings, newFindings...)
			}
		}

		if req.ThreatModel {
			tm, terr := a.Analyzer.ThreatModel(ctx, opts.Root)
			if terr != nil {
				res.Errors = append(res.Errors, "llm threat model: "+terr.Error())
			} else {
				res.ThreatModel = tm
			}
		}
	}

	// The LLM pass can add findings, so re-apply the severity filter, sort and
	// cap once more before the result is stored.
	res.Findings = model.Filter(res.Findings, opts.MinSeverity, opts.MaxFindings)
	model.SortFindings(res.Findings)
	res.FinishedAt = time.Now().UTC()
	res.Stats.DurationMS = res.FinishedAt.Sub(res.StartedAt).Milliseconds()
	fillStats(&res.Stats, res.Findings)

	if err := a.Store.Save(res); err != nil {
		a.Logger.Warn("save scan", "error", err)
	}
	return res, nil
}

func fillStats(stats *model.Stats, findings []model.Finding) {
	stats.BySeverity = map[model.Severity]int{}
	stats.ByCategory = map[model.Category]int{}
	for _, f := range findings {
		stats.BySeverity[f.Severity]++
		stats.ByCategory[f.Category]++
	}
}

// Review scans only the added lines of a diff.
func (a *App) Review(ctx context.Context, req model.ScanRequest) (*model.ScanResult, error) {
	if strings.TrimSpace(req.Diff) == "" && !req.ChangedOnly {
		req.ChangedOnly = true
	}
	req.Mode = "quick"
	return a.Scan(ctx, req)
}

// Explain returns a model-written explanation of one finding.
func (a *App) Explain(ctx context.Context, f model.Finding) (string, error) {
	if !a.LLM {
		return "", errors.New("no model configured; set VIGIL_PROVIDER/VIGIL_MODEL/VIGIL_API_KEY or use a local Ollama")
	}
	return a.Analyzer.Explain(ctx, f, a.Root)
}

// ProposeFix returns a validated unified diff for one finding.
func (a *App) ProposeFix(ctx context.Context, f model.Finding) (*model.Fix, error) {
	if !a.LLM {
		return nil, errors.New("no model configured; set VIGIL_PROVIDER/VIGIL_MODEL/VIGIL_API_KEY or use a local Ollama")
	}
	return a.Analyzer.ProposeFix(ctx, f, a.Root)
}

// ApplyFix applies a validated diff to the working tree. It never commits.
// The diff is validated again here so a caller cannot bypass the path, binary
// and hunk checks that ProposeFix performs.
func (a *App) ApplyFix(ctx context.Context, fix *model.Fix) error {
	if fix == nil || strings.TrimSpace(fix.Diff) == "" {
		return errors.New("empty fix")
	}
	if err := analysis.ValidateDiff(a.Root, fix.Diff); err != nil {
		return fmt.Errorf("refusing to apply an unsafe diff: %w", err)
	}
	if err := gitutil.Apply(ctx, a.Root, fix.Diff); err != nil {
		return err
	}
	fix.Applied = true
	return nil
}

// ThreatModel generates a threat model for the configured root.
func (a *App) ThreatModel(ctx context.Context) (string, error) {
	if !a.LLM {
		return "", errors.New("no model configured; set VIGIL_PROVIDER/VIGIL_MODEL/VIGIL_API_KEY or use a local Ollama")
	}
	return a.Analyzer.ThreatModel(ctx, a.Root)
}

// LastScan returns the most recent stored scan.
func (a *App) LastScan() (*model.ScanResult, error) { return a.Store.Last() }

// GetScan returns a stored scan by id.
func (a *App) GetScan(id string) (*model.ScanResult, error) { return a.Store.Get(id) }

// Close releases resources. The store is file-backed and needs no close today.
func (a *App) Close() error { return nil }

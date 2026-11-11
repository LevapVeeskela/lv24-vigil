# Vigil internal contracts

This file is the hand-off contract between work packages. Packages may be
implemented in parallel; **do not change a signature here without updating the
callers in the same change**.

## Layout

```
cmd/vigil/            CLI entry point and one file per command
internal/model/       domain types (Finding, ScanResult, Severity, Fix)
internal/config/      config resolution (defaults → user → project → env)
internal/rules/       deterministic rules; File, Rule, Registry
internal/scanner/     walker, ignore, language, diff, baseline, scan orchestration
internal/gitutil/     git repo root, changed files, unified diff
internal/store/       scan history on disk (~/.local/share/vigil/scans or .vigil/)
internal/llm/         provider clients (OpenAI-compatible, Anthropic, Gemini, local CLI)
internal/analysis/    LLM triage, deep review, fix proposal, threat model
internal/report/      markdown, json, sarif, html renderers
internal/tools/       MCP tool/resource/prompt registration
internal/safepath/    repository-relative path validation and symlink-safe resolution
internal/mcp/         MCP transport and JSON-RPC types
internal/version/     build metadata
```

## Scanner

```go
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
    MinSeverity  model.Severity
    MaxFindings  int
    Concurrency  int
    MaxFileBytes int64
    FollowLinks  bool
    BaselinePath string
    NoBaseline   bool
    OSV          bool
}

func New(reg *rules.Registry, logger *slog.Logger) *Scanner
func (s *Scanner) Scan(ctx context.Context, opts Options) (*model.ScanResult, error)
func (s *Scanner) ScanFiles(ctx context.Context, files []*rules.File, opts Options) (*model.ScanResult, error)
func (s *Scanner) ScanPaths(ctx context.Context, root string, paths []string, opts Options) (*model.ScanResult, error)
```

`Scan` must:
- resolve the root, walk it, skip ignored/binary/oversized files;
- run the selected rules with a worker pool;
- fill `Stats`, sort findings, apply the baseline;
- never execute or modify scanned code.

## Store

```go
func Open(root string) (*Store, error)
func (s *Store) Save(res *model.ScanResult) error
func (s *Store) Last() (*model.ScanResult, error)
func (s *Store) Get(id string) (*model.ScanResult, error)
func (s *Store) List(limit int) ([]Summary, error)
type Summary struct { ID string; StartedAt time.Time; Findings int; Critical int; High int }
```

## LLM

```go
func New(cfg config.Config, logger *slog.Logger) (Client, error)
```

`Client` is defined in `internal/llm/types.go`. Providers must:
- honour `ctx` and `cfg.Timeout`;
- retry 429/5xx/network errors twice with jitter;
- never log the key or the prompt body;
- return a typed `*llm.Error`.

The `command` provider is the exception to the HTTP rules: it runs a local argv
with no shell, no API key and no retry loop. It honours `cfg.CommandTimeout`
(falling back to `cfg.Timeout`), caps stdout at `cfg.CommandMaxOutputBytes`, and
returns typed errors for a missing executable, a non-zero exit, a timeout and an
output cap. Its `command`, `command_env`, `command_prompt_mode` and
`command_output` settings may only come from the user config or the environment;
a project file must be rejected. It is never auto-detected.

## Analysis

```go
type Analyzer struct{ /* ... */ }
func New(cfg config.Config, client llm.Client, logger *slog.Logger) *Analyzer
func (a *Analyzer) Triage(ctx context.Context, fs []model.Finding, root string) ([]model.Finding, error)
func (a *Analyzer) DeepReview(ctx context.Context, root string, files []*rules.File, existing []model.Finding) ([]model.Finding, error)
func (a *Analyzer) Explain(ctx context.Context, f model.Finding, root string) (string, error)
func (a *Analyzer) ProposeFix(ctx context.Context, f model.Finding, root string) (*model.Fix, error)
func (a *Analyzer) ThreatModel(ctx context.Context, root string) (string, error)
```

## Report

```go
type Options struct { Color bool; ShowFix bool }
func Render(format string, res *model.ScanResult, opts Options) ([]byte, error)
func Write(w io.Writer, format string, res *model.ScanResult, opts Options) error
```

Formats: `md`, `json`, `sarif`, `html`.

## MCP tools

```go
type Deps struct {
    App     *app.App
    Version string
}
func Register(srv *mcp.Server, d Deps)
```

Tool names use the `vigil_` prefix. Every tool must return a useful text result
even when the model is unavailable (deterministic findings are never blocked by
an LLM outage).

## Non-negotiables

- No network calls except the configured LLM endpoint and, when `scan.osv` is
  enabled, the OSV API (`api.osv.dev`, or a `scan.osv_base_url` mirror set in the
  user config or the environment, never in a project file). OSV sends only
  package coordinates, never source code, and is off by default.
- No telemetry.
- Read-only by default. Scans write only their own history. Only `vigil_fix`
  with `apply=true` writes source files, and it never commits.
  `vigil_baseline`, `vigil_report` with a path, and `vigil init` write only
  their own artifacts.
- Secrets are masked in every output (`rules.MaskSecret`).
- Scanned code is untrusted input: prompt templates must delimit it and instruct
  the model to ignore instructions found inside it.

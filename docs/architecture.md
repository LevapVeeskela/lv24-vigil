# Architecture

Vigil is a Go program with one job: turn a repository into a small, reviewable
set of security findings, locally and repeatably, then let an optional model add
context without becoming a dependency.

## Pipeline

```text
 CLI or MCP request
        |
        v
 +----------------+      +------------------+      +------------------+
 | config.Load    |----->| scanner.Scan     |----->| model.ScanResult |
 | defaults       |      | walk / ignore    |      | findings + stats |
 | user config    |      | size / binary    |      +------------------+
 | project config |      | rules + baseline |
 | environment    |      +------------------+
 +----------------+               |
                                  v
                       +----------------------+
                       | optional analysis    |
                       | triage               |
                       | deep review          |
                       | fix / explain        |
                       | threat model         |
                       +----------------------+
                                  |
                                  v
                       +----------------------+
                       | report + store       |
                       | md / json / sarif    |
                       | html                 |
                       | .vigil/scans         |
                       +----------------------+
```

The deterministic path is complete without the analysis layer. The analysis
layer fails open: an error is appended to `ScanResult.Errors`, the deterministic
findings remain, and the scan still finishes.

## Packages

| Package | Responsibility |
|---|---|
| `internal/model` | Domain types: `Finding`, `ScanResult`, `Severity`, `Confidence`, `Fix`, `Location` |
| `internal/config` | Defaults, user config, project config, environment, validation |
| `internal/rules` | Rule interface, registry, eight rule packs, secret masking helpers |
| `internal/scanner` | Walker, ignore matcher, language detection, diff mode, baseline, orchestration |
| `internal/gitutil` | Repository root, changed files, unified diff, `git apply --check`, apply |
| `internal/store` | Scan history on disk, atomic writes, retention |
| `internal/llm` | Provider clients, shared HTTP transport, retries, typed errors |
| `internal/analysis` | Triage, deep review, explain, fix proposal, threat model, diff validation |
| `internal/report` | Markdown, JSON, SARIF and HTML renderers |
| `internal/mcp` | JSON-RPC types, stdio transport, tool/resource/prompt dispatch |
| `internal/tools` | MCP tool, resource and prompt registration |
| `internal/app` | Wiring of config, registry, scanner, analyzer and store |
| `internal/version` | Build metadata injected with `-ldflags` |

Dependencies point inward. `rules` and `model` know nothing about the CLI, the
MCP server or a provider. `app` is the composition root.

## Deterministic engine

- The walker skips hard-coded directories such as `.git`, `node_modules`,
  `vendor`, `dist`, `build`, `target`, virtual environments, caches and `.vigil`.
- Files larger than `scan.max_file_bytes` (2 MiB by default) are skipped.
- Binary files are detected by content sniffing, not only by extension.
- Symlinks are skipped unless `scan.follow_symlinks` is enabled; followed
  directory links are cycle-checked by resolved path.
- Rules run over a worker pool. The result is sorted by severity, confidence,
  path and line.
- A baseline is applied after the rules. Suppressed findings move to a separate
  list; they are not deleted.
- A finding ID is a content hash of rule ID, clean path, start line and normalised
  evidence. A fingerprint drops the line number so small moves do not create a
  new finding.

The rules are line-oriented with small windows where a call spans lines. This is
a deliberate trade-off: a full data-flow engine would be larger, slower and much
harder to keep free of false positives. The optional deep review covers some
multi-line cases, but it is not a substitute for a real flow analysis.

## Model layer

`internal/llm` exposes one `Client` interface and three implementations:

- OpenAI-compatible chat completions, used by OpenAI, OpenRouter, Groq, DeepSeek,
  Mistral, xAI, `custom`, Ollama and LM Studio;
- Anthropic Messages;
- Gemini `generateContent`.

The shared transport applies the timeout, retries `429`, `5xx` and network errors
twice with jitter, caps the response body at 4 MiB and redacts the key and bearer
tokens from errors. Provider clients never log the prompt body.

`internal/analysis` builds bounded prompts:

- triage: batches of ten findings;
- deep review: at most eight files, ten windows per file, forty windows total,
  forty model findings;
- fix: one file, forty lines of context, at most two attempts with a validation
  error fed back;
- threat model: a 48 KiB repository map, 16 KiB output cap.

Every code excerpt is wrapped in `<untrusted_code>` and stripped of control
characters. Returned paths and line ranges are checked against the real files.
A proposed diff is checked for path safety, binary content, `.git` edits and hunk
line counts before it is returned or applied.

## Report layer

The four renderers are pure: the same result produces the same bytes. Markdown is
the default, JSON is the machine format, SARIF 2.1.0 is for code scanning, and
HTML is a standalone report with no external assets. Secrets are already masked
in the finding, so every renderer inherits the masking.

## Store

The store is a directory of JSON files with a `last.json` pointer. It keeps the
last 50 scans, writes atomically and falls back to the user cache directory when
the scan root is not a project. There is no database and no background process.

## MCP

`internal/mcp` is a small JSON-RPC server over stdio. It supports `initialize`,
`ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`,
`prompts/list` and `prompts/get`. Protocol versions `2025-06-18`, `2025-03-26`
and `2024-11-05` are accepted; an unknown version falls back to the newest.

The MCP layer is a transport. Tool handlers live in `internal/tools` and call the
same `app.App` as the CLI, so the two surfaces cannot drift in behavior.

## Design decisions

**Why Go?** A single static binary with no runtime, no CGO and a small dependency
set is easy to drop into CI, a container or a developer machine. The scanner is
I/O- and regex-heavy, which Go handles well.

**Why YAML only?** Configuration is the only structured file Vigil needs to read.
Keeping one YAML dependency avoids a dependency tree and a supply-chain surface.

**Why deterministic first?** A security tool must produce the same evidence when
the model is down, rate-limited or different from yesterday. The model adds
context; it is not the detector.

**Why fail open?** A broken model should not turn a scan into a false "clean"
result. The scan reports the error and keeps the deterministic findings.

**Why no SaaS?** The product is the local tool. There is no account, no upload
endpoint and no shared dashboard to secure.

## Limits

- No cross-file data-flow analysis.
- No exploit execution or dynamic testing.
- LLM findings are advisory and model-dependent.
- The store is local; there is no team aggregation.
- The MCP server is stdio-only.

See [security-model.md](security-model.md) and [rules.md](rules.md).

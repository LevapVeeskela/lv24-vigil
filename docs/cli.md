# CLI reference

`vigil` is a single binary. Running it with no arguments scans the current
directory.

```bash
vigil
```

## Commands

| Command | What it does |
|---|---|
| `vigil scan [path]` | Scan a repository or directory. Alias: `vigil audit`. |
| `vigil review` | Review changed files against `HEAD`, or a diff you supply. |
| `vigil fix FINDING_ID` | Propose a fix for one finding. Add `--apply` to write it. |
| `vigil mcp` | Run the MCP server over stdio. |
| `vigil init` | Write a starter `.vigil.yaml`. |
| `vigil status` | Show provider, model, rules, store and last scan. Alias: `vigil doctor`. |
| `vigil rules` | List and filter the detection rules. |
| `vigil baseline` | List, add, remove or clear the suppression baseline. |
| `vigil report` | Render a stored scan. |
| `vigil threat-model [path]` | Generate a STRIDE-style threat model. Alias: `vigil threatmodel`. |
| `vigil version` | Print the version. Also `--version` and `-v`. |
| `vigil help` | Print the command summary. Also `--help` and `-h`. |

## Scan and review flags

These flags are shared by `vigil scan` and `vigil review`, except where noted.

| Flag | Values | Meaning |
|---|---|---|
| `--path DIR` | directory | Scan root. Default `.`; a positional path also works. |
| `--mode MODE` | `quick`, `standard`, `deep` | Analysis depth. Default from config (`standard`). |
| `--changed` | - | Scan only files changed against `--base`. `scan` only. |
| `--base REF` | git ref | Ref for `--changed` and `--diff`. Default `HEAD`. |
| `--diff FILE` | path or `-` | Scan added lines from a unified diff. `-` reads stdin. |
| `--no-llm` | - | Deterministic rules only. |
| `--deep` | - | Run the LLM deep review. |
| `--threat-model` | - | Generate a threat model during the scan. |
| `--include GLOB` | glob, repeatable | Only scan matching paths. Comma-separated values also work. |
| `--exclude GLOB` | glob, repeatable | Skip matching paths. Comma-separated values also work. |
| `--rules ID[,ID]` | rule IDs | Run only these rules. |
| `--disable ID[,ID]` | rule IDs | Skip these rules. |
| `--min-severity LEVEL` | `low`, `medium`, `high`, `critical` | Hide findings below this level. Default from config. |
| `--max-findings N` | integer | Cap the number of findings. `0` uses the config default. |
| `--no-baseline` | - | Ignore the suppression baseline. |
| `--format FMT` | `md`, `json`, `sarif`, `html` | Report format. Default from config (`md`). |
| `--output FILE` | path or `-` | Write the report to a file. `-` means stdout. |
| `--fail-on LEVEL` | `low`, `medium`, `high`, `critical` | Exit `2` when a finding at or above this level exists. |
| `--quiet` | - | Skip the human summary. |
| `--color MODE` | `auto`, `always`, `never` | ANSI color in the human summary only. |

`--include` and `--exclude` accept `*`, `?` and `**` globs. A pattern without a
slash matches a base name at any depth.

`--fail-on` changes the exit code, not the report. `--min-severity` changes the
report and therefore also what can trip the gate.

## Scan modes

| Mode | Deterministic rules | LLM triage | LLM deep review |
|---|---|---|---|
| `quick` | yes | yes, if a model is configured | no |
| `standard` | yes | yes, if a model is configured | only with `--deep` |
| `deep` | yes | yes, if a model is configured | yes |

`--no-llm` turns off triage, deep review, fixes and threat models. The
deterministic rules always run.

Deep review is bounded: at most eight high-risk files, ten windows per file and
forty windows per scan. It is not a full-repository LLM read.

## Input selection

By default a scan walks the whole tree. Three alternatives:

```bash
# Only files changed against a ref:
vigil scan --changed --base origin/main

# Only added lines from a saved diff:
git diff --output=change.diff origin/main...HEAD
vigil scan --diff change.diff

# Only added lines from stdin:
git diff | vigil scan --diff -
```

`--diff` takes precedence over `--changed`. `--diff` also works with `review`.

## Review

Review changed lines against `HEAD`:

```bash
vigil review
```

Compare with another branch:

```bash
vigil review --base origin/main
```

Review a saved diff:

```bash
vigil review --diff change.diff
```

`review` always uses `--mode quick` (no deep review) and only looks at added
lines. It does not have a `--changed` flag because reviewing changes is the
whole point. Use `fetch-depth: 0` in GitHub Actions so the base ref exists. See
[ci.md](ci.md).

## Fix

```bash
vigil scan
vigil fix VGL-XXXXXXXXXX
```

Without `--apply`, the command prints a proposed unified diff. With `--apply`, it
validates and writes the patch:

```bash
vigil fix VGL-XXXXXXXXXX --apply
```

| Flag | Meaning |
|---|---|
| `--scan ID` | Scan that contains the finding. Default: the most recent scan. |
| `--apply` | Write the validated diff to the working tree. |
| `--root DIR` | Project root. Default `.`. |

The finding ID can be exact, case-insensitive or a unique prefix. Suppressed
findings are searchable too. The diff must stay inside the repository, must not
touch `.git`, must not be a binary patch and must pass `git apply --check`. Vigil
never commits, stages or pushes.

A fix needs a model. If no provider is configured, `vigil fix` returns an error
that tells you which variables to set.

## Report

Render the last stored scan:

```bash
vigil report
vigil report --format json
vigil report --format sarif --output vigil.sarif
vigil report --format html --output vigil.html
vigil report --scan scan_20260101T120000Z_ab12cd
```

| Flag | Meaning |
|---|---|
| `--format FMT` | `md`, `json`, `sarif` or `html`. Default from config. |
| `--output FILE` | Write to a file. `-` means stdout. |
| `--scan ID` | Scan to render. Default: the most recent scan. |

`vigil report` reads the local store. It does not run a new scan.

## Rules

```bash
vigil rules
vigil rules --category secrets
vigil rules --severity critical
vigil rules --language python
vigil rules --query jwt
vigil rules --json
```

Filters combine with AND. `--language` keeps rules that declare that language.
`--json` emits the rule metadata array.

## Baseline

The default subcommand is `list`.

```bash
vigil baseline
vigil baseline list
vigil baseline add VGL-XXXXXXXXXX --reason "accepted risk in legacy importer"
vigil baseline remove VGL-XXXXXXXXXX
vigil baseline clear --yes
```

`add` resolves the finding in the last scan or recent history and records its
fingerprint too, so the entry survives small line moves. `remove` removes both
the ID and the matching fingerprint. `clear` refuses to run without `--yes`.

The default file is `.vigil-baseline.json` in the scan root. The format:

```json
{
  "version": 1,
  "fingerprints": ["fp_0123456789abcdef"],
  "findings": [
    { "id": "VGL-XXXXXXXXXX", "reason": "accepted risk in legacy importer" }
  ]
}
```

Suppressed findings are removed from the active findings and recorded separately
in the scan result. They no longer fail `--fail-on`. Use `--no-baseline` to see
everything.

## Init

```bash
vigil init
vigil init --force
```

Writes a commented `.vigil.yaml` in the current directory. Without `--force` it
refuses to overwrite an existing file.

## Status

```bash
vigil status
vigil status --json
```

Shows the version, root, provider, model, base URL, whether the API key is set
(value hidden), LLM status, rule count, store directory, baseline path, config
files, last scan and warnings. `--json` emits a stable object for scripts.

## Threat model

```bash
vigil threat-model
vigil threat-model ./services/api
vigil threat-model --output threat-model.md
```

Builds a bounded repository map (directory tree, README, manifests and the first
part of route/auth/controller files) and asks the model for a STRIDE-style
Markdown document. It needs a model. The output is capped at 16 KiB.

## MCP

```bash
vigil mcp
vigil mcp --root ./services/api
```

Runs the MCP server over stdio. `--root` sets the project root exposed to the
tools. stdout is the protocol stream; diagnostics go to stderr.

## Formats

| Format | Use |
|---|---|
| `md` | Human review, pull request comments, terminal output |
| `json` | Automation, custom dashboards, archival |
| `sarif` | GitHub code scanning and other SARIF consumers |
| `html` | A standalone report with no external assets |

The JSON report contains the scan ID, timestamps, root, mode, findings, stats,
model information and any errors. SARIF is 2.1.0.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, and no finding met the `--fail-on` threshold |
| `1` | Runtime error, invalid usage, missing model for a model-only command |
| `2` | A finding at or above the `--fail-on` severity exists |

A scan that finds issues but does not use `--fail-on` still exits `0`. This is
intentional: the report is the output, the exit code is the policy gate.

## Configuration

See [providers.md](providers.md) for provider keys and precedence. The common
project settings:

| Key | Default | Meaning |
|---|---|---|
| `provider` | inferred | Provider name |
| `model` | provider default | Model ID |
| `base_url` | provider default | API base URL |
| `max_tokens` | `4096` | Output token cap |
| `temperature` | `0.1` | Sampling temperature |
| `timeout` | `120s` | Request timeout |
| `scan.mode` | `standard` | `quick`, `standard` or `deep` |
| `scan.min_severity` | `low` | Minimum reported severity |
| `scan.max_findings` | `200` | Cap on reported findings |
| `scan.concurrency` | CPU count, capped | Rule worker count |
| `scan.include` | empty | Allowlist of glob patterns |
| `scan.exclude` | built-in list | Extra exclude globs |
| `scan.disable_rules` | empty | Rule IDs to skip |
| `scan.use_llm` | `true` when a provider exists | Enable model analysis |
| `scan.max_file_bytes` | `2 MiB` | Skip larger files |
| `scan.follow_symlinks` | `false` | Follow symlinks during the walk |
| `scan.baseline` | `.vigil-baseline.json` | Suppression file |
| `output.format` | `md` | Default report format |
| `output.path` | empty | Default report path |
| `output.color` | `auto` | `auto`, `always` or `never` |
| `output.show_fix` | `true` | Include fix diffs in Markdown and HTML |

`api_key` is only accepted in the user config or the environment, never in a
project file. A project file with `api_key` is rejected.

Example: [../examples/.vigil.yaml](../examples/.vigil.yaml).

## History

A scan is saved after it finishes:

- `<root>/.vigil/scans` when the root contains a `.vigil/` directory or is a git
  repository;
- the user cache directory (`~/.cache/vigil/scans` on Linux,
  `~/Library/Caches/vigil/scans` on macOS, `%LocalAppData%\vigil\scans` on
  Windows) for a one-off scan outside a project.

The store keeps the last 50 scans. `vigil status` shows the resolved store path.
`vigil report` reads the latest one. The MCP tool `vigil_history` lists recent
entries.

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
| `vigil precheck` | Upload a SARIF report to the LV24 security control plane as a pre-check. |
| `vigil hook install` | Install a local pre-commit or pre-push gate. |
| `vigil hook status` | Show installed Vigil hooks, marker and target command. |
| `vigil hook uninstall` | Remove Vigil hooks and restore a saved backup. |
| `vigil threat-model [path]` | Generate a STRIDE-style threat model. Alias: `vigil threatmodel`. |
| `vigil version` | Print the version. Also `--version` and `-v`. |
| `vigil help` | Print the command summary. Also `--help` and `-h`. |

## Local git hooks

```bash
vigil hook install [--mode pre-commit|pre-push] [--force] [--fail-on LEVEL] [--no-llm]
vigil hook status
vigil hook uninstall
```

`pre-commit` (default) runs
`vigil scan --changed --base HEAD --no-llm --fail-on high --quiet`; `pre-push`
uses `@{upstream}` and falls back to `HEAD~1` (then `HEAD` on a single-commit
branch). The generated script is `#!/bin/sh`, executable and marked
`# managed by lv24-vigil`. It honours `VIGIL_BIN` (default `vigil`) and fails
with installation instructions when the binary is missing.

A foreign hook is never replaced or removed silently: install refuses without
`--force`, and `--force` saves it as `<hook>.pre-vigil.bak`. Uninstall removes
only marked hooks and restores that backup.

## Scan and review flags

These flags are shared by `vigil scan` and `vigil review`, except where noted.

| Flag | Values | Meaning |
|---|---|---|
| `--path DIR` | directory | Scan root. Default `.`; a positional path also works. |
| `--mode MODE` | `quick`, `standard`, `deep` | Analysis depth. Default from config (`standard`). |
| `--changed` | - | Scan only files changed against `--base`. `scan` only. |
| `--base REF` | git ref | Ref for `--changed` (and for `review` when no `--diff` is given). Default `HEAD`. |
| `--diff FILE` | path or `-` | Scan added lines from a unified diff file. `-` reads stdin. It is not a git ref; use `--base` for that. |
| `--no-llm` | - | Deterministic rules only. |
| `--deep` | - | Run the LLM deep review. |
| `--threat-model` | - | Generate a threat model during the scan. |
| `--include GLOB` | glob, repeatable | Only scan matching paths. Comma-separated values also work. |
| `--exclude GLOB` | glob, repeatable | Skip matching paths. Comma-separated values also work. |
| `--rules ID[,ID]` | rule IDs | Run only these rules. |
| `--disable ID[,ID]` | rule IDs | Skip these rules. |
| `--min-severity LEVEL` | `info`, `low`, `medium`, `high`, `critical` | Hide findings below this level. Default from config. |
| `--max-findings N` | integer | Cap the number of findings. `0` uses the config default. |
| `--no-baseline` | - | Ignore the suppression baseline. |
| `--format FMT` | `md`, `json`, `sarif`, `html` | Report format. Default from config (`md`). |
| `--output FILE` | path or `-` | Write the report to a file. `-` means stdout. |
| `--fail-on LEVEL` | `info`, `low`, `medium`, `high`, `critical` | Exit `2` when a finding at or above this level exists. |
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

All three modes run the same deterministic rule set. The mode controls the
optional LLM passes. `--no-llm` turns off triage, deep review, fixes and threat
models; the deterministic rules always run.

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

`review` uses `--mode quick` and only looks at added lines; passing `--deep`
still enables the optional LLM deep review. It does not have a `--changed` flag
because reviewing changes is the whole point. Use `fetch-depth: 0` in GitHub
Actions so the base ref exists. See [ci.md](ci.md).

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
touch `.git` (in any case), must not be a binary or symlink patch, and must have
matching hunk counts. Before `--apply` writes anything, `git apply --check` must
also pass. Vigil never commits, stages or pushes.

A fix needs a model. If no provider is configured, `vigil fix` returns an error
that tells you which variables to set.

## Report

Render the last stored scan:

```bash
vigil report
vigil report --format json
vigil report --format sarif --output vigil.sarif
vigil report --format html --output vigil.html
vigil report --scan scan_20260101T120000_ab12cd
```

| Flag | Meaning |
|---|---|
| `--format FMT` | `md`, `json`, `sarif` or `html`. Default from config. |
| `--output FILE` | Write to a file. `-` means stdout. |
| `--scan ID` | Scan to render. Default: the most recent scan. |

`vigil report` reads the local store. It does not run a new scan.

## Pre-check

Upload a SARIF report to the LV24 security control plane:

```bash
vigil scan . --format sarif --output vigil.sarif --fail-on high
vigil precheck --sarif vigil.sarif \
  --api https://lv24.by/api \
  --token "$STAFF_JWT" \
  --target "$GITHUB_REPOSITORY" \
  --commit "$GITHUB_SHA"
```

| Flag | Meaning |
|---|---|
| `--sarif FILE` | SARIF 2.1.0 report to upload. Required; max 10 MiB. |
| `--target TARGET` | Target identifier, for example the repository slug. Required. |
| `--api URL` | Control-plane base URL. Default `http://localhost:3791`; through the LV24 edge use `https://lv24.by/api`. A trailing slash is ignored. |
| `--token JWT` | Staff JWT with `ops:security-scans`. Falls back to `VIGIL_SECURITY_API_TOKEN`. |
| `--commit SHA` | Commit the report describes. Optional. |
| `--tool-version V` | Tool version recorded with the pre-check. Default: the Vigil version. |
| `--json` | Print the API response as JSON. |

The token is a **staff JWT**, not an API key: `vigil precheck` calls the staff
endpoint `POST {api}/security-scans/prechecks`. The token is never printed, and
passing it through `VIGIL_SECURITY_API_TOKEN` keeps it out of the command line.

A success prints one line:

```
precheck 0f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b created: 1 error / 2 warning / 3 note
```

A pre-check is **evidence only**. It does not start a scan, does not start the
Strix sandbox and writes nothing to the run/finding tables, so it keeps working
while the execution kill-switch is off.

The report is checked locally before the upload (`version` starts with `2.1.` and
`runs` is a non-empty array) and validated again by the control plane, which also
rejects results without `ruleId`, `message.text` or a file URI. A 4xx/5xx prints
the API error body (capped at 2 KiB) and exits `1`.

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
| `scan.deep_review` | `false` | Run the LLM deep review on every scan |
| `scan.max_file_bytes` | `2 MiB` | Skip larger files; the effective limit is capped at 64 MiB |
| `scan.follow_symlinks` | `false` | Follow symlinks during the walk (user config only) |
| `scan.baseline` | `.vigil-baseline.json` | Suppression file; must stay inside the project root |
| `scan.osv` | `false` | Opt-in OSV dependency advisory lookup (network). Off by default |
| `scan.osv_base_url` | `https://api.osv.dev` | OSV API endpoint override (self-hosted mirror or tests) |
| `output.format` | `md` | Default report format |
| `output.path` | empty | Default report path |
| `output.color` | `auto` | `auto`, `always` or `never` |
| `output.show_fix` | `true` | Include fix diffs in Markdown and HTML |

`api_key` and `base_url` are only accepted in the user config or the environment,
never in a project file. A project file that sets either is rejected, as are
absolute or `..` paths in `scan.baseline` and `output.path`; this keeps a hostile
repository from redirecting model traffic or writing outside the project tree.

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

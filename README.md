# Vigil

**Security audit for your code, on your own model.**

Vigil is a local-first security auditor exposed as an MCP server and a CLI. It runs
100+ deterministic rules over a repository, then optionally uses the model you
already pay for to triage findings, review risky code, propose fixes and write a
threat model. There is no Vigil account, no telemetry and no Docker requirement
for a normal scan.

[![npm](https://img.shields.io/npm/v/lv24-vigil)](https://www.npmjs.com/package/lv24-vigil)
[![release](https://img.shields.io/github/v/release/LevapVeeskela/lv24-vigil)](https://github.com/LevapVeeskela/lv24-vigil/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![go](https://img.shields.io/badge/go-1.27-00ADD8)](https://go.dev/)

> **Status: 0.1.0.** The deterministic engine is usable today. LLM output is
> advisory, rule coverage is still growing, and Vigil is not a replacement for a
> pentest. Treat every finding as a lead to verify, not a verdict.

## Why Vigil

- **Your model, your keys.** OpenAI, Anthropic, Gemini, OpenRouter, Groq,
  DeepSeek, Mistral, xAI, OpenCode Go, Ollama, LM Studio, or any
  OpenAI-compatible endpoint.
  No proxy, no cloud account, no telemetry.
- **Deterministic first.** The rules run before any model call. A provider
  outage cannot hide a hardcoded secret or a shell injection.
- **Fits the agent you already use.** One MCP server for OpenCode, Claude Code,
  Codex and Cursor. The agent can scan, explain, fix and re-check without
  leaving the conversation.
- **Read-only by default.** Scans never modify source files; they write only
  their own history under `.vigil/scans` or the user cache. `vigil fix --apply`
  writes a validated unified diff and never commits; the baseline and report
  commands write only their own files. Secrets are masked in output.
- **Small and portable.** One static Go binary, standard library plus
  `gopkg.in/yaml.v3`, no CGO, no Docker for the default scan.
- **CI-native.** Markdown, JSON, SARIF and HTML. `--fail-on high` exits `2` so a
  pull request can block on a real finding.

## How it works

```text
 repository
     |
     v
 +-----------------+     +--------------------------+     +-------------------+
 | walker + ignore |---->| 100+ deterministic rules |---->| findings          |
 | size + binary   |     | secrets injection crypto |     | severity evidence |
 +-----------------+     | auth web config CI deps  |     +-------------------+
                         +--------------------------+              |
                                                                  v
                        +------------------------------------------------------+
                        | optional, on your model: triage, deep review,        |
                        | fix diff, STRIDE threat model                        |
                        +------------------------------------------------------+
                                                                  |
                                                                  v
                        +------------------------------------------------------+
                        | baseline -> report (md/json/sarif/html) -> history   |
                        |                                  -> MCP resources     |
                        +------------------------------------------------------+
```

The model never replaces deterministic evidence. A failed or missing model is a
warning, not a failed scan. See [docs/architecture.md](docs/architecture.md).

## Install

```bash
npm i -g lv24-vigil
```

The npm package selects a platform package (`@lv24/vigil-<os>-<cpu>`) at install
time and runs no install scripts.

Other options:

```bash
# Go 1.27+
go install github.com/levapveeskela/lv24-vigil/cmd/vigil@latest
```

Standalone binaries and installers are published with GitHub releases. A
distroless Dockerfile is included for container use. Details:
[docs/install.md](docs/install.md).

## 60-second quickstart

```bash
cd your-repo

# Deterministic rules only, no key, no network:
vigil scan --no-llm

# Add LLM triage with a hosted model:
export OPENAI_API_KEY=sk-...
vigil scan

# Or keep everything local:
VIGIL_PROVIDER=ollama VIGIL_MODEL=qwen2.5-coder:14b vigil scan
```

Useful next commands:

```bash
vigil status                         # resolved provider, model and config sources
vigil rules                          # the rule catalog (source of truth)
vigil scan --format sarif --fail-on high
vigil review --base origin/main --format sarif --fail-on high
vigil fix VGL-XXXXXXXXXX             # print a proposed unified diff
vigil fix VGL-XXXXXXXXXX --apply     # write it to the working tree, never commit
vigil threat-model                   # STRIDE-style markdown, needs a model
vigil report --format html > report.html
```

`vigil scan` with no path scans the current directory. A finding ID comes from a
previous scan or report. Full command reference: [docs/cli.md](docs/cli.md).

## Use it from your coding agent (MCP)

Start the server with `vigil mcp` (stdio, JSON-RPC). Register it once:

**OpenCode** - `opencode.json` in the project root (or
`~/.config/opencode/opencode.json`):

```json
{
  "mcp": {
    "vigil": {
      "type": "local",
      "command": ["npx", "-y", "lv24-vigil", "mcp"],
      "enabled": true
    }
  }
}
```

**Claude Code**:

```bash
claude mcp add vigil -- npx -y lv24-vigil mcp
```

**Codex** - `~/.codex/config.toml`:

```toml
[mcp_servers.vigil]
command = "npx"
args = ["-y", "lv24-vigil", "mcp"]
```

**Cursor** - `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "npx",
      "args": ["-y", "lv24-vigil", "mcp"]
    }
  }
}
```

Then ask your agent: *"Scan this repository with Vigil and explain the top three
findings."* Setup details, tools, resources and prompts:
[docs/mcp.md](docs/mcp.md).

## Providers

Set `VIGIL_PROVIDER` and the provider key, or let Vigil infer the provider from a
well-known key. Explicit `VIGIL_*` variables win over provider conventions.

| Provider | `VIGIL_PROVIDER` | Key variable | Default model |
|---|---|---|---|
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-4.1-mini` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | `gemini-2.5-flash` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4.5` |
| Groq | `groq` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| DeepSeek | `deepseek` | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| Mistral | `mistral` | `MISTRAL_API_KEY` | `mistral-large-latest` |
| xAI | `xai` | `XAI_API_KEY` | `grok-4-fast` |
| OpenCode Go | `opencode-go` | `OPENCODE_API_KEY` | `deepseek-v4.1-flash` |
| Ollama | `ollama` | none | `qwen2.5-coder:14b` |
| LM Studio | `lmstudio` | none | `local-model` |
| OpenAI-compatible | `custom` | `VIGIL_API_KEY` | set `VIGIL_MODEL` |

Local models:

```bash
VIGIL_PROVIDER=ollama VIGIL_MODEL=qwen2.5-coder:14b vigil scan
VIGIL_PROVIDER=lmstudio VIGIL_MODEL=local-model vigil scan
```

`OLLAMA_HOST` points at a non-default Ollama. `VIGIL_BASE_URL` overrides the
endpoint for any provider; `custom` requires it. Full reference:
[docs/providers.md](docs/providers.md).

## What it checks

| Category | Prefix | Rules | Looks for |
|---|---|---:|---|
| Secrets | `VGL-SEC` | 24 | cloud keys, tokens, private keys, connection strings, `.env` leaks |
| Injection | `VGL-INJ` | 37 | SQL, shell, code eval, XSS, deserialization, SSTI, prototype pollution |
| Crypto | `VGL-CRY` | 12 | weak hashes/ciphers, ECB, static IVs, bad randomness, TLS verify off, JWT `none` |
| Auth | `VGL-AUTH` | 9 | unverified JWTs, cookie flags, CORS + credentials, CSRF, default passwords |
| Web | `VGL-WEB` | 12 | SSRF, path traversal, open redirect, CORS, debug endpoints, host header |
| Config / IaC | `VGL-CFG` | 17 | Docker, Compose, Kubernetes, Terraform, nginx, committed env files |
| CI | `VGL-CI` | 11 | unpinned actions, `pull_request_target`, script injection, secrets in logs |
| Dependencies | `VGL-DEP` | 7 | missing lockfiles, wildcard versions, git/HTTP installs, TLS bypass |

Representative IDs: `VGL-SEC-002` (critical, AWS secret key), `VGL-SEC-011`
(critical, private key), `VGL-INJ-001` (high, JS code execution), `VGL-INJ-019`
(critical, Java deserialization), `VGL-CRY-011` (critical, JWT `none`),
`VGL-AUTH-002` (critical, JWT verification disabled), `VGL-WEB-001` (high, SSRF),
`VGL-CFG-009` (high, Docker socket), `VGL-CI-002` (critical,
`pull_request_target` checkout), `VGL-DEP-006` (high, npm TLS off).

Model-only findings use `VGL-AI-001` and are marked as LLM-sourced. The CLI
`vigil rules` is the authoritative list. More: [docs/rules.md](docs/rules.md).

## MCP tools

| Tool | What it does | Writes? |
|---|---|---|
| `vigil_scan` | Scan a repository or directory | scan history only |
| `vigil_review` | Review only changed lines or a supplied diff | scan history only |
| `vigil_explain` | Explain one finding in context | no |
| `vigil_fix` | Propose a unified diff; `apply=true` writes it | `apply=true` only |
| `vigil_threat_model` | Generate a STRIDE-style threat model | no |
| `vigil_status` | Provider, model, engine and store status | no |
| `vigil_rules` | List detection rules | no |
| `vigil_baseline` | Inspect or update the suppression baseline | baseline file only |
| `vigil_report` | Render a stored scan as md/json/sarif/html | only when `path` is supplied |
| `vigil_verify` | Re-check whether a finding is still present | no |
| `vigil_history` | List recent scans from the local store | no |

Resources: `vigil://status`, `vigil://rules`, `vigil://scan/last`,
`vigil://scan/<id>`. Prompts: `security_review`, `threat_model`, `fix_finding`.

Every tool returns a useful text result even when no model is configured; the
deterministic findings are never blocked by an LLM outage.

## CI

```bash
vigil review --base origin/main --format sarif --fail-on high > vigil.sarif
```

Upload the result with `github/codeql-action/upload-sarif` and keep the workflow
at `fetch-depth: 0`. The repository ships a composite action in `action.yml`; the
example below uses the CLI directly so it also works on any runner.

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- run: npx -y lv24-vigil review --base origin/${{ github.base_ref }} --format sarif --fail-on high > vigil.sarif
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vigil.sarif }
```

Fork pull requests do not receive repository secrets; without a key Vigil still
runs the deterministic rules. Full guide: [docs/ci.md](docs/ci.md).

## Security model

- **Local-first.** No Vigil cloud, no telemetry, no analytics, no account.
- **Read-only by default.** A scan writes no source files; it writes only its
  scan history under `.vigil/scans` (or the user cache). The other write paths
  are `vigil_fix` with `apply=true` (or `vigil fix --apply`), the baseline
  command, an explicitly requested report file, and `vigil init`. A fix never
  commits and never stages.
- **Your code goes only where you point it.** Deterministic scans make no network
  calls. LLM features send the minimum context needed to the endpoint you
  configured. Use a local model if code must not leave the machine.
- **Secrets are masked.** Detected credentials are redacted in evidence,
  snippets and reports. Raw secret values are never printed by the rule engine.
- **Scanned code is untrusted.** Prompts delimit code as data, strip control
  characters and instruct the model to ignore instructions inside it. Model
  output is validated before it becomes a finding or a diff.
- **Fixes are checked before they land.** Paths must stay inside the repository
  (including through symlinks, junctions and hardlinks), binary and symlink
  patches and `.git` edits are rejected, hunk counts must match, and
  `git apply --check` runs before any write.

Details and limits: [docs/security-model.md](docs/security-model.md).

## How Vigil compares

| | Strix (`usestrix/strix`) | Vigil | Hosted scanner |
|---|---|---|---|
| What it is | autonomous pentesting agent | static + LLM auditor | managed service |
| Runs where | sandbox, Docker required | your machine or CI | vendor cloud |
| Actively exploits targets | yes | no | varies |
| Fits a coding agent via MCP | separate integration | first-class | usually not |
| Code leaves your machine | to your model | only to your model, if enabled | yes |
| Best for | validating exploitable issues | fast, local, repeatable checks | teams without local setup |

Vigil and Strix are complementary: Vigil finds cheap, deterministic issues while
you write code; Strix validates deeper issues in an authorized sandbox. See
[docs/comparison.md](docs/comparison.md) and the LV24 fork analysis in
[docs/lv24-security-analysis.md](docs/lv24-security-analysis.md).

## Roadmap

Not commitments, just direction:

- broader language and framework coverage for the injection and auth packs;
- better data-flow rules without turning Vigil into a full SAST engine;
- smoother baseline and suppression workflows;
- more MCP client recipes and editor integrations;
- translated docs beyond the current English set.

## Documentation

| Document | Contents |
|---|---|
| [docs/install.md](docs/install.md) | npm, Go, installers, binaries, container |
| [docs/providers.md](docs/providers.md) | providers, keys, local models, config precedence |
| [docs/mcp.md](docs/mcp.md) | MCP clients, tools, resources, prompts |
| [docs/cli.md](docs/cli.md) | commands, flags, exit codes, formats |
| [docs/rules.md](docs/rules.md) | rule families, representative IDs, baseline |
| [docs/ci.md](docs/ci.md) | GitHub Actions, SARIF, fork PRs, baselines |
| [docs/security-model.md](docs/security-model.md) | egress, masking, prompt safety, limits |
| [docs/architecture.md](docs/architecture.md) | packages, pipeline, design decisions |
| [docs/troubleshooting.md](docs/troubleshooting.md) | common failures and fixes |
| [docs/comparison.md](docs/comparison.md) | Vigil vs Strix vs hosted scanners |
| [docs/lv24-security-analysis.md](docs/lv24-security-analysis.md) | Strix upstream sync and the LV24 fork |

Russian overview: [README.ru.md](README.ru.md). Changes:
[CHANGELOG.md](CHANGELOG.md). Contributing:
[CONTRIBUTING.md](CONTRIBUTING.md). Security reports:
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

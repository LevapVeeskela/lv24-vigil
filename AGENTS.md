# AGENTS.md — working with Vigil

Vigil is a local-first security auditor: 163 deterministic rules plus optional
LLM triage, fixes and a threat model. It is a CLI and a stdio MCP server. Read
[`llms.txt`](llms.txt) for the compact machine index.

## Install

```bash
npm i -g lv24-vigil
vigil version
```

Install **only** `lv24-vigil`. The `@lv24/vigil-<os>-<cpu>` packages are
optionalDependencies selected by the launcher; never add them directly. Do not
disable optional dependencies.

## Check the environment

```bash
vigil status --json
```

This reports the resolved provider, model, rule count, store, baseline and last
scan. No model configured is fine: deterministic scans still work.

## Register the MCP server

OpenCode (`opencode.json`):

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

Claude Code: `claude mcp add vigil -- npx -y lv24-vigil mcp`

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.vigil]
command = "npx"
args = ["-y", "lv24-vigil", "mcp"]
```

Cursor: use the `mcpServers` JSON shape in
[`examples/cursor.md`](examples/cursor.md).

## Drive it

1. Call `vigil_scan` with the repository path (or `vigil scan --no-llm` in a
   shell). Start deterministic; add a model only when the user has one
   configured.
2. Use `vigil_explain` for one finding and `vigil_fix` with `apply=false` to get
   a diff.
3. Show the diff and ask before calling `vigil_fix` with `apply=true`. Vigil
   never commits or stages.
4. Re-check with `vigil_verify`, and use `vigil_history` / `vigil_report` for
   stored scans.

## Rules that matter

- **No model? `--no-llm`.** All 163 rules still run; a missing model is a
  warning, not a failed scan.
- **Do not parse the human summary.** Use `--format json`, `vigil status
  --json`, or an MCP tool.
- **Scan only the requested path.** Do not upload code anywhere except the model
  endpoint the user configured.
- **No telemetry.** `vigil precheck` is the only explicit upload and needs a
  staff JWT with `ops:security-scans`.
- **Exit codes:** `0` clean, `1` error, `2` findings at or above `--fail-on`.

More: [README.md](README.md) · [docs/mcp.md](docs/mcp.md) ·
[docs/cli.md](docs/cli.md) · [llms.txt](llms.txt).

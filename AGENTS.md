# AGENTS.md — working with Vigil

Vigil is a local-first security auditor: 221 deterministic rules plus optional
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

## Before commit / before deploy

Run the deterministic gate before you commit, hand off or deploy:

```bash
vigil scan . --no-llm --fail-on high
```

Install a local guard once per clone:

```bash
vigil hook install                  # pre-commit
vigil hook install --mode pre-push  # or before push
vigil hook status
vigil hook uninstall
```

The hook is marked `# managed by lv24-vigil`, honours `VIGIL_BIN` (default
`vigil`), and refuses to replace a foreign hook without `--force` (which saves
`<hook>.pre-vigil.bak`). Uninstall removes only Vigil hooks and restores the
backup.

CI templates: [`examples/github-workflow.yml`](examples/github-workflow.yml)
(PR, `main`, manual dispatch), [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml)
(MR, default branch, manual web) and the composite [`action.yml`](action.yml).
All run `vigil scan --no-llm --fail-on high`; the optional pre-check needs a
staff JWT with `ops:security-scans`.

Rules:

- Never auto-apply a fix (`vigil fix --apply` or `vigil_fix apply=true`), never
  commit, stage or push on the user's behalf, and never suppress a finding
  without an explicit baseline decision.
- Exit code `2` is a policy failure, not a crash. Report it; do not retry it
  away.

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
5. Use `vigil_hardening` for anti-RE posture gaps (mobile/desktop release
   settings); [docs/anti-re-hardening.md](docs/anti-re-hardening.md) maps each
   rule to the reverse-engineering capability it raises the cost against. Use
   `vigil_dependencies` for known public dependency advisories.
   The dependency tool makes an explicit OSV network request; the hardening
   tool is deterministic and offline.

## Rules that matter

- **No model? `--no-llm`.** All 221 rules still run; a missing model is a
  warning, not a failed scan.
- **Do not parse the human summary.** Use `--format json`, `vigil status
  --json`, or an MCP tool.
- **Scan only the requested path.** Do not upload code anywhere except the model
  endpoint the user configured.
- **No telemetry.** `vigil precheck` is the only explicit upload and needs a
  staff JWT with `ops:security-scans`.
- **Exit codes:** `0` clean, `1` error, `2` findings at or above `--fail-on`.
- **Dependency advisories are known public OSV records only.** A clean result is
  not proof of safety, and no tool here can detect a zero-day. Never describe
  `vigil_dependencies` as zero-day coverage.
- **Hardening gaps are not vulnerabilities.** `vigil_hardening` reports missing
  release controls (obfuscation, debug signing, inspector flags, source maps);
  do not turn a missing control into an exploitability or bypass claim.

More: [README.md](README.md) · [docs/mcp.md](docs/mcp.md) ·
[docs/cli.md](docs/cli.md) · [llms.txt](llms.txt).

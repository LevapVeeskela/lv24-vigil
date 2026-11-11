# Use Vigil over MCP

Vigil runs as a Model Context Protocol server over stdio. A coding agent can call
it to scan the repository, explain a finding, propose a fix, verify the result
and write a threat model without shelling out to a separate tool.

## Start the server

```bash
vigil mcp
vigil mcp --root ./services/api
```

The process speaks newline-delimited JSON-RPC on stdin/stdout. Without `--root`
it uses its working directory as the project root. Most MCP clients start the
server in the project directory automatically; `--root` is useful when they do
not.

Supported protocol versions: `2025-06-18`, `2025-03-26`, `2024-11-05`.

The server advertises tools, resources and prompts. It does not open an HTTP port
and does not require a daemon.

## Client setup

### OpenCode

`opencode.json` in the project root (or `~/.config/opencode/opencode.json`):

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

If you installed Vigil globally, replace the command with `["vigil", "mcp"]`.

### Claude Code

```bash
claude mcp add vigil -- npx -y lv24-vigil mcp
```

Restart the client after adding the server.

### Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.vigil]
command = "npx"
args = ["-y", "lv24-vigil", "mcp"]
```

### Cursor

`~/.cursor/mcp.json`:

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

### Other clients

Any MCP client that supports local stdio servers can run:

```text
command: vigil
args:    ["mcp"]
```

or the `npx` form above. The transport is stdio; no URL or port is needed.

## Tools

| Tool | Purpose | Side effects |
|---|---|---|
| `vigil_scan` | Scan the repository or a directory. Runs deterministic rules first, then optional LLM analysis. | scan history; network to the configured model, and to OSV when `scan.osv` is on |
| `vigil_review` | Review only changed lines, or a supplied unified diff. | scan history; network to the configured model, and to OSV when `scan.osv` is on |
| `vigil_explain` | Explain one finding: what the code does, why it matters, how an attacker could use it, and a fix direction. | network to the configured model |
| `vigil_fix` | Propose a minimal unified diff. With `apply=true`, write the validated diff to the working tree. | network to the configured model; writes only with `apply=true`; never commits |
| `vigil_threat_model` | Generate a STRIDE-style threat model from a bounded repository map. | network to the configured model |
| `vigil_status` | Report provider, model, engine and store status. | none |
| `vigil_rules` | List the rule catalog with IDs, severities and categories. | none |
| `vigil_hardening` | Run only the `VGL-ARE` anti-RE hardening rules and group gaps by platform. Maps each gap to the REA reverse-engineering surface it raises the cost against in [anti-re-hardening.md](anti-re-hardening.md). | scan history only |
| `vigil_dependencies` | Read supported manifests and query OSV.dev for known public advisories. | network request to OSV |
| `vigil_baseline` | List, add, remove or clear accepted findings in the baseline. | baseline file only |
| `vigil_report` | Render a stored scan as Markdown, JSON, SARIF or HTML. | only when `path` is supplied |
| `vigil_verify` | Re-check whether a finding is still present after a change. | none |
| `vigil_history` | List recent scans from the local store. | none |

Tools that can leave the machine (a configured model or OSV) declare
`openWorldHint: true`: `vigil_scan`, `vigil_review`, `vigil_explain`,
`vigil_fix`, `vigil_threat_model` and `vigil_dependencies`. `vigil_hardening`
and `vigil_verify` are always offline.

The deterministic result is returned even when no model is configured. If the
model fails, the tool returns the findings it has and a warning, not an empty
result.

`vigil_scan` returns at most 50 findings by default and caps `maxFindings` at
500. Raise `maxFindings` when you need the full list; the CLI default is 200.

### `vigil_fix` and `apply=true`

`vigil_fix` accepts a finding ID, a fingerprint (`fp_...`) or a unique prefix,
plus an optional `scanId` (default: the most recent scan). Without `apply`, it
returns a proposed unified diff. The diff is validated before it is shown:

- paths must be relative and inside the repository (symlinks, junctions and
  hardlinked targets that leave the root are rejected);
- `.git` (case-insensitive, including Windows short forms), symlink and binary
  patches are rejected;
- hunk line counts must match the body.

With `apply=true`, the same checks run, `git apply --check` must pass, and only
then is the patch applied to the working tree. Vigil never commits, never stages
and never pushes. Ask your client to require confirmation before a tool call that
writes files.

## Resources

| URI | Contents |
|---|---|
| `vigil://status` | Provider, model, engine and store status |
| `vigil://rules` | The rule catalog |
| `vigil://scan/last` | The most recent stored scan |
| `vigil://scan/<id>` | A stored scan by ID |

Resources are read-only. They are useful when an agent wants context without
starting another scan. Scan resources are registered when the server starts, so
a scan created later is available through `vigil_report` and the other tools
immediately, and as a resource after the server restarts.

## Prompts

| Prompt | Arguments | Purpose |
|---|---|---|
| `security_review` | `path` (optional) | Scan, triage and fix the top findings |
| `threat_model` | `path` (optional) | Turn a threat model into a review plan |
| `fix_finding` | `findingId` (required) | Explain, propose and confirm a fix |
| `anti_re_hardening` | `path` (optional) | Review missing anti-RE protections and debug leaks without calling them vulnerabilities |
| `dependency_audit` | `path` (optional) | Review known public dependency advisories and their fixed versions |

Prompt names are stable. The client may expose them as slash commands or as
templates.

## Example session

```text
You: Scan this repository with Vigil and summarise the critical and high findings.

Agent: [calls vigil_scan]
       Found 3 high and 1 critical finding. The critical one is a hardcoded
       AWS secret in scripts/deploy.sh. Two highs are SQL string concatenation
       in api/users.ts.

You: Explain the AWS one and propose a fix.

Agent: [calls vigil_explain, then vigil_fix]
       The key is committed in the deploy script and used to call S3. Here is a
       minimal diff that reads the value from the environment instead.

You: Apply it and verify.

Agent: [calls vigil_fix with apply=true, then vigil_verify]
       Applied. The finding is no longer present. The working tree is modified;
       nothing was committed.
```

## Security notes

- The server inherits the client's environment. The model key is read from the
  same variables as the CLI (`VIGIL_API_KEY`, `OPENAI_API_KEY`, and so on).
- The server runs with the permissions of the user who started the client. Do not
  run it as root or against a repository you do not trust.
- The write paths are `vigil_fix` with `apply=true` (source files),
  `vigil_baseline` (the baseline file), `vigil_report` with `path` (a report
  inside the project root) and the local scan history written by
  `vigil_scan`/`vigil_review`. A fix never commits or stages. Write paths are
  confined to the server root, including through symlinks and junctions.
- Scanned code is untrusted input. Prompts delimit it as data and model output is
  validated before it becomes a finding or a diff.
- If code must not leave the machine, configure a local Ollama or LM Studio model
  or run the deterministic tools with no model configured.

See [security-model.md](security-model.md) for the full model.

## Troubleshooting

**The client shows no tools.**

- Run `vigil mcp` manually. It should wait for JSON-RPC on stdin; stdout is
  reserved for protocol messages.
- Check that the command and args in the client config are arrays, not a single
  string.
- Restart the client after editing its config.
- If `npx` cannot find the package, install it globally and use
  `["vigil", "mcp"]`.

**Tools work but scans find nothing.**

- Confirm the client started the server in the repository you expect.
- Run `vigil scan --no-llm` in the same directory to compare.
- Check the default excludes and your `.vigil.yaml` `scan.exclude` list.

**A fix is refused.**

- The model may have produced an invalid diff. Ask it to retry, or use
  `vigil fix <id>` and inspect the diff before applying.
- A diff that touches `.git` (in any case), a binary file, an absolute path, a
  path outside the repository, or a path through a symlink/junction that leaves
  the repository is rejected by design.

More: [troubleshooting.md](troubleshooting.md).

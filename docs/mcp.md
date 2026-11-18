# Use Vigil over MCP

Vigil runs as a Model Context Protocol server over stdio. A coding agent can call
it to scan the repository, explain a finding, propose a fix, verify the result
and write a threat model without shelling out to a separate tool.

Listed in the official MCP Registry as `io.github.LevapVeeskela/vigil` (v0.10.1); ownership proof and publishing: [mcp-registry.md](mcp-registry.md).

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

## Modes

Three flags change what the server can do. Each has an environment equivalent.

| Flag | Environment | Effect |
|---|---|---|
| `--read-only` | `VIGIL_MCP_READ_ONLY=1` | Hide `vigil_fix`, hide the `fix_finding` prompt and refuse source, baseline and report writes |
| `--offline` | `VIGIL_MCP_OFFLINE=1` | No model, no OSV; deterministic rules only |
| `--unsafe-unbound-fix` | `VIGIL_MCP_UNSAFE_UNBOUND_FIX=1` | 0.10 compatibility: one-call apply without a reviewed proposal (unsafe) |

**`--read-only`.** `vigil_fix` is removed from `tools/list` (`tools/list` then
lists 13 tools) and the `fix_finding` prompt is not registered. A direct
`tools/call` for `vigil_fix` is refused with `VGL-READONLY`. `vigil_baseline`
still lists entries, but `add`, `remove`, `prune`, `batch` and `clear` are
refused, and `vigil_report` works only without `path`. Scan history is still
written locally, so findings keep stable IDs and later tools can address them.

**`--offline`.** The model client is never built and OSV is forced off, including
a configured `scan.osv_base_url`. Scans run the deterministic rules only,
`vigil_dependencies` is refused with `VGL-OFFLINE`, and `vigil_fix` (which needs
a model) is refused as needing network. `vigil_status.network` reports `none`.

**`--unsafe-unbound-fix`.** Restores the 0.10 behaviour where
`vigil_fix apply=true` proposes and applies in one call without a `fixId` and
`diffSha256`. The tool returns a warning, and the mode is not recommended; use
propose then apply instead.

Hiding is discovery, not enforcement. A hidden tool stays registered and a direct
`tools/call` reaches its handler, so every handler checks the mode and returns a
typed error (see [Typed errors](#typed-errors)). The server instructions and
`vigil_status` report the effective modes.

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

The server exposes 14 tools (13 in read-only mode, which hides `vigil_fix`):

| Tool | Purpose | Side effects |
|---|---|---|
| `vigil_scan` | Scan the repository or a directory. Runs deterministic rules first, then optional LLM analysis. | local scan history (`readOnlyHint: false`); network to the configured model, and to OSV when `scan.osv` is on |
| `vigil_review` | Review only changed lines, or a supplied unified diff. | local scan history (`readOnlyHint: false`); network to the configured model, and to OSV when `scan.osv` is on |
| `vigil_explain` | Explain one finding: what the code does, why it matters, how an attacker could use it, and a fix direction. | network to the configured model |
| `vigil_fix` | Propose a validated unified diff, then apply exactly the proposal a human reviewed. | network to the configured model on propose; stores the proposal under `.vigil/pending`; writes source files only on a bound `mode=apply`; never commits |
| `vigil_threat_model` | Generate a STRIDE-style threat model from a bounded repository map. | network to the configured model |
| `vigil_status` | Report provider, model, rule count, store, effective modes and network posture. | none |
| `vigil_rules` | List the rule catalog with IDs, severities and categories. | none |
| `vigil_hardening` | Run only the `VGL-ARE` anti-RE hardening rules and group gaps by platform. `platform` narrows the review to one surface. Maps each gap to the REA reverse-engineering surface it raises the cost against in [anti-re-hardening.md](anti-re-hardening.md). | local scan history (`readOnlyHint: false`) only |
| `vigil_mcp_audit` | Run only the `VGL-MCP` rules over MCP server configuration files. With `includeUser=true` it also reads known home-directory configs. | none |
| `vigil_dependencies` | Read supported manifests and query OSV.dev for known public advisories. | network request to OSV; refused with `VGL-OFFLINE` in offline mode |
| `vigil_baseline` | List, add, remove, prune, batch or clear accepted findings in the baseline. | baseline file only; `dryRun` previews without writing; refused with `VGL-READONLY` |
| `vigil_report` | Render a stored scan as Markdown, JSON, SARIF or HTML. | a report file only when `path` is supplied; refused with `VGL-READONLY` |
| `vigil_verify` | Re-check whether a finding is still present after a change. | none |
| `vigil_history` | List recent scans from the local store. | none |

Tools that can leave the machine (a configured model or OSV) declare
`openWorldHint: true`: `vigil_scan`, `vigil_review`, `vigil_explain`,
`vigil_fix`, `vigil_threat_model` and `vigil_dependencies`. `vigil_hardening`,
`vigil_mcp_audit` and `vigil_verify` are always offline. The MCP audit reads
configuration text only: no configured server is started and no endpoint is
contacted.

`vigil_scan`, `vigil_review` and `vigil_hardening` declare `readOnlyHint: false`
because they write local scan history. None of the three writes source files.

The deterministic result is returned even when no model is configured. If the
model fails, the tool returns the findings it has and a warning, not an empty
result.

### Finding addressing

`vigil_explain`, `vigil_fix` and `vigil_verify` accept either of:

- `findingId`: an exact `VGL-...` ID or `fp_...` fingerprint, or a unique prefix
  of at least four characters;
- `path` with an optional `line`: a repository-relative path. `line` selects the
  finding whose range contains it, otherwise the nearest finding on that path.
  Omit `line` only when the path has exactly one finding.

`scanId` selects the scan to resolve in (default: the most recent one).
`vigil_baseline add` and `remove` take the same `findingId` forms, not `path`.

A lookup never guesses. An ambiguous prefix, a path with several findings and no
`line`, or a line that matches several findings returns `VGL-AMBIGUOUS` with a
`candidates[]` list. A miss returns `VGL-NOT-FOUND`, also with candidates when
the scan has findings. Each candidate carries `findingId`, `ruleId`, `location`
and `severity`, never a snippet. Passing both `findingId` and `path` is
`VGL-ARGS`.

### Bound output

Results from `vigil_scan`, `vigil_review`, `vigil_hardening`, `vigil_mcp_audit`,
`vigil_rules`, `vigil_history` and `vigil_baseline action=list` carry a `page`
envelope:

```json
{"offset": 0, "limit": 50, "total": 120, "hasMore": true, "nextOffset": 50}
```

`total` is the number of items the tool can page through, and `nextOffset` is
present only when another window exists. The text summary states the same bound
and how to resume. Offsets are zero-based; a negative offset is `VGL-ARGS`.

| Tool | Field | Default | Cap |
|---|---|---|---|
| `vigil_scan`, `vigil_review`, `vigil_hardening`, `vigil_mcp_audit` | `maxFindings` | 50 | 500 |
| `vigil_rules` | `limit` | 50 | 500 |
| `vigil_history` | `limit` | 10 | 100 |
| `vigil_baseline` (`action=list`, findings) | `limit` | 50 | 500 |

Start with `offset=0` and pass `page.nextOffset` from the previous response.
`offset` is accepted by `vigil_scan`, `vigil_review`, `vigil_hardening`,
`vigil_mcp_audit`, `vigil_rules`, `vigil_history` and `vigil_baseline` with
`action=list`.

`maxFindings` is a window size, not a report cap. `vigil_scan`, `vigil_review`,
`vigil_hardening` and `vigil_mcp_audit` page through at most 500 findings; when
the scan reports more, the text names the honest count and says so. For
`vigil_scan`, `vigil_review` and `vigil_hardening`, `stats.findingsTotal` is the
count before that cap. Narrow the path or raise `minSeverity` to keep the pool
inside the cap.

`vigil_scan`, `vigil_review`, `vigil_hardening` and `vigil_mcp_audit` also
return `coverage`:

```json
{"filesScanned": 812, "filesSkipped": 34, "bytesScanned": 7340032, "errors": [], "llmUsed": false}
```

`coverage.errors` repeats the warnings already on the scan result, and
`filesSkipped` states what was not read, so incomplete coverage is visible
instead of looking like a clean result. `vigil_baseline action=list`
returns `findings` (the window), `findingsTotal` (all entries), `page` and
`expired` computed over every entry, not only the visible window.

### Typed errors

Failures carry a stable code in the text and in
`structuredContent.error.code`; `structuredContent.error.message` explains the
failure and `candidates` is present only for a lookup miss or ambiguity.
`isError` stays `true`. Error paths carry no code snippets or evidence text.

| Code | Meaning |
|---|---|
| `VGL-ARGS` | Invalid argument or combination: missing `findingId`/`path`, both at once, a caller path outside the scan root, negative `offset`, conflicting fix modes, a malformed batch |
| `VGL-BAD-PATH` | A diff target is absolute, leaves the root or cannot be parsed |
| `VGL-NO-SCAN` | Reserved for a missing scan history; today a missing scan is a plain error that points at `vigil_history` |
| `VGL-NOT-FOUND` | No finding or baseline entry matches; candidates may be attached |
| `VGL-AMBIGUOUS` | Several findings match; `candidates[]` lists them |
| `VGL-READONLY` | A write, or any `vigil_fix` call, was attempted on a read-only server |
| `VGL-OFFLINE` | A call that needs network was made on an offline server |
| `VGL-FIX-UNBOUND` | `mode=apply` without `fixId`/`diffSha256` while the unsafe escape hatch is off |
| `VGL-FIX-NOT-FOUND` | Unknown, cleaned-up or unreadable proposal ID |
| `VGL-FIX-MISMATCH` | Proposal belongs to another scan or finding, or `diffSha256` does not match |
| `VGL-FIX-EXPIRED` | The 15-minute proposal TTL has passed |
| `VGL-FIX-CONSUMED` | The proposal was already applied, or another apply holds it |
| `VGL-FILE-CHANGED` | A target file, or the server root, changed since the proposal |
| `VGL-FIX-NONDETERMINISTIC` | The finding is model-only and no deterministic rule corroborates it |

`VGL-NO-FINDINGS` is also reserved. Clients may branch on the code; existing
codes are not renamed.

### `vigil_hardening` and platforms

`vigil_hardening` accepts `platform` with `all` (default), `android`, `ios`,
`electron`, `node`, `flutter`, `web` or `other`. The tool narrows `OnlyRules`
before the scan, so `maxFindings` and the statistics describe the selection.
Rules that belong to other platforms are reported as filtered rather than
scanned; the summary names the selected platform and the finding/rule counts per
platform. Grouping uses `model.RuleMeta.Platform` as the source of truth, with
the numeric `VGL-ARE` ID ranges only as a fallback. `vigil_hardening` is
deterministic and offline; it never consults a configured model.

### `vigil_fix`: propose, then apply

`vigil_fix` accepts either `findingId` (ID, fingerprint or unique prefix) or
`path` plus optional `line`, plus an optional `scanId` (default: the most recent
scan). `mode=propose` is the default and modifies no source file.

The proposed unified diff is validated before it is shown:

- paths must be relative and inside the repository (symlinks, junctions and
  hardlinked targets that leave the root are rejected);
- `.git` (case-insensitive, including Windows short forms), symlink and binary
  patches are rejected;
- hunk line counts must match the body.

A successful proposal stores the diff under `.vigil/pending` and returns
`fixId`, `diffSha256`, `expiresAt` and `targets`. The proposal expires after 15
minutes; the stored pre-image hash of every target is what makes a stale diff
detectable.

`mode=apply` requires the `fixId` and `diffSha256` from the proposal. It loads
the stored diff, checks the server root, scan and finding, the diff hash, the
expiry and the consumed state, and re-hashes every target. Only then does it
mark the proposal consumed and apply that exact diff to the working tree.
Apply never calls the model, never regenerates the diff, is single-use, and
does not commit, stage or push. A failed apply still consumes the proposal:
propose again instead of retrying it. `apply=true` is a deprecated alias for
`mode=apply` and stays bound to the reviewed proposal.

A finding that comes from the model only, with no deterministic rule
corroborating it at the same path and overlapping lines, is refused with
`VGL-FIX-NONDETERMINISTIC` in both modes. The approval flow binds a reviewed
diff; it is not a substitute for deterministic evidence.

`--unsafe-unbound-fix` restores the 0.10 path: `apply=true` proposes and applies
in one call without a `fixId` or `diffSha256`. That path always warns and is
off by default.

The CLI is deliberately different: `vigil fix --apply` validates and applies in
one run with no proposal, `fixId`, TTL or pre-image check. It is unchanged. Use
the MCP flow when a human should review the diff before it is written.

### `vigil_baseline`

`action` is `list` (default), `add`, `remove`, `prune`, `batch` or `clear`.
`add` requires `findingId` and `reason`; both `add` and `remove` resolve IDs,
fingerprints and unique prefixes against a scan. A write is refused with
`VGL-READONLY` on a read-only server; `list` still works.

`list` accepts `offset` and `limit` (default 50, cap 500) and returns `findings`
as the visible window, `findingsTotal` for every entry, `page` and `expired`
computed over all entries rather than the window. The text prints a
`Page: ...` line. `fingerprints` are returned in full.

- `ticket` stores a reference. Control characters are stripped and the value is
  capped at 128 characters.
- `expires` is `YYYY-MM-DD` in UTC. A past date is rejected on add; an expired
  entry stops suppressing the next day.
- `disposition` is `false_positive`, `accepted_risk` or `wont_fix`.
  `remediated` is refused: a fixed finding is removed from the baseline.
- `dryRun` previews without writing. It defaults to `true` for `prune` and
  `batch`, and to `false` for `add` and `remove`.
- `scanId` selects the scan used to resolve findings and to preview impact. The
  preview returns `wouldSuppress` counts plus `until`, the latest expiry among
  the affected entries.
- `prune` removes expired entries; `batch` accepts at most 50 add/remove items,
  defaults to `dryRun=true`, validates every argument before writing, reports
  per-item `added`, `already_present`, `removed`, `not_found` or `error`, and
  writes nothing when an argument error rejects the request.
- `clear` writes an empty baseline.

The file stays schema version 2, so a 0.10 build can still read a baseline
written by this server.

### `vigil_status`

`vigil_status` reports `readOnly` and `offline` as booleans and `network` as
`none`, `model`, `osv` or `model+osv`, computed from the runtime that actually
started (a model that failed to initialise does not claim egress). The API key
is reported as `configured` or `not set`, never printed. The same payload names
the store, rule count, last scan and any startup warnings.

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
templates. In read-only mode `fix_finding` is not registered; the other prompts
are unchanged.

## Example session

```text
You: Scan this repository with Vigil and summarise the critical and high findings.

Agent: [calls vigil_scan]
       Found 3 high and 1 critical finding. The critical one is a hardcoded
       AWS secret in scripts/deploy.sh. Two highs are SQL string concatenation
       in api/users.ts.

You: Explain the AWS one and propose a fix.

Agent: [calls vigil_explain, then vigil_fix with mode=propose]
       The key is committed in the deploy script and used to call S3. Here is a
       minimal diff that reads the value from the environment instead. Proposal
       fx_... expires in 15 minutes.

You: Apply it and verify.

Agent: [calls vigil_fix with mode=apply, fixId and diffSha256, then vigil_verify]
       Applied the reviewed diff. The finding is no longer present. The working
       tree is modified; nothing was committed.
```

## Security notes

- The server inherits the client's environment. The model key is read from the
  same variables as the CLI (`VIGIL_API_KEY`, `OPENAI_API_KEY`, and so on).
- The server runs with the permissions of the user who started the client. Do not
  run it as root or against a repository you do not trust.
- The write paths are `vigil_fix` with `mode=apply` (source files, using only the
  stored diff a human reviewed), `vigil_baseline` (the baseline file),
  `vigil_report` with `path` (a report inside the project root) and the local
  scan history written by `vigil_scan`/`vigil_review`/`vigil_hardening`.
  Proposals are stored under `.vigil/pending`; they are single-use and expire
  after 15 minutes. A fix never commits or stages. Write paths are confined to
  the server root, including through symlinks and junctions.
- Read-only mode is enforcement, not just catalog filtering: `vigil_fix` is
  hidden from `tools/list` and refused on a direct call, and baseline, source and
  report writes are rejected.
- Offline mode is a construction-time guarantee: the model client is never built
  and OSV is disabled before the scan starts, so a configured endpoint cannot be
  contacted.
- Scanned code is untrusted input. Prompts delimit it as data and model output is
  validated before it becomes a finding or a diff.
- If code must not leave the machine, run `vigil mcp --offline` (or set
  `VIGIL_MCP_OFFLINE=1`), or configure a local Ollama or LM Studio model.
- There is no telemetry, analytics, account or update check.

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
- `mode=apply` needs the `fixId` and `diffSha256` from `mode=propose`. After
  `VGL-FIX-EXPIRED`, `VGL-FIX-CONSUMED` or `VGL-FILE-CHANGED`, propose again
  rather than replaying the old approval.
- A diff that touches `.git` (in any case), a binary file, an absolute path, a
  path outside the repository, or a path through a symlink/junction that leaves
  the repository is rejected by design.

More: [troubleshooting.md](troubleshooting.md).

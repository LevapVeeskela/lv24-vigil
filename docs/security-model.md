# Security model

Vigil is a security tool that reads source code, so its own behavior matters.
This page describes what it does with your code, what it sends to a model, and
where the boundaries are.

## Principles

1. **Local-first.** There is no Vigil cloud, account, telemetry, analytics or
   crash reporter.
2. **Deterministic before probabilistic.** Rules run first and produce findings
   without a model. A model outage cannot hide them.
3. **Read-only by default.** A scan never modifies source files; it writes only
   its own history under `.vigil/scans` or the user cache.
4. **Least context.** LLM features send only the context needed for the task, to
   the endpoint you configure.
5. **Treat code as untrusted.** Every prompt delimits repository content as data
   and validates what comes back.
6. **Mask what is detected.** Credentials found by rules are redacted in output.

## Network egress

A deterministic scan (`--no-llm`, or no provider configured) makes no network
calls. Git operations are local. The scan store is local.

`vigil mcp --offline` (`VIGIL_MCP_OFFLINE=1`) turns both outbound channels off
at construction time: the model client is never built and `scan.osv` is
forced off, including a configured `scan.osv_base_url`. Only deterministic rules
run. `vigil_dependencies` is refused with `VGL-OFFLINE`, and `vigil_status`
reports `network: "none"`. `vigil_fix` needs a model, so it is refused too.
Because the settings are cleared before the scan engine is constructed, an
offline server cannot fall back to a configured endpoint.

When `scan.osv: true`, the scan also queries `api.osv.dev` (or the
`scan.osv_base_url` mirror) with dependency coordinates parsed from manifests.
The mirror can be set only in the user config or `VIGIL_OSV_BASE_URL`: a
committed project file is rejected, like `base_url`, so a scanned repository
cannot send its inventory to, or take advisory records from, its own host. The
MCP `osvBaseUrl` argument accepts `https`, or plain `http` only on a loopback
host, and refuses credentials in the URL.
It sends package names, versions and ecosystems, never source code. OSV is off
by default.

When LLM features are enabled, the only outbound requests go to the configured
provider endpoint:

- OpenAI, Anthropic, Gemini, OpenRouter, Groq, DeepSeek, Mistral, xAI: the
  provider's API.
- OpenCode Go: `https://opencode.ai/inference/go/openai/v1` (with the
  `x-opencode-session` routing header).
- Ollama or LM Studio: the local server you configure.
- `custom`: the `VIGIL_BASE_URL` you configure.

There is no phone-home, update check, usage counter or background request.

## What is sent to the model

| Feature | Context sent |
|---|---|
| Triage | Finding metadata, location, description and the rule evidence/snippet |
| Deep review | Bounded windows of up to eight selected high-risk files |
| Explain | One finding plus the surrounding file context |
| Fix | One file, the finding location and a bounded context window |
| Threat model | A bounded repository map: tree, README, manifests and the first part of route/auth/controller files |

Deep review and fix send code, not just metadata. A secret that no rule detected
could appear in a file window. If that matters for your repository, use a local
model or `--no-llm`.

The threat model does not send the whole repository. The map is capped at 200
files and 48 KiB, with a 12 KiB tree section and a 5000-entry walk limit.

## Secret masking

Secret rules pass every detected value through `rules.MaskSecret` before it
reaches evidence, a snippet or a report. A finding never contains the raw
credential. Generic assignment rules also avoid obvious placeholders and
low-entropy values.

Tool output applies the same hard redactor (`rules.RedactSecrets`) to the text
content and to every string in `structuredContent`. Well-known credential shapes
(AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, JWT and similar)
are masked in both forms, so reading the JSON payload does not recover a value
the text hides. When a model API key is configured, that exact key is removed
from both the text and the structured payload. Object keys and the JSON shape
are never changed; only values are rewritten.

Masking has limits:

- it covers values a rule detected and well-known credential shapes, not every
  secret-looking string; a token in an unknown format can still appear in tool
  output, and Vigil does not scan its own output for secrets;
- a model can still see an undetected secret inside a code window;
- a secret in git history remains in history after you remove the working copy.

Treat reports and `structuredContent` as potentially sensitive. Rotate anything
that was committed: removing the file or the line is not enough.

## Prompt injection and model output

Scanned code is untrusted input. Vigil:

- wraps code in `<untrusted_code path="..."> ... </untrusted_code>` delimiters;
- neutralises tag-looking text inside the excerpt so it cannot close the
  delimiter, and a hostile repository cannot inject a second wrapper;
- strips control characters;
- uses a system prompt that tells the model the content is data, never
  instructions;
- tells the model not to reveal, repeat or invent credentials;
- validates returned paths and line ranges against the real files;
- drops findings that point outside the reviewed file or repository;
- validates a proposed diff before it can be applied;
- rejects hardlinked files, because a hardlink inside the tree can reference an
  inode outside it.

The model does not get a shell, a browser, a network tool or the ability to run
the scanned code. It returns text and structured JSON; Vigil decides what to do
with it.

Model output is still probabilistic. A finding can be wrong. Triage and deep
review are advisory, and the deterministic evidence stays attached.

## Read-only scans and fix safety

A scan never modifies source files. It walks files, reads them, runs rules and
writes only to the local scan store.

Scans write no source files; they write only their own history. The
source-writing paths are `vigil fix --apply` (CLI, unbound) and `vigil_fix` with
`mode=apply` (MCP, bound to a reviewed proposal).
Other commands write only their own artifacts:
`vigil init` (`.vigil.yaml`), `vigil baseline` / `vigil_baseline` (the baseline
file), `vigil report --output` / `vigil_report` with `path` (a report file), and
`vigil hook install` (`.git/hooks/<mode>`, plus a `.pre-vigil.bak` backup when a
foreign hook is replaced with `--force`).

`vigil mcp --read-only` (`VIGIL_MCP_READ_ONLY=1`) hides `vigil_fix` from
`tools/list`, does not register the `fix_finding` prompt, and refuses a direct
`vigil_fix` call, baseline mutations and `vigil_report` with a path with
`VGL-READONLY`. Scan history is still written, because later tools address
findings by scan ID. Read-only mode never changes path confinement.

A fix applied through MCP is bound to a proposal a human reviewed:

- `mode=propose` returns `fixId`, `diffSha256` and `expiresAt` (15 minutes) and
  stores an authenticated diff under `.vigil/pending` (or the user cache when
  that path is unsafe); it does not modify source files;
- `mode=apply` requires that `fixId` and `diffSha256`, uses the stored diff,
  checks the root, scan, finding, hash, expiry and consumed state, and re-hashes
  every target file;
- the proposal is marked consumed before the diff is written, so it is
  single-use and a failed apply cannot be replayed;
- apply never calls the model, never regenerates the diff, and never commits,
  stages or pushes.

Model-only findings are refused with `VGL-FIX-NONDETERMINISTIC` unless a
deterministic rule corroborates the same path and overlapping lines. The
approval flow binds what was reviewed; it does not replace deterministic
evidence. The CLI `vigil fix --apply` path is unchanged and unbound: it validates
and applies in one run without a `fixId`, TTL or pre-image check.

Before writing a fix, Vigil checks:

- the diff is non-empty and has a file header and at least one hunk;
- every path is relative, clean and inside the repository;
- no path is `.git` (case-insensitive, including Windows short forms such as
  `.GIT` and `.git.`);
- the patch is not a binary or symlink patch;
- no target is a hardlinked file that could reference an inode outside the
  repository;
- each hunk's declared old/new line counts match its body;
- `git apply --check` succeeds.

Only then does it run `git apply` against the working tree. It never commits,
stages, pushes or changes the index beyond what `git apply` needs. A failed check
leaves the tree untouched.

## MCP trust model

The MCP server runs as a local subprocess of the client. It inherits:

- the client's working directory or the `--root` passed to `vigil mcp`;
- the client's environment, including the model key;
- the client's user permissions.

The client decides when to call a tool. `vigil_fix` with `mode=apply` writes
source files; `vigil_baseline` and `vigil_report` with `path` write their own
files. Configure the client to require confirmation for those calls if the agent
is not fully trusted. Do not run the server as root or against a repository you
do not trust.

Hidden tools are a discovery signal, not a boundary by themselves. In read-only
mode `vigil_fix` is removed from `tools/list` and the `fix_finding` prompt is not
registered, but the tool stays registered so a direct `tools/call` reaches its
handler, which refuses it with `VGL-READONLY`. The same enforcement covers
baseline mutations and `vigil_report` with a path. Path confinement is unchanged
in every mode, and scan history is still written in read-only mode so findings
keep stable IDs.

The server does not expose an HTTP port. It speaks JSON-RPC over stdio.

## Keys and configuration

- The API key is read from `VIGIL_API_KEY` or the provider's key variable.
- A user config may contain `api_key` and `base_url`; a project `.vigil.yaml`
  may not. Vigil rejects a project file that sets either.
- `vigil status` redacts the key and any userinfo or key-shaped query parameter
  in the base URL.
- Provider error messages redact the key, bearer tokens and URL userinfo.
  Response bodies are capped at 4 MiB.
- Keys are never written to scan results or reports.

Use a key with the minimum scope your provider allows. For CI, use a dedicated
key and store it as a secret; do not print it in logs.

## Supply chain

- The binary is built from Go with a small dependency set: the standard library
  plus `gopkg.in/yaml.v3`.
- There is no CGO and no runtime plugin loading.
- The npm package uses platform packages and runs no install scripts.
- The Dockerfile builds a distroless image with the binary, not a build
  toolchain.

Verify the release you download from the official release page and keep your
toolchain and provider SDKs current.

## What Vigil does not do

- It does not execute exploits or run the scanned application.
- It does not perform dynamic or black-box testing.
- It does not guarantee that a repository is free of vulnerabilities.
- It does not replace a pentest, a code review or a dependency advisory feed.
- It does not provide a hosted scanning service or a shared dashboard.

## Reporting a problem in Vigil

See [../SECURITY.md](../SECURITY.md). Do not include real credentials or private
source code in a report; use a minimal synthetic reproduction.

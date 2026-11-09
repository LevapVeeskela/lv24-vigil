# Troubleshooting

Start with:

```bash
vigil version
vigil status
vigil scan --no-llm
```

`vigil status` shows the resolved provider, model and the source of each setting.
`--no-llm` separates a rule problem from a provider problem.

## Provider and model errors

### "no LLM provider configured"

Vigil found no provider and no known key. Set one explicitly:

```bash
export VIGIL_PROVIDER=openai
export VIGIL_MODEL=gpt-4.1-mini
export OPENAI_API_KEY=sk-...
```

Or use a local model:

```bash
export VIGIL_PROVIDER=ollama
export VIGIL_MODEL=qwen2.5-coder:14b
```

If several keys are exported, inference picks the first in its fixed order
(Anthropic, OpenAI, Gemini, OpenRouter, DeepSeek, Groq, Mistral, xAI, Ollama).
Set `VIGIL_PROVIDER` to remove the ambiguity.

### "found credentials for ...; set VIGIL_PROVIDER"

A key exists but no provider was selected. This is intentional: Vigil will not
guess between several configured providers. Set `VIGIL_PROVIDER`.

### "provider ... requires an API key"

Set `VIGIL_API_KEY` or the provider-specific variable. Ollama and LM Studio do
not need a key. A `custom` endpoint needs a non-empty key even if the server
ignores it; use a placeholder.

### "provider ... requires a model"

Set `VIGIL_MODEL`. Some providers have a default, but an explicit model is
clearer and avoids surprises when a provider changes its default.

### "provider custom requires base_url"

Set `VIGIL_BASE_URL` to the API root that contains `chat/completions`, usually
ending in `/v1`.

### "api_key must live in the user config or the environment"

A project `.vigil.yaml` contains `api_key`. Remove it. Project config is committed
to git; put the key in the user config or the environment instead.

## Local model problems

**Connection refused on Ollama.**

```bash
ollama serve
ollama pull qwen2.5-coder:14b
curl http://localhost:11434/api/tags
```

If Ollama listens elsewhere, set `OLLAMA_HOST`.

**Connection refused on LM Studio.**

Open LM Studio, load a model, enable the local server, and confirm it listens on
port `1234`. If it uses another port, set `VIGIL_BASE_URL`.

**The local model returns malformed JSON.**

Small models often struggle with structured output. Try a larger coding model, or
use `--no-llm` for the deterministic result. Vigil validates what it can and drops
invalid items, but it cannot make a weak model reliable.

## HTTP errors from a provider

| Status | Likely cause | What to do |
|---|---|---|
| `401` | Bad or missing key | Check the key variable and the provider |
| `403` | Key scope, region, billing or policy | Check the provider console |
| `404` | Wrong base URL or model ID | Check `VIGIL_BASE_URL` and `VIGIL_MODEL` |
| `429` | Quota or rate limit | Wait, lower concurrency, or use another key |
| `5xx` | Provider outage | Retry later; Vigil already retries twice |
| timeout | Slow model or network | Raise `VIGIL_TIMEOUT`, use a smaller model |

A persistent `429` is a provider quota, not a Vigil bug. `vigil scan --no-llm`
still produces the deterministic report.

## "LLM disabled" warning

Vigil prints a warning when a provider is configured but the client cannot be
created. The scan continues with deterministic rules. The warning includes the
reason; common causes are a missing key, an unknown provider or a bad base URL.

If you want a hard failure instead, run a model-only command such as
`vigil threat-model`; it returns an error when no model is available.

## Findings

### No findings

- Confirm the path: `vigil scan --path .`
- Check `scan.exclude` and the built-in excludes. `node_modules`, `vendor`,
  `dist`, `build`, `target`, virtual environments and `.vigil` are skipped.
- Check `scan.min_severity`; the default is `low`.
- Check the baseline; an accepted finding is suppressed.
- The rule may not cover the language or framework. Run `vigil rules`.
- Try `vigil scan --no-llm --format json` and inspect `stats.filesScanned`.

### Too many findings

- Raise `scan.min_severity` to `medium` or `high`.
- Add a baseline for accepted debt; see [rules.md](rules.md).
- Disable a rule that does not fit the project with `scan.disable_rules`.
- Narrow the scan with `scan.include` or `scan.exclude`.
- Start with `--fail-on high` in CI instead of failing on every low finding.

### The same finding changes ID

IDs include the rule, path, start line and normalised evidence. A line move
changes the ID but not the fingerprint. Use the fingerprint in the baseline when
the issue is stable but the location moves. If both change, the evidence or the
path changed enough that it is effectively a new finding.

## Review finds nothing

`vigil review` compares the working tree with `HEAD` by default, or with `--base`
if supplied.

- In CI, use `fetch-depth: 0`; a shallow clone may not contain the base ref.
- Check that the changes are in tracked files or untracked files that are not
  ignored by the built-in excludes.
- `--diff FILE` expects a unified diff, not a patch from another format.
- Review only looks at added lines; a removed line is not a finding location.
- On Windows PowerShell, `git diff > change.diff` can write UTF-16LE, which is
  not a valid diff input. Use `git diff --output=change.diff` or
  `git diff | Out-File -Encoding utf8 change.diff`.

## Fix is refused

Common reasons:

- the model returned a diff that does not modify the finding file;
- a path is absolute or escapes the repository;
- the diff touches `.git` or contains a binary patch;
- the hunk header counts do not match the body;
- `git apply --check` fails because the file changed since the scan.

Re-run the scan, then ask for the fix again. Inspect the diff before `--apply`.
Vigil never commits, so `git diff` is the source of truth after a write.

## MCP problems

**No tools in the client.**

- Run `vigil mcp` manually; stdout is reserved for protocol messages.
- Check that `command` is an array and `args` is an array, not one string.
- Restart the client after editing its config.
- If `npx` cannot resolve the package, install it globally and use
  `["vigil", "mcp"]`.

**The agent scans the wrong directory.**

By default the server uses its working directory as the project root. Start the
client from the repository, set the client's working directory, or pass
`vigil mcp --root DIR`.

**A write happens without confirmation.**

The client controls tool approval. Configure it to require confirmation for
`vigil_fix` with `apply=true`, or do not expose that tool to an untrusted agent.

More: [mcp.md](mcp.md).

## Git and container issues

**"dubious ownership" in a container.**

Git refuses to operate on a repository owned by another UID. Add the mount point
as a safe directory:

```bash
git config --global --add safe.directory /src
```

**`git apply` fails in a container.**

The mounted tree may be read-only, or the container user may not own it. Mount it
read-write and run as a user that can write the files. A scan does not need write
access; only `fix --apply` does.

## Reports and history

**`vigil report` says there is no scan.**

Run `vigil scan` first. The store is written after a successful scan. In a
project it lives under `.vigil/scans`; outside a project it lives in the user
cache directory. See [cli.md](cli.md).

**The HTML report has no styling.**

The HTML renderer is standalone and embeds its styles. If the file is empty, the
scan failed before rendering; check the exit code and stderr.

**A secret appears in output.**

Secret rules mask detected values. If you see a raw credential, report it with a
synthetic reproduction and the rule ID. Do not paste the real secret. See
[../SECURITY.md](../SECURITY.md).

## Exit code 2 in CI

`--fail-on` exits `2` when a finding at or above the threshold exists. That is the
gate working, not a crash. Either fix the finding, accept it in the baseline, or
raise the threshold. Keep the SARIF upload on `if: always()` so the result is
still visible.

See [ci.md](ci.md).

## Still stuck

Open an issue with:

- `vigil version`;
- the operating system and install method;
- the command and flags;
- the error text with secrets removed;
- a minimal fixture repository or diff when possible.

Do not include real credentials or private source code.

# Providers and configuration

Vigil uses a model only for the optional analysis features: triage, deep review,
explanations, fix proposals and threat models. The deterministic rules never call
a model.

## Configuration order

Values are resolved in this order, later wins:

1. Built-in defaults.
2. User config: `~/.config/vigil/config.yaml` on Linux, `~/Library/Application
   Support/vigil/config.yaml` on macOS, `%AppData%\vigil\config.yaml` on Windows.
   Set `VIGIL_CONFIG` to use another path.
3. Project config: `.vigil.yaml`, then `.vigil.yml`, then `vigil.yaml` in the scan
   root. The first name is the convention.
4. Environment variables.

A project config is committed to git, so it may not contain `api_key` or
`base_url`. Vigil rejects the file with an explicit error if it does. The same
applies to the `command` provider's executable and environment (`command`,
`command_env`, `command_prompt_mode`, `command_output`): a cloned repository
must not be able to run arbitrary commands. Keep all of them in the user config
or the environment. A project config must be a regular file
inside the project; a symlink that leaves the project, or a hardlinked
`.vigil.yaml`, is rejected. A project file also cannot enable
`scan.follow_symlinks` or point `scan.baseline` / `output.path` outside the
project; `scan.baseline` is always resolved inside the project root.

## Provider reference

| Provider | `VIGIL_PROVIDER` | Key variable | Default model | Default base URL |
|---|---|---|---|---|
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-4.1-mini` | `https://api.openai.com/v1` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5` | `https://api.anthropic.com` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | `gemini-2.5-flash` | `https://generativelanguage.googleapis.com/v1beta` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4.5` | `https://openrouter.ai/api/v1` |
| Groq | `groq` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` | `https://api.groq.com/openai/v1` |
| DeepSeek | `deepseek` | `DEEPSEEK_API_KEY` | `deepseek-chat` | `https://api.deepseek.com/v1` |
| Mistral | `mistral` | `MISTRAL_API_KEY` | `mistral-large-latest` | `https://api.mistral.ai/v1` |
| xAI | `xai` | `XAI_API_KEY` | `grok-4-fast` | `https://api.x.ai/v1` |
| OpenCode Go | `opencode-go` (alias `opencode`) | `OPENCODE_API_KEY` or `OPENCODE_GO_API_KEY` | `deepseek-v4.1-flash` | `https://opencode.ai/inference/go/openai/v1` |
| Ollama | `ollama` | none | `qwen2.5-coder:14b` | `http://localhost:11434/v1` |
| LM Studio | `lmstudio` | none | `local-model` | `http://localhost:1234/v1` |
| Local CLI | `command` | none | `command` (free-form label) | none |
| OpenAI-compatible | `custom` | `VIGIL_API_KEY` | set `VIGIL_MODEL` | set `VIGIL_BASE_URL` |

Explicit `VIGIL_PROVIDER`, `VIGIL_MODEL`, `VIGIL_API_KEY` and `VIGIL_BASE_URL`
win over provider-specific variables.

## Provider inference

If `VIGIL_PROVIDER` is unset, Vigil infers it from the first key it finds in this
order:

1. `ANTHROPIC_API_KEY`
2. `OPENAI_API_KEY`
3. `GEMINI_API_KEY` or `GOOGLE_API_KEY`
4. `OPENROUTER_API_KEY`
5. `DEEPSEEK_API_KEY`
6. `GROQ_API_KEY`
7. `MISTRAL_API_KEY`
8. `XAI_API_KEY`
9. `OPENCODE_API_KEY` or `OPENCODE_GO_API_KEY`
10. `OLLAMA_HOST`

Anthropic is checked first. If you have several keys exported, set
`VIGIL_PROVIDER` explicitly rather than relying on inference.

The `command` provider is never inferred: it executes a local process, so it
must be selected explicitly with `provider: command` or `VIGIL_PROVIDER=command`.

## Hosted providers

OpenCode Go (OpenAI-compatible, one key for the Go catalog):

```bash
export VIGIL_PROVIDER=opencode-go
export VIGIL_MODEL=deepseek-v4.1-flash
export OPENCODE_API_KEY=...          # or OPENCODE_GO_API_KEY
# default base URL: https://opencode.ai/inference/go/openai/v1
```

Or in `%AppData%\vigil\config.yaml` (Windows) / `~/.config/vigil/config.yaml`:

```yaml
provider: opencode-go
model: deepseek-v4.1-flash
base_url: https://opencode.ai/inference/go/openai/v1
api_key: "..."
```

The `opencode` alias is accepted. Until the key is pasted, the MCP server and
the CLI still start and report `LLM not configured`; deterministic scans keep
working.

OpenAI:

```bash
export VIGIL_PROVIDER=openai
export VIGIL_MODEL=gpt-4.1-mini
export OPENAI_API_KEY=sk-...
vigil scan
```

Anthropic:

```bash
export VIGIL_PROVIDER=anthropic
export VIGIL_MODEL=claude-sonnet-4-5
export ANTHROPIC_API_KEY=sk-ant-...
vigil scan
```

Gemini:

```bash
export VIGIL_PROVIDER=gemini
export VIGIL_MODEL=gemini-2.5-flash
export GEMINI_API_KEY=...
vigil scan
```

OpenRouter:

```bash
export VIGIL_PROVIDER=openrouter
export VIGIL_MODEL=anthropic/claude-sonnet-4.5
export OPENROUTER_API_KEY=sk-or-...
vigil scan
```

Any other listed provider follows the same pattern: set `VIGIL_PROVIDER`, the
provider key variable, and optionally `VIGIL_MODEL`.

## Local models

Ollama:

```bash
export VIGIL_PROVIDER=ollama
export VIGIL_MODEL=qwen2.5-coder:14b
vigil scan
```

If Ollama is not on the default port:

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
```

LM Studio:

```bash
export VIGIL_PROVIDER=lmstudio
export VIGIL_MODEL=local-model
vigil scan
```

LM Studio must have a model loaded and the local server enabled on port `1234`.
Change `VIGIL_BASE_URL` if it listens elsewhere.

Local models are the right choice when code must not leave the machine. They are
usually weaker at structured JSON and deep review than hosted frontier models;
the deterministic findings are unaffected.

## Command provider (local CLI)

`command` runs a local executable that already owns its authentication and reads
the completion from stdout. Vigil stores no key, makes no HTTP request and never
invokes a shell. This is the way to reuse an authenticated `opencode run` model:

```yaml
provider: command
model: opencode-go/deepseek-v4.1-flash
command:
  - opencode
  - run
  - --format
  - json
  - --model
  - opencode-go/deepseek-v4.1-flash
  - --agent
  - plan
  - "{prompt}"
command_output: opencode-json
```

Put this in the **user** config (`%AppData%\vigil\config.yaml` on Windows,
`~/.config/vigil/config.yaml` elsewhere) or set the environment:

```bash
export VIGIL_PROVIDER=command
export VIGIL_MODEL=opencode-go/deepseek-v4.1-flash
export VIGIL_COMMAND='["opencode","run","--format","json","--model","opencode-go/deepseek-v4.1-flash","--agent","plan","{prompt}"]'
export VIGIL_COMMAND_OUTPUT=opencode-json
```

`VIGIL_COMMAND` is a JSON array of argv strings; a single executable path with no
arguments is also accepted and is not split on whitespace. The same settings are
available as `command_prompt_mode`, `command_output`, `command_timeout` and
`command_max_output_bytes` in the user config, plus `command_env` for extra
environment variables.

`model` is a free-form label used in reports; the `--model` flag inside `command`
is what actually selects the model. `max_tokens` and `temperature` are ignored
because the CLI owns its own sampling.

| Setting | Default | Meaning |
|---|---|---|
| `command` | required | argv array; `{prompt}` is replaced by the prompt as one argument |
| `command_prompt_mode` | `arg` | `arg` appends the prompt as one argument when there is no `{prompt}`; `stdin` writes it to stdin |
| `command_output` | `auto` | `auto` detects OpenCode JSONL, `text` takes stdout verbatim, `opencode-json` parses JSONL text parts |
| `command_timeout` | `timeout` | per-invocation timeout, Go duration syntax |
| `command_max_output_bytes` | `4 MiB` | stdout cap, clamped to `16 MiB` |
| `command_env` | none | extra environment variables for the child process |

Security notes:

- **The command runs with your privileges.** Treat it like running it yourself.
  Use `--agent plan` (or another no-tools agent) so triage cannot edit files,
  run tools or fetch URLs. Vigil never passes scanned code to a shell, but the
  CLI you choose decides what it does with the prompt.
- **No key is stored.** OpenCode uses its own `opencode auth login` session. Vigil
  does not read or forward that token.
- **Prefer `command_env` for tokens.** Vigil redacts values of 8 or more
  characters from error messages; `command` argv is not redacted.
- **A project file cannot set this up.** `command`, `command_env`,
  `command_prompt_mode` and `command_output` are rejected in `.vigil.yaml`; only
  the user config and the environment may set them. `command_timeout` and
  `command_max_output_bytes` are non-executable limits and may be set in a
  project file.
- **Windows argv limit.** The prompt is one argv element, and Windows
  `CreateProcess` limits the whole command line to roughly 32k characters. For
  very large prompts use `command_prompt_mode: stdin` (with no `{prompt}`) or a
  small wrapper that reads stdin and calls the real CLI. On Windows a bare
  `opencode` often resolves to `opencode.cmd`, a batch shim that re-parses `%*`
  and can mangle a multi-line prompt (or make the CLI wait). Prefer the real
  `.exe` path, or use stdin mode; Vigil logs a warning when it detects a batch
  shim in argument mode.
- **Output is bounded.** Stdout is capped by `command_max_output_bytes`; stderr
  keeps only a 2 KiB tail for errors. ANSI colour and a leading
  `> agent · model` header are removed in text mode. Prompts and completions are
  never logged; debug logs contain lengths only.

## Any OpenAI-compatible endpoint

Use `custom` for a gateway, a corporate proxy or a self-hosted server:

```bash
export VIGIL_PROVIDER=custom
export VIGIL_BASE_URL=https://llm.example.com/v1
export VIGIL_MODEL=my-model
export VIGIL_API_KEY=...
vigil scan
```

The base URL must point at the API root that contains `chat/completions`, usually
ending in `/v1`. Vigil appends `chat/completions` to it.

`custom` requires `VIGIL_BASE_URL` and a non-empty `VIGIL_API_KEY`; use a
placeholder value if the endpoint ignores the key. Vigil does not guess a base
URL.

## Model settings

| Setting | Default | Meaning |
|---|---|---|
| `VIGIL_MAX_TOKENS` | `4096` | Maximum output tokens per request |
| `VIGIL_TEMPERATURE` | `0.1` | Sampling temperature, `0` to `2` |
| `VIGIL_TIMEOUT` | `120s` | Per-request timeout, Go duration syntax |

Provider clients retry `429`, `5xx` and network errors twice with jitter. A
persistent `429` is a provider quota, not a Vigil bug. See
[troubleshooting.md](troubleshooting.md).

## Turning the model off

```bash
vigil scan --no-llm
```

or:

```bash
export VIGIL_NO_LLM=1
```

or in `.vigil.yaml`:

```yaml
scan:
  use_llm: false
```

`--no-llm` is the strongest switch. The scan still runs every deterministic rule
and produces the same report formats.

## Config file example

See [../examples/.vigil.yaml](../examples/.vigil.yaml). A minimal project file:

```yaml
provider: openai
model: gpt-4.1-mini

scan:
  mode: standard
  min_severity: low
  exclude:
    - "fixtures/**"
    - "testdata/**"

output:
  format: md
  show_fix: true
```

Do not add `api_key` or `base_url` to a project file. Put them in the user
config or the environment.

## Checking the result

```bash
vigil status
```

The output shows the resolved provider, model, base URL, and the source of a
value when known (a config path or `env:NAME`; a bare value is the built-in
default). The API key and any userinfo or key-shaped query parameter in the base
URL are redacted.

If `vigil status` says the LLM is disabled, the scan still works; it simply skips
triage, deep review, fixes and threat models. The reason is printed as a warning.

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

A project config is committed to git, so it may not contain `api_key`. Vigil
rejects the file with an explicit error if it does. Keep the key in the user
config or the environment.

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
| Ollama | `ollama` | none | `qwen2.5-coder:14b` | `http://localhost:11434/v1` |
| LM Studio | `lmstudio` | none | `local-model` | `http://localhost:1234/v1` |
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
9. `OLLAMA_HOST`

Anthropic is checked first. If you have several keys exported, set
`VIGIL_PROVIDER` explicitly rather than relying on inference.

## Hosted providers

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

Do not add `api_key` to a project file. Put it in the user config or the
environment.

## Checking the result

```bash
vigil status
```

The output shows the resolved provider, model, base URL, and the source of a
value when known (a config path or `env:NAME`; a bare value is the built-in
default). The API key is redacted.

If `vigil status` says the LLM is disabled, the scan still works; it simply skips
triage, deep review, fixes and threat models. The reason is printed as a warning.

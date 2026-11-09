# lv24-vigil

**Vigil** is a security auditor for your code that runs on your own model.
Deterministic rules catch known patterns, an LLM you choose triages the results,
and the same binary works as a CLI or as an MCP server for Claude Code, Codex
and OpenCode.

- **Source and docs:** <https://github.com/LevapVeeskela/lv24-vigil>
- **License:** Apache-2.0
- **No telemetry.** Only the configured LLM endpoint is contacted. There is no
  cloud account and no call home.

## Install

```bash
npm i -g lv24-vigil
vigil version
```

npm installs only the binary for your platform (`@lv24/vigil-<os>-<cpu>`:
Windows, macOS and Linux on x64 and arm64). Nothing is downloaded at install
time and no install scripts run. Update with `npm i -g lv24-vigil@latest`.

## Quick start

```bash
cd ~/src/my-app
vigil scan .                       # deterministic rules + LLM triage
vigil scan . --no-llm              # rules only, no model needed
vigil scan . --format sarif --output vigil.sarif
vigil review --base HEAD~1         # review only changed lines
vigil review --diff changes.patch  # review a patch file
vigil rules                        # list detection rules
vigil init                         # write a starter .vigil.yaml
```

Configure the model with environment variables (for example
`VIGIL_PROVIDER`, `VIGIL_MODEL`, `VIGIL_API_KEY`, `VIGIL_BASE_URL`) or with
`.vigil.yaml`. `OLLAMA_HOST` points Vigil at a local model. Secrets are masked
in every output.

## MCP server

Vigil speaks MCP over stdio:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "vigil",
      "args": ["mcp"]
    }
  }
}
```

Add that block to your MCP client configuration (Claude Code/Desktop, Codex,
OpenCode) and ask the agent to scan a repository, explain a finding or propose
a fix. Deterministic findings are never blocked by an LLM outage.

## Links

- Repository: <https://github.com/LevapVeeskela/lv24-vigil>
- Issues: <https://github.com/LevapVeeskela/lv24-vigil/issues>
- Standalone installers (no Node.js required) live in
  [`installers/`](https://github.com/LevapVeeskela/lv24-vigil/tree/main/installers).

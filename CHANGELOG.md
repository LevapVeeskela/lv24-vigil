# Changelog

All notable changes to Vigil are documented here. The format is loosely based on
Keep a Changelog; versions follow semantic versioning once the public API is
stable.

## 0.1.0 - 2026-11-09

Initial public release.

### Added

- Deterministic rule engine with 100+ rules in eight families: secrets,
  injection, crypto, auth, web, config/IaC, CI and dependencies.
- Optional LLM analysis on the user's own provider: finding triage, deep review,
  fix proposal as a unified diff, finding explanation and STRIDE-style threat
  model.
- Providers: OpenAI, Anthropic, Gemini, OpenRouter, Groq, DeepSeek, Mistral,
  xAI, Ollama, LM Studio and any OpenAI-compatible endpoint.
- MCP server over stdio with tools `vigil_scan`, `vigil_review`, `vigil_explain`,
  `vigil_fix`, `vigil_threat_model`, `vigil_status`, `vigil_rules`,
  `vigil_baseline`, `vigil_report`, `vigil_verify` and `vigil_history`.
- MCP resources `vigil://status`, `vigil://rules`, `vigil://scan/last` and
  `vigil://scan/<id>`; prompts `security_review`, `threat_model` and
  `fix_finding`.
- CLI commands `scan`, `review`, `fix`, `mcp`, `init`, `status`, `rules`,
  `baseline`, `report`, `threat-model` and `version`.
- Output formats: Markdown, JSON, SARIF 2.1.0 and HTML.
- `--fail-on` severity gate with exit code `2`.
- Changed-lines review from a git ref or a supplied unified diff.
- Per-project configuration in `.vigil.yaml`, user configuration and environment
  overrides. Project files cannot contain an API key.
- Suppression baseline (`.vigil-baseline.json`) with stable finding IDs and
  fingerprints.
- Local scan history under `.vigil/scans` in a project, or the user cache
  directory elsewhere.
- Read-only scans; validated fixes that write to the working tree and never
  commit.
- Secret masking in findings and reports.
- npm installation with platform packages, `go install`, standalone binaries and
  installers, and a distroless Dockerfile.
- Documentation for installation, providers, MCP clients, CLI, rules, CI,
  security model, architecture, troubleshooting, comparison and the LV24 Strix
  fork.

### Known limitations

- Rules are heuristic and line-oriented; multi-line semantic bugs can be missed.
- LLM findings are advisory and depend on the configured model.
- Vigil does not execute exploits, run dynamic tests or replace a pentest.
- No SaaS, no telemetry and no hosted scanning service.

# Changelog

All notable changes to Vigil are documented here. The format is loosely based on
Keep a Changelog; versions follow semantic versioning once the public API is
stable.

## 0.2.0 - 2026-11-10

### Added

- **34 new deterministic rules** (163 total): Kubernetes/Helm and Terraform
  misconfigurations, nginx TLS, GitLab/Jenkins/CircleCI supply chain, OAuth/
  OIDC/JWT hardening, GraphQL/API surfaces, and dependency manifests.
- **OSV dependency vulnerability scanning** (opt-in): `scan.osv: true` queries
  `api.osv.dev` for npm, PyPI, Go, RubyGems, crates.io, Packagist and Maven
  packages and emits findings with CVSS-derived severity. `scan.osv_base_url`
  points at a mirror. Off by default; no network unless enabled.
- **Triage retry**: findings omitted by the model in a batch are re-requested
  once, and `TriageStats` exposes batches/retries/judged/missing/failed.
- End-to-end MCP tests, fuzz targets for diff parsing, glob matching, git refs
  and every rule, and a race-clean suite (`go test -race` in a Linux container).
- Dogfooding `vigil.yml` workflow (SARIF upload), Dependabot, issue and PR
  templates, `.gitattributes`, and `docs/release.md` (npm Trusted Publishing).

### Changed

- npm packages for `0.2.0` are published through Trusted Publishing (OIDC).
- `scan.osv` is no longer a reserved no-op.

### Fixed

- Diff hunk headers with a zero or overflowing start are rejected instead of
  producing invalid 1-based locations.
- JWT short-secret and credential-in-query rules no longer flag generic
  `secretKey` values, documentation prose or test fixtures.

## 0.1.4 - 2026-11-10

### Changed

- npm releases are published from GitHub Actions with Trusted Publishing
  (OIDC), without a long-lived npm token. `0.1.4` is the first release
  published end-to-end through the OIDC path.
- Added `scripts/npm-publish-and-trust.ps1` and
  `scripts/npm-trust-interactive.ps1` for the one-time bootstrap.

## 0.1.3 - 2026-11-09

### Fixed

- OpenCode Go requests now send a stable `x-opencode-session` header; the
  gateway rejects requests without it (`HTTP 400: Request is missing
  x-opencode-session`). `VIGIL_OPENCODE_SESSION` / `OPENCODE_SESSION_ID`
  override the generated id.

## 0.1.2 - 2026-11-09

### Added

- First-class `opencode-go` provider (alias `opencode`): OpenAI-compatible
  endpoint `https://opencode.ai/inference/go/openai/v1`, default model
  `deepseek-v4.1-flash`, key from `OPENCODE_API_KEY` or
  `OPENCODE_GO_API_KEY`. The MCP server still starts without a key and reports
  `LLM not configured`.

## 0.1.1 - 2026-11-09

Security hardening after an independent review of 0.1.0.

### Security

- Reject git refs that start with `-`, contain whitespace or control characters,
  closing option injection through `--base` / `baseRef`; run git with
  `core.fsmonitor=false` and `core.untrackedCache=false` so a hostile
  repository config cannot execute a hook during a scan.
- Confine every read and write to the project root through the new
  `internal/safepath` package: symlinks, junctions, hardlinks, `.GIT` case
  variants, trailing-dot names and UNC/drive-relative paths are rejected.
- Project configs may no longer set `base_url` (egress hijack), absolute or
  out-of-root `output.path` / `scan.baseline`, or `scan.follow_symlinks: true`.
  Config files must be regular, non-hardlinked files of at most 1 MiB.
- Redact userinfo and key-shaped query parameters from base URLs in `status`,
  scan metadata and provider errors.
- Bound diff padding (2,000,000 lines), MCP handler concurrency (16) and recover
  handler panics; reject oversized MCP lines without killing the server.
- Write reports, baselines and configs atomically through a temp file and
  rename, so a hardlinked target cannot be modified outside the tree.
- `installers/unix/install.sh`: `wget --https-only` for redirects.

### Fixed

- `git apply` now uses the same zero-context flag as `git apply --check`.
- `scan.deep_review` is honored; `scan.osv` is documented as reserved.
- `--changed` applies the normal hard-skip, include and exclude filters.
- `VGL-AUTH-006` no longer flags i18n translation catalogs.
- Documentation corrected for `--diff` (file or `-`), OpenCode config path,
  rule counts, MCP side effects and path restrictions.

### Added

- 61 new unit and adversarial tests: config, model, MCP protocol, app pipeline,
  safepath, tool paths and prompt-injection defenses.

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

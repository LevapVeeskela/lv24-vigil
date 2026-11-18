# Changelog

All notable changes to Vigil are documented here. The format is loosely based on
Keep a Changelog; versions follow semantic versioning once the public API is
stable.

## Unreleased

### Added

- MCP read-only and offline modes. `vigil mcp --read-only`
  (`VIGIL_MCP_READ_ONLY=1`) hides `vigil_fix` and the `fix_finding` prompt and
  rejects direct fix calls, baseline mutations and `vigil_report` with a path,
  while scan history is still written. `--offline` (`VIGIL_MCP_OFFLINE=1`)
  builds no model client and forces OSV off, so only deterministic rules run and
  `vigil_dependencies` returns `VGL-OFFLINE`. `vigil_status` reports `readOnly`,
  `offline` and `network` (`none`, `model`, `osv` or `model+osv`).
- Diff-bound `vigil_fix`: `mode=propose` returns `fixId`, `diffSha256` and a
  15-minute `expiresAt`; `mode=apply` applies only that stored diff, single-use,
  after checking the root, scan, finding, hash, expiry, consumed state and the
  pre-image hashes of every target. Model-only findings are refused with
  `VGL-FIX-NONDETERMINISTIC` unless a deterministic rule corroborates them.
- Finding addressing by `path` plus optional `line` in `vigil_explain`,
  `vigil_fix` and `vigil_verify`, alongside exact IDs, fingerprints and unique
  prefixes. An ambiguous lookup returns `VGL-AMBIGUOUS` with `candidates[]`
  instead of guessing; failures carry stable `VGL-*` codes in
  `structuredContent.error.code`.
- Bounded MCP output: page envelopes (`offset`, `limit`, `total`, `hasMore`,
  `nextOffset`) on scan, review, hardening, MCP audit, rules, history and
  baseline list results, plus coverage blocks (`filesScanned`, `filesSkipped`,
  `bytesScanned`, `errors`, `llmUsed`) on scans. `maxFindings` is a window
  (default 50, cap 500), not a silent report cap.
- Baseline MCP parity: `ticket`, `expires`, `disposition`, `dryRun`, `prune` and
  `batch` (max 50, defaults to `dryRun=true`, per-item results). `action=list`
  windows findings with `offset`/`limit` and returns `findingsTotal` plus
  `expired` over all entries. The schema stays version 2, so a 0.10 build can
  still read the file.

### Changed

- `vigil_baseline` supports `add`, `remove`, `prune`, `batch` and `clear`
  alongside `list`; writes are rejected in read-only mode and batch argument
  errors write nothing. `clear` requires `confirm=true`, reasons are sanitized
  and capped, and the legacy fingerprint/expired lists are capped at 500 with
  totals.
- The `fix_finding` prompt now walks propose → review → apply with `fixId` and
  `diffSha256`, and is hidden in read-only mode.

### Security

- Proposal files are authenticated with a per-process key, so a proposal
  committed to the repository or written by another process cannot be applied;
  a restarted server requires a fresh proposal. When `.vigil` is a symlink or
  otherwise unsafe, proposals fall back to the user cache instead of writing
  outside the tree.
- Read-only mode is enforced by handlers, not only by `tools/list`: a hidden
  tool stays registered and a direct call is refused with `VGL-READONLY`.
- Offline mode is a construction-time guarantee: model settings and OSV are
  cleared before the engine is built, so a configured endpoint cannot be used.
- Fix approval binds the applied diff to the reviewed proposal with a 15-minute
  TTL, single use and target pre-image checks; the apply path re-derives the
  target set from the stored diff. A failed apply still consumes the proposal.
- The CLI `vigil fix --apply` path is unchanged and unbound; only the MCP path
  requires a reviewed `fixId`/`diffSha256`.
- Offset values above the 500-finding paging cap are rejected instead of
  overflowing into an uncapped scan. A non-empty unparsable
  `VIGIL_MCP_READ_ONLY`/`VIGIL_MCP_OFFLINE` value stops the server instead of
  silently disabling the mode.

## 0.10.1 - 2026-11-16

Patch release. **No code or rule changes**: 263 rules in ten families, 14 MCP
tools.

### Fixed

- Release-pipeline validation: the workflow installs cosign through
  `sigstore/cosign-installer` v4 and pins `cosign-release: v2.4.1`, so
  `checksums.txt` is signed into the same keyless `checksums.txt.sigstore.json`
  bundle that 0.9.3 and 0.10.0 shipped. The 0.10.1 run confirms that
  `cosign verify-blob --bundle` accepts the bundle produced through the v4
  installer. Release assets are unchanged from 0.10.0: six static binaries, six
  Linux packages, the CycloneDX SBOM, `checksums.txt` with its bundle, and the
  multi-arch GHCR image.

### Changed

- Post-0.10.0 distribution documentation: per-channel status in
  [docs/distribution.md](docs/distribution.md), the AUR package name
  `vigil-security-bin` (`vigil-bin` belongs to an unrelated project), and
  refreshed install, CI, PyPI, container, pre-commit and release docs.
- Version references and the composite action default move to `0.10.1`.

## 0.10.0 - 2026-11-16

Minor release. **No rule changes**: 263 rules in ten families, 14 MCP tools.

### Added

- Baseline format v2: entries carry `fingerprint`, `ruleId`, `path`, `ticket`
  and `expires`; version-1 files load and upgrade in memory.
  `vigil baseline add` accepts `--ticket`, `--expires` and `--path`,
  `list` shows that metadata and `vigil baseline prune [--dry-run]` removes
  expired entries, which stop suppressing immediately. SARIF reports emit
  `suppressions` for baseline (`external`) and inline (`inSource`) ignores,
  with `baselineState` on baseline results.
- Anti-RE hardening platform presets: `RuleMeta.Platform`,
  `vigil hardening --platform android|ios|electron|node|flutter|web|other|all`
  and the `platform` argument on `vigil_hardening` narrow the VGL-ARE review.
- `vigil config validate [path] [--json]` loads the user and project config
  with scan precedence, exits 1 on errors and never opens the store or a model;
  `vigil config show [--json]` prints effective values with their sources and
  masks credentials.
- Report-only JUnit: `vigil report --format junit` renders a stored scan as
  `testsuites`/`testsuite` named `vigil`; `scan --format junit` is rejected with
  a hint.

### Changed

- Version references and the composite action default move to `0.10.0`. Release
  assets are unchanged from 0.9.3.

## 0.9.3 - 2026-11-15

Distribution metadata release. **No code or rule changes**: 263 rules, 14 MCP
tools.

### Added

- Published to the official MCP Registry as
  `io.github.LevapVeeskela/vigil` v0.9.3: `mcpName` in the npm package and a
  `server.json` manifest, so registry-aware clients can resolve and install the
  stdio server (`npx -y lv24-vigil mcp`). Layout and verification:
  [docs/mcp-registry.md](docs/mcp-registry.md).
- AUR packaging (`vigil-security-bin`) prepared for the published release assets, with
  build and verification steps in [docs/aur.md](docs/aur.md). Publication waits
  for AUR registration to reopen.
- MCP directory and CII submission preparation, tracked in
  [docs/mcp-directories.md](docs/mcp-directories.md).

### Changed

- Version references and the composite action default move to `0.9.3`. Release
  assets are unchanged from 0.9.2.

## 0.9.2 - 2026-11-15

Release-pipeline fix. **No code or rule changes**: 263 rules, 14 MCP tools.

### Fixed

- The release workflow installs cosign after the GoReleaser build, so
  goreleaser-action verifies its own binary with the bundled cosign. The 0.9.1
  tag failed before publishing; 0.9.2 supersedes it. Keyless signing still
  covers `checksums.txt` and the release assets are unchanged.

## 0.9.1 - 2026-11-15

No rule changes (263 rules, ten families, 14 MCP tools): the same engine as
0.9.0, delivered through more channels and attributable end to end.

### Added

- Native Linux packages: `vigil-<version>-linux-<arch>.deb`, `.rpm` and `.apk`
  for amd64 and arm64, built by GoReleaser from the same `-ldflags` as the
  binaries. Each installs the binary, a `/usr/bin/vigil` symlink and the
  license; deb and rpm declare `Provides: vigil`.
- A CycloneDX 1.6 self-SBOM asset (`vigil-sbom-<version>.cdx.json`) generated on
  the runner from the tagged tree with `vigil sbom`.
- Keyless cosign signing: `checksums.txt.sigstore.json`, a bundle over
  `checksums.txt` and therefore over all six binaries and six Linux packages.
- SLSA build provenance from `actions/attest-build-provenance` for every file in
  `release-assets/`, checked with `gh attestation verify`.
- A multi-arch container image at `ghcr.io/levapveeskela/lv24-vigil`
  (`linux/amd64`, `linux/arm64`, distroless, `nonroot`) with BuildKit
  provenance and SPDX SBOM attestations, published by
  `.github/workflows/container.yml` for a `v*` tag or on demand.
- `pre-commit` hooks (`.pre-commit-hooks.yaml`: `vigil-scan` and the opt-in
  `vigil-mcp-audit`) and [docs/pre-commit.md](docs/pre-commit.md).
- OpenSSF Scorecard (`.github/workflows/scorecard.yml`) with published results,
  and the Scorecard, pre-commit and Go Reference badges in both READMEs.

### Changed

- The release pipeline fails when a tag does not produce exactly six binaries,
  six Linux packages and `checksums.txt`, before anything is published.
- `action.yml` defaults to `0.9.1`; the documented pin is `@v0.9.1`.
- Install docs cover the GHCR image (tags, digest pinning, attestation checks)
  and the deb/rpm/apk packages; the READMEs link the pre-commit setup.

## 0.9.0 - 2026-11-15

263 rules (42 new since 0.8.0), inline suppression, an offline MCP configuration
audit and SBOM export.

### Added

- 42 deterministic rules since 0.8.0. The security-tool research pass added 27:
  provider-specific secrets (1Password, age, Docker Hub, Discord, Stripe webhook
  secrets, PyPI, RubyGems, Terraform Cloud), LDAP/XPath injection, unsafe
  SnakeYAML, Jinja2 `autoescape=False`, an exposed `phpinfo()`, zip-slip and
  upload path traversal, SSH
  host-key verification, five mobile/desktop anti-RE checks, five
  Terraform/Kubernetes/Compose checks and a CI scanner-gate check.
- 15 more deterministic rules: `VGL-MCP-001`–`VGL-MCP-010` audit MCP server
  configuration posture (unpinned packages, literal secrets, cleartext
  endpoints, TLS bypass), `VGL-AUTH-023` covers JWT key material taken from the
  token header, `VGL-WEB-026` covers a static file server rooted at the project
  root, `VGL-INJ-063` covers Django raw SQL APIs receiving formatted SQL,
  `VGL-INJ-064` covers PHP XML parsing with entity substitution or external
  DTDs, and `VGL-INJ-065` covers Ruby `raw`/`html_safe` rendering request data.
  Catalog: **263 rules** in ten families.
- Inline suppression: a `vigil:ignore` comment on the finding's line or the line
  above suppresses matching findings, optionally limited to rule IDs and
  annotated with `reason="..."` and `until=YYYY-MM-DD`. Suppressed findings stay
  in the result with `suppressed: true`; an expired or malformed directive emits
  a warning and suppresses nothing. Disable per run with
  `--no-inline-suppressions`, or in configuration with
  `scan.inline_suppressions: false`.
- `vigil mcp-audit [path] [--user]` and the `vigil_mcp_audit` MCP tool run only
  the `VGL-MCP` rules over MCP server configuration files (`.mcp.json`,
  `mcp.json`, `mcp-config.json`, `claude_desktop_config.json`, `opencode.json`,
  `*.mcp.json` and YAML variants). Deterministic and offline: no configured
  server is started and no endpoint is contacted.
- `vigil sbom [path] [--format cyclonedx|spdx] [--include-dev]` exports the
  declared dependency inventory as CycloneDX 1.6 (default) or SPDX 2.3 JSON.
  The document is reproducible (inventory-derived serial number and SPDX
  namespace, `SOURCE_DATE_EPOCH` timestamp), offline, and does not resolve
  version ranges.
- Python dependency collection covers `requirements*.txt`, `-r` includes and
  PEP 621 `pyproject.toml` dependencies.

### Fixed

- OSV advisories that the source withdrew are no longer reported; `MAL-*`
  records are critical malware findings with remove/rotate remediation.
- The pre-commit hook scans the staged diff (`git diff --cached`) instead of the
  working tree, so a staged-then-reverted secret is still caught.
- `VGL-WEB-002` covers Java and PHP traversal sinks; `VGL-WEB-003` covers Java
  `sendRedirect` and Spring `redirect:`.

### Changed

- Documentation counts and family tables now report 263 rules, ten families and
  14 MCP tools.

## 0.8.0 - 2026-11-11

Upgrade from 0.7.x if you use `vigil dependencies` or `scan.osv`: 0.7.x
reported every OSV advisory as `medium`. The minor bump is for the breaking
project-config change below.

### Security

- **Breaking for project files:** `scan.osv_base_url` is rejected in a
  committed `.vigil.yaml` / `.vigil.yml` / `vigil.yaml`, like `base_url`. A
  scanned repository could otherwise send the package inventory to its own host
  and feed back forged advisory records. Set a mirror in the user config or with
  `VIGIL_OSV_BASE_URL` (in CI, as a workflow `env`), or pass `--osv-base-url`.
- The MCP `vigil_dependencies` argument `osvBaseUrl` accepts `https`, or plain
  `http` only on a loopback host (`127.0.0.1`, `::1`, `localhost`), and refuses
  credentials in the URL without echoing them.

### Changed

- `vigil status` / `vigil doctor` no longer stop at a configuration that does
  not load. They print a reduced report with a `configError` object (`file`,
  `key`, `message`, `fix`) that says where a rejected key belongs (user config
  path or environment variable, plus the CI `env:` / `variables:` form), without
  printing the configured value or editing any file. The exit code stays `1`;
  `--json` now emits valid JSON in this case, and `configError` is `null` when
  the configuration is fine.

### Fixed

- **Dependency severities were always `medium`.** OSV `querybatch` returns
  advisory IDs only, so every real finding fell back to the default severity
  with no fixed version or description, and `--fail-on high` could never fire
  on a dependency advisory. Vigil now fetches each advisory's full record
  (`GET /v1/vulns/{id}`, bounded to 500 records, 8 concurrent requests) and
  warns when a record cannot be fetched.
- A `querybatch` response with a different result count than queries is now
  discarded for that batch instead of attributing advisories by position to
  possibly the wrong packages.
- Dependency coverage gaps are reported as warnings instead of being silently
  dropped: oversized or unparseable manifests, an inventory truncated by the
  package limit and packages left unqueried after a failed batch.
- OSV result pages are followed (`next_page_token`, up to 10 pages per package
  and 200 page requests per audit) instead of reading only the first page; a
  limit that is hit is reported.
- OSV findings in `vigil scan` (with `scan.osv`) now go through the baseline and
  `disable_rules`, so an accepted advisory can be suppressed like any finding.
- `vigil_scan`, `vigil_review`, `vigil_explain`, `vigil_fix` and
  `vigil_threat_model` declare `openWorldHint: true`: they can reach a
  configured model (and OSV for scan/review).
- Anti-RE debug/dev/test/example path checks match whole words instead of
  substrings: `devportal/`, `devtools/`, `debugger/` or `latest/` no longer
  hide findings, while `src/dev`, `RunnerDebug`, `vite.config.dev.ts` and
  `e2e/` are still treated as non-release (`e2e/` was previously reported).
- `VGL-ARE-055` also reports Hermes disabled in the Podfile
  (`:hermes_enabled => false`, `hermes_enabled: false`, `ENV['USE_HERMES'] =
  '0'`) and in the pre-0.71 Gradle template (`enableHermes: false`).
- The repository ships a `.vigil.yaml` with the same excludes as the CI
  self-scan, so a local `vigil scan .` matches the gate.
- `vigil hardening --rules` can only narrow the anti-RE set; a non-`VGL-ARE`
  ID is rejected instead of silently running other rule families. `vigil
  hardening --help` now describes the command instead of the generic scan.
- `vigil_hardening` no longer names a configured model in its summary; the
  hardening scan never uses one.
- `VGL-ARE-001`–`005` skip example and test apps (for example a Flutter
  plugin's `example/` app, whose template signs release with the debug key)
  and `androidTest` manifests, like the other anti-RE rules.
- `VGL-ARE-020` no longer flags `flutter build web --release`; Flutter does not
  support `--obfuscate` for web.
- `VGL-ARE-052`/`053` scope `project.pbxproj` settings by every build
  configuration header, so `Profile`, `Staging` or `Debug-dev` blocks after a
  `Release` block are not reported, and `Release-prod` style configurations are.
- `VGL-ARE-054` treats an enclosing `if (BuildConfig.DEBUG) {` block as a debug
  guard (negated checks and `else` branches still fire).
- `VGL-ARE-057`/`058` match the documented `[FuseV1Options.RunAsNode]: true`
  computed-key form used by `@electron/fuses` and the Forge FusesPlugin, and
  only read JS/TS/JSON/YAML files, so Markdown docs that quote a fuse setting
  are no longer reported.
- MCP `prompts/list` and `resources/list` return a stable, name-sorted order
  instead of Go map order.

## 0.7.1 - 2026-11-11

### Fixed

- `VGL-ARE-006` no longer flags a `network_security_config.xml` under
  `src/debug` (or another debug variant); debug-only configs are not shipped in
  the release APK.
- `VGL-ARE-053` no longer flags `COPY_PHASE_STRIP = NO` by itself. Modern Xcode
  projects use that default while `STRIP_INSTALLED_PRODUCT = YES` still strips
  the shipped binary. The rule now reports only `DEBUG_INFORMATION_FORMAT =
  dwarf` and `STRIP_INSTALLED_PRODUCT = NO`.

## 0.7.0 - 2026-11-11

### Added

- **23 anti-RE hardening rules** (`VGL-ARE`): Android release minification and
  debug signing, debuggable/backup/cleartext manifest settings, network security
  config cleartext, iOS `get-task-allow` and ATS arbitrary loads, Flutter release
  obfuscation, Electron `webSecurity`/Node isolation, Node inspector flags and
  production source maps. A second wave covers the artifact surfaces a
  reverse-engineering toolkit inspects: Rust debug symbols and DWARF, .NET debug
  symbols and optimization, iOS testability and debug symbols, Electron fuses
  and ASAR, JavaScript minification, Android WebView debugging and Hermes. These
  are missing-control posture checks, not vulnerability or exploitability
  claims; the mapping is documented in `docs/anti-re-hardening.md`.
- **`vigil_hardening` MCP tool** and **`vigil hardening` CLI command** run only
  the `VGL-ARE` rules, deterministically and offline.
- **`vigil_dependencies` MCP tool** and **`vigil dependencies` CLI command**
  inventory supported manifests/lockfiles and query OSV.dev for known public
  advisories. Network is explicit; no package manager runs and nothing is
  written.
- **Wider OSV inventory**: pnpm and Yarn lockfiles, `Pipfile.lock`,
  `poetry.lock`, `uv.lock`, `pubspec.lock`, `gradle.lockfile` and NuGet
  `packages.lock.json`, plus `Pub` and `NuGet` ecosystems.
- MCP prompts `anti_re_hardening` and `dependency_audit`; `--no-osv` scan flag.

### Changed

- Rule catalog is now **221** deterministic rules in nine families.
- `vigil_hardening` never mixes configured OSV findings into a posture report.

## 0.6.0 - 2026-11-11

### Added

- **35 new deterministic rules** (198 total): 5 secrets (Telegram, Vault, npm,
  GitLab, Azure Service Bus), 3 dependency/TLS checks (Composer, Yarn, Go
  checksum), 10 injection/language sinks (Go SQL, Java XXE/JNDI, Ruby/.NET
  deserialization, TypeNameHandling, Python popen/pickle, PHP extract, EF Core
  raw SQL), 6 crypto/auth/web (Java/.NET/PHP/Ruby TLS verification, legacy TLS,
  OAuth redirect_uri, Spring actuator) and 11 config/IaC/CI (Docker privileged
  and host namespaces, seccomp/AppArmor, dangerous caps, IAM/SG/S3/IMDS,
  workflow_run checkout, github-script injection, nginx upstream TLS).
- Rules were selected from gitleaks/trufflehog/detect-secrets, Semgrep, Bandit,
  gosec, FindSecBugs, Brakeman, nodejsscan, hadolint, Checkov/tfsec/KICS,
  kube-linter/kubesec, zizmor and OWASP guidance; noisy or taint-only candidates
  were rejected.

### Changed

- The composite action default CLI version is now `0.6.0`. No engine, CLI or MCP
  behaviour changes beyond the new rules.

## 0.5.4 - 2026-11-11

### Fixed

- The composite action now installs the npm CLI version hardcoded to the action
  release (`0.5.4`) instead of relying on `GITHUB_ACTION_REF`, which is empty in
  composite actions. `uses: ...@v0.5.4` installs `lv24-vigil@0.5.4`; an explicit
  `version` input still overrides it. The Marketplace smoke workflow asserts the
  resolved version.
- The 0.5.3 tag's auto-ref attempt is superseded; it fell back to `latest` in
  the smoke test. No engine, rule, CLI or MCP behaviour changes.

## 0.5.3 - 2026-11-11

### Changed

- The composite action now installs the npm CLI version matching the action tag
  (`GITHUB_ACTION_REF`) by default; an explicit `version` input still overrides
  it. `uses: ...@v0.5.3` is reproducible instead of silently following `latest`.
- The npm README carries the GitHub Marketplace badge. No engine, rule, CLI or
  MCP behaviour changes.

## 0.5.2 - 2026-11-10

### Changed

- Documentation-only release: the PyPI release-trigger clarification and the
  `0.5.0` stale-template warning are now part of the tagged tree. No runtime,
  rule, CLI or MCP behaviour changes.
- The composite action is listed on the GitHub Marketplace as `Vigil security
  scan` (Security + Code quality).

## 0.5.1 - 2026-11-10

### Fixed

- `examples/github-workflow.yml`, the GitHub workflow snippet in `README.md`,
  `README.ru.md` and `docs/ci.md` now read the `fail-on` dispatch input as
  `${{ inputs['fail-on'] }}`. `inputs.fail-on` is parsed as a subtraction and
  the workflow fails validation before it runs.
- `examples/gitlab-ci.yml` and `docs/ci.md` run `vigil precheck` only when
  `vigil.sarif` exists, so a scan that failed before writing the report no
  longer turns into a confusing pre-check error.
- The released tag now contains the corrected templates. `v0.5.0` predates
  them; it stays published and immutable, and `0.5.1` supersedes it for anyone
  copying the CI examples.

### Unchanged

- No runtime, rule, CLI or MCP behaviour changes: the Go engine, npm launcher
  and Python launcher only carry the new version metadata. The composite action
  example and the documentation pins move to `0.5.1`.

## 0.5.0 - 2026-11-10

### Added

- `vigil hook install|status|uninstall`: a first-class local audit gate.
  `install` writes `.git/hooks/pre-commit` (default) or `pre-push` with the
  `# managed by lv24-vigil` marker, `#!/bin/sh` and the executable bit. The
  pre-commit hook runs
  `vigil scan --changed --base HEAD --no-llm --fail-on high --quiet`; pre-push
  diffs against `@{upstream}` with a `HEAD~1` fallback. Hooks honour
  `VIGIL_BIN`, check `command -v`, and fail with installation instructions when
  the binary is missing. A foreign hook is never replaced silently: install
  refuses without `--force`, and `--force` saves `<hook>.pre-vigil.bak`.
  `status` prints installed hooks, marker and target command; `uninstall`
  removes only marked hooks and restores the backup.
- `examples/gitlab-ci.yml`: a `vigil` job for merge requests, the default branch
  and manual web runs, with a plain SARIF artifact, optional native SARIF
  report ingestion and an optional LV24 pre-check.
- `action.yml` is now a composite action that installs the npm package and runs
  `vigil scan` with `path`, `fail-on`, `no-llm`, `format` and `version` inputs.
  It needs Node.js 18+ on the runner.

### Changed

- `examples/github-workflow.yml` now covers `workflow_dispatch` (with a
  `fail-on` input, default `high`), `pull_request` and pushes to `main`. It
  installs `lv24-vigil@latest` with `actions/setup-node`, writes SARIF, uploads
  it with `github/codeql-action/upload-sarif`, and optionally runs
  `vigil precheck` when `VIGIL_SECURITY_API_TOKEN` is set.
- README (English and Russian), npm README, `docs/ci.md`, `docs/cli.md`,
  `llms.txt` and `AGENTS.md` document the three audit paths (local hook, GitHub
  Actions, GitLab CI), the pre-check secret and the agent rule to run
  `vigil scan --no-llm --fail-on high` before commit without auto-fixing or
  committing.
- The Go version constant and the Python launcher/pyproject move to `0.5.0`.
  npm package versions are derived from the release tag.

## 0.4.1 - 2026-11-10

### Changed

- Public documentation rebuilt for humans and agents: a visual README with a
  package-choice table and quickstart, and a matching npm page, so the registry
  listing explains what Vigil is before the fold.
- New SVG banner (`.github/assets/banner.svg`) used by both READMEs and the npm
  page.
- `llms.txt` and `AGENTS.md` give coding agents the install paths, CLI/MCP
  surfaces and safety boundaries without scraping HTML; a Cursor MCP example
  lives in `examples/cursor.md`.
- npm metadata: the description now leads with the value proposition
  ("security audit for your code on your own model") and the keywords target
  discovery (`sast`, `mcp`, `vulnerability-scanner`, `code-review`, `go`).
- `docs/install.md` and `docs/ci.md` pin `0.4.1`; the Python launcher moves to
  `0.4.1` so it runs the matching npm version by default.

### Unchanged

- No runtime, rule, CLI or MCP behaviour changes: this release is documentation,
  packaging metadata and version pins only.

## 0.4.0 - 2026-11-10

### Added

- `vigil precheck` uploads a SARIF 2.1.0 report to the LV24 security control
  plane (`POST /security-scans/prechecks`) with a staff JWT (`ops:security-scans`).
  Local SARIF validation, `--json`, `VIGIL_SECURITY_API_TOKEN` fallback, and no
  scan is started.
- `examples/config.command.yaml`: a keyless `provider: command` example that
  uses the locally authenticated `opencode run --format json --agent plan`.
## 0.3.0 - 2026-11-10

### Added

- `command` LLM provider: run a local CLI as the model backend without storing
  an API key. The documented example uses `opencode run --format json --agent
  plan` with OpenCode Go; `command_output: opencode-json` parses the JSONL
  stream. A project `.vigil.yaml` cannot set the command or its environment.

### Changed

- Dependabot: `actions/checkout` v7, `actions/setup-go` v7,
  `actions/setup-node` v7, `goreleaser/goreleaser-action` v7 and
  `github/codeql-action/upload-sarif` v4 (all pinned to commit SHAs).

## 0.2.1 - 2026-11-10

### Fixed

- npm publishing now runs as the `npm-publish` workflow itself, triggered by
  `workflow_run` after a successful `release`. A reusable-workflow call from
  `release.yml` does not match the npm Trusted Publisher, which is bound to the
  workflow file that owns the publish job.
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

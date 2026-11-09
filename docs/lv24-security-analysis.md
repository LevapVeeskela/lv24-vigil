# LV24 security analysis: Strix upstream sync and the Vigil layer

This page records what changed in the Strix upstream between the two commits the
LV24 fork has used, what the fork backported, what it deliberately skipped, and
where Vigil fits. It is an engineering note, not a benchmark.

Sources: `main/security-engine/PATCHES.md`, `main/security-engine/README.md`,
`main/security-scans-api/README.md`, and the upstream tree at `215482eb`. These
paths refer to the LV24 monorepo, not to this repository.

## The two bases

| | Commit | Date | Upstream package |
|---|---|---|---|
| Previous base | `6b7ae2ebe4d47037a927aade23265ff4e4f27e84` | 2026-10-29 | `strix-agent` |
| Current base | `215482eb2204cd30ac6b87520e3f5c6511e2e2e8` | 2026-11-08 | `strix-agent` 1.7.0 |

Both are Apache-2.0. The fork moved its pin on 2026-11-09. Every ported path was
byte-identical to the previous base before the move, so no LV24 patch had to be
merged by hand and all `LV24-Pn` markers stayed unchanged. After the move,
`strix/` differs from upstream only by the registered patches;
`scripts/sync-upstream.ps1` lists them as expected copy drift.

## What changed upstream

### 1. Opengrep replaces semgrep

The white-box static tooling moved from semgrep to opengrep:

- new `strix/skills/tooling/opengrep.md`;
- removed `strix/skills/tooling/semgrep.md`;
- updated text in `strix/skills/README.md`,
  `strix/skills/coordination/source_aware_whitebox.md`,
  `strix/skills/custom/source_aware_sast.md`,
  `strix/skills/frameworks/django.md`,
  `strix/skills/scan_modes/{quick,standard,deep}.md`,
  `strix/skills/tooling/agent_browser.md` (dead `references/*.md` links became
  plain paths),
  `strix/skills/vulnerabilities/semantic_confusion.md` (email/IDNA identity-drift
  section), and `strix/agents/prompts/system_prompt.jinja`.

No `semgrep` reference remains under `strix/`, `containers/` or `tests/`.

### 2. Bundled offline opengrep rules

`containers/Dockerfile` now:

- installs opengrep **1.31.0**;
- bakes the community ruleset into `/opt/opengrep-rules` at a pinned ref, with
  tests, fixtures, tooling and `license: proprietary` rules removed;
- copies the Strix rules to `/opt/opengrep-rules/strix`;
- pins trivy to **0.76.1** with sha256 verification;
- resolves the gitleaks tag without the GitHub API;
- drops `pipx install semgrep`.

The new `COPY` keeps the repository root as the build context, which matches the
fork layout. LV24 never builds this file: the Docker gateway pulls the sandbox
image, so the change does not alter a LV24 build assumption.

### 3. New CI rule

`containers/opengrep-rules/github-owned-action-not-pinned-to-commit-sha.yaml`
adds a rule for GitHub Actions that are not pinned to a commit SHA. It ships with
the bundled ruleset, not as a separate LV24 rule.

### 4. Dedupe decision validation

`strix/report/dedupe.py` and the new `tests/test_dedupe_decisions.py` harden the
dedupe path:

- a decision is honoured only when `is_duplicate` is a real boolean;
- a `true` decision must name an id present in `existing_reports`;
- the id is kept verbatim (no `[:64]` truncation), so an unknown id cannot alias
  an existing report;
- a malformed decision falls into the existing fail-open path
  (`is_duplicate: false` plus `error`) instead of suppressing a finding.

This matters because a false dedupe silently removes a real vulnerability from a
report.

### 5. Default sandbox image 1.4.0

`strix/config/settings.py` changed the default `STRIX_IMAGE` from `1.3.1` to
`1.4.0`. The 1.4.0 image is the one with opengrep tooling and the bundled
`/opt/opengrep-rules`.

### 6. Skill updates

The skill tree was updated for the opengrep move and for several accuracy fixes:
source-aware whitebox, source-aware SAST, Django, the three scan modes, the agent
browser tool notes, semantic confusion and the system prompt. These are prompt
and knowledge changes, not engine changes.

### 7. Pin metadata

`lv24_engine/__init__.py` follows `upstream.sha`; the scaffold test asserts both
agree. The fork's `UPSTREAM_PIN` is part of the sync, not a separate patch.

## What the LV24 fork backported

| Upstream change | Backported? | Where |
|---|---|---|
| Opengrep skill and text updates | yes | `strix/skills/**`, `strix/agents/prompts/system_prompt.jinja` |
| Bundled opengrep rules and image tooling | yes, as a reference copy | `containers/Dockerfile`, `containers/opengrep-rules/**` |
| New GitHub Action pinning rule | yes | `containers/opengrep-rules/github-owned-action-not-pinned-to-commit-sha.yaml` |
| Dedupe decision validation | yes | `strix/report/dedupe.py`, `tests/test_dedupe_decisions.py` |
| Default image `1.4.0` | yes, in code | `strix/config/settings.py` |
| `UPSTREAM_PIN` move | yes | `lv24_engine/__init__.py`, `upstream.sha` |

The fork's own patches (`LV24-P1` through `LV24-P9`) were not rewritten by this
sync. `P1` configures the runs directory, `P2` stages source archives instead of
bind mounts, `P2b` adds Docker-gateway compatibility, `P3` adds a per-process tool
denylist, `P4` handles strict tool schemas and reasoning flags, `P5` renders the
authorization block, `P8` hardens report emission and `P9` covers severity
calibration at the store call site. `P6` is the root prompt overlay owned by the
WP1 adapter, not by the upstream sync.

## What was skipped and why

- **`.github/workflows/**` and `.pre-commit-config.yaml`** are not vendored. LV24
  has its own CI and pre-commit policy; copying upstream workflows would create a
  second, conflicting pipeline.
- **`docs/**.mdx` and `scripts/install.sh`** are not copied. The fork keeps
  `UPSTREAM_README.md` and the TUI sidecar hook because the build metadata
  references the hook; the rest of the upstream docs and installer are not part
  of the embedded library.
- **The sandbox image pin was not moved in deployment.** The fork default is now
  `1.4.0`, but `infra/docker-compose.security.yml` and
  `infra/scripts/security-preflight.{ps1,sh}` still pin
  `ghcr.io/usestrix/strix-sandbox:1.3.1`. This is deliberate: the Docker gateway
  never pulls images itself, so an operator must pull and verify `:1.4.0` before
  moving the pin. `1.3.1` ships semgrep, not opengrep, and has no
  `/opt/opengrep-rules`; the white-box static pass now names a tool the image
  lacks. Moving the pin is an ops/deployment change, not a library change.

That last item is the main follow-up before the next execution-enabled scan. It
is tracked as a sandbox-image mismatch in `PATCHES.md`, not as an upstream sync
failure.

## What the fork adds around Strix

The fork is not just a copy of the upstream tree. It adds a small adapter
(`lv24_engine/`) and a controlled patch set so Strix can run as a library behind
the LV24 control plane:

- `security-scans-api` (`:3791`) is the Go control plane. It owns staff
  authorization, runs, findings, artifacts, schedules, reports and the
  kill-switch.
- `security-engine` is the Python runner. It claims a run, prepares the
  workspace, calls `run_strix_scan`, streams events and findings, uploads
  artifacts and completes the run.
- `security-docker-gateway` is the only Docker-socket holder. It creates the
  sandbox with a fixed spec and a label fence; it never pulls images.
- The sandbox runs on `lv24-security-sandbox-net`, not the city network, and has
  no WAN port.
- Model calls go through `ai-gateway`; public runs are forced to `lv24/auto` with
  a fail-closed tool/context preflight.

The control plane and the engine are separate from the product request path. The
kill-switch has two layers: env `SECURITY_SCANS_ENABLED=1` and PG
`security_scan_settings.layer_enabled=true`. When off, execution returns
`503 DISABLED`; health stays up.

## How Vigil relates

Vigil is **not** a Strix fork and shares no code with `security-engine` or
`security-scans-api`.

- **Strix fork** = autonomous, sandboxed, exploit-validating pentest runtime for
  staff-authorized assessments. It is heavy by design and runs behind a control
  plane.
- **Vigil** = developer-facing static + LLM auditor. It runs locally, needs no
  Docker, executes no target and exposes itself as an MCP server so a coding
  agent can use it while writing code.

They are complementary layers:

| Layer | Tool | Question it answers |
|---|---|---|
| Inner loop | Vigil | "Is there a risky pattern in this change?" |
| Deep assessment | Strix fork | "Is this actually exploitable, with a proof?" |

Vigil can point at a suspicious area and propose a fix; the Strix fork can then
validate the issue in a sandbox when the risk justifies the cost. Neither tool
should be described as replacing the other.

## Status and honest limits

As of 2026-11-09, the LV24 security plane is an engineering-local contour:

- `security-engine` and `security-scans-api` are landed locally, not SHIPPED.
- Production is untouched; migrations 209/210/211/212 are local only.
- Execution, report delivery and retention are OFF by default.
- No live email/Telegram send and no retention deletion have run.
- Finding emission is nondeterministic and severity calibration is unverified.
  A same-model pair produced one critical finding and then zero findings; a
  read-only SQL injection PoC was over-rated before calibration work. The fix was
  verified on one replayed sample, not on a repeated live run.
- There is no prod soak.

These limits belong to the pentest plane. They do not change Vigil's
deterministic rules, but they are the reason this page does not claim a benchmark,
a detection rate or production readiness for either layer.

## References

Paths below are in the LV24 monorepo.

- `main/security-engine/PATCHES.md` - upstream patch register and sync notes.
- `main/security-engine/README.md` - adapter, configuration, security model.
- `main/security-scans-api/README.md` - control plane, kill-switch, reports.
- `main/docs/plans/2026-11-04-lv24-security-scans-strix-fork-design.md` - design
  source of truth.
- [comparison.md](comparison.md) - Vigil vs Strix vs hosted scanners.
- [architecture.md](architecture.md) - Vigil's own design.

# Release and npm publishing

Vigil ships from git tags. A tag produces the GitHub release with six static
binaries, and a second job publishes seven npm packages. Since `0.1.4` the npm
half runs on npm Trusted Publishing (OIDC): no npm token is stored in the
repository or in GitHub secrets, and npm records a provenance attestation for
each published package.

## How a release works

Push a tag `vX.Y.Z`:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The release version comes from the tag: GoReleaser injects it with `-ldflags`,
so the binaries follow the tag. The constant in `internal/version` is the local
build fallback; the Python launcher version in `python/pyproject.toml` and
`python/src/lv24_vigil/__init__.py` must be bumped in the release commit because
the PyPI workflow validates it against the tag. npm package versions are
generated from the tag.

```text
 git tag vX.Y.Z
      |
      v
 release.yml
   GoReleaser (CGO off)  ->  6 binaries + checksums.txt
   asset check           ->  fail unless exactly 6 binaries + checksums.txt
   gh release create     ->  GitHub release (notes generated, prerelease if the tag has "-")
      |
      v
 npm-publish.yml (reusable workflow, needs: release)
   gh release download   ->  release-assets/
   node npm/build.mjs    ->  verify every SHA-256, write 7 packages
   bash npm/publish.sh   ->  OIDC publish: 6 platform packages, then lv24-vigil
```

| Step | Workflow | Result |
|---|---|---|
| Tag push | `release.yml` | Workflow starts; the tag is the version |
| Build | `release.yml` | `vigil_<version>_<goos>_<goarch>[.exe]` for windows, linux and darwin on amd64 and arm64, plus `checksums.txt` (SHA-256) |
| Asset check | `release.yml` | The run fails unless exactly six binaries and `checksums.txt` are present |
| GitHub release | `release.yml` | Creates `vX.Y.Z` with generated notes; a tag containing `-` becomes a prerelease; on a re-run only missing assets are uploaded |
| Package build | `npm-publish.yml` | `npm/build.mjs` verifies each binary against `checksums.txt` and writes nothing unless all six match |
| npm publish | `npm-publish.yml` | Platform packages first, then the launcher; versions already on npm are skipped |

npm is a separate job on purpose. It `needs` the GitHub release, so the binaries
exist before packaging starts, and the publish step is `continue-on-error`, so a
failed npm publish leaves the release published and green. The job ends with a
warning that names the missing setup; re-run it after fixing the cause.

`npm-publish.yml` is both a reusable workflow (called by `release.yml`) and a
`workflow_dispatch` workflow, so it can publish an existing tag on demand.
`release.yml` triggers on any `v*` tag; `npm-publish.yml` accepts only
`v<major>.<minor>.<patch>` with an optional `-prerelease` suffix. `ci.yml` runs a
GoReleaser snapshot and an npm package dry run on pull requests, so asset naming
and package layout mistakes fail before a tag is cut.

## Packages

Seven packages are published for each release:

| Package | Contents |
|---|---|
| `lv24-vigil` | Launcher (`bin/vigil.js`), README, LICENSE; `optionalDependencies` pinned to the same version; `engines.node >= 18` |
| `@lv24/vigil-win32-x64` | `bin/vigil.exe` for Windows x64 |
| `@lv24/vigil-win32-arm64` | `bin/vigil.exe` for Windows arm64 |
| `@lv24/vigil-darwin-x64` | `bin/vigil` for macOS x64 |
| `@lv24/vigil-darwin-arm64` | `bin/vigil` for macOS arm64 |
| `@lv24/vigil-linux-x64` | `bin/vigil` for Linux x64 |
| `@lv24/vigil-linux-arm64` | `bin/vigil` for Linux arm64 |

Platform packages use npm's `os`/`cpu` names (`win32`, `darwin`, `linux`), while
the release assets use Go's (`windows`, `darwin`, `linux`). They contain the
binary only, declare `os`/`cpu`, and run no install scripts. Publish them first:
the launcher resolves the matching platform package at run time, so an install
that cannot find one still succeeds but the first `vigil` call exits `1` with
`platform package ... is not installed`. The same message appears when the
install skipped optional dependencies (`--no-optional` or `--omit=optional`).

A prerelease version (for example `0.5.1-beta.1`) is published under the `beta`
dist-tag; `latest` is left untouched.

## One-time bootstrap: Trusted Publishing

npm has to know which GitHub workflow may publish each package. Until that
relationship exists, the OIDC token exchange fails and npm reports the package
as not found. Configure it once per package, before the first OIDC publish.

```bash
npm login --auth-type=web
```

Then, for each of the seven packages:

```bash
npm trust github lv24-vigil --file npm-publish.yml --repo LevapVeeskela/lv24-vigil --allow-publish -y
npm trust github @lv24/vigil-win32-x64 --file npm-publish.yml --repo LevapVeeskela/lv24-vigil --allow-publish -y
npm trust github @lv24/vigil-win32-arm64 --file npm-publish.yml --repo LevapVeeskela/lv24-vigil --allow-publish -y
npm trust github @lv24/vigil-darwin-x64 --file npm-publish.yml --repo LevapVeeskela/lv24-vigil --allow-publish -y
npm trust github @lv24/vigil-darwin-arm64 --file npm-publish.yml --repo LevapVeeskela/lv24-vigil --allow-publish -y
npm trust github @lv24/vigil-linux-x64 --file npm-publish.yml --repo LevapVeeskela/lv24-vigil --allow-publish -y
npm trust github @lv24/vigil-linux-arm64 --file npm-publish.yml --repo LevapVeeskela/lv24-vigil --allow-publish -y
```

- `--file` is the workflow file that contains the publishing job, not the tag
  workflow. That is `npm-publish.yml`: `release.yml` calls it as a reusable
  workflow, and the OIDC claim is issued for the called workflow.
- `--allow-publish` permits `npm publish` from that workflow; `-y` skips the
  confirmation prompt.
- A `409` response means the trusted publisher is already configured. Nothing to
  do.
- `npm trust list <pkg>` prints the current binding, but it always asks for a
  2FA code.

npm 11.5.1 or newer is required for the OIDC exchange in CI (`npm/publish.sh`
refuses an older npm). Use the same or newer npm for the `npm trust` commands.

## Verify a release

```bash
npm view lv24-vigil version          # 0.6.0
npm view lv24-vigil dist-tags        # { latest: '0.6.0' }
npm i -g lv24-vigil@0.6.0            # or @latest
vigil version                        # vigil 0.6.0 (<commit>, <date>, go<version>)
```

Platform packages, one line each:

```bash
for p in win32-x64 win32-arm64 darwin-x64 darwin-arm64 linux-x64 linux-arm64; do
  echo "@lv24/vigil-$p $(npm view "@lv24/vigil-$p" version)"
done
```

Workflow runs:

```bash
gh run list --workflow release.yml --limit 3
gh run list --workflow npm-publish.yml --limit 3
gh run view <run-id> --log
```

The publish step prints `npm: publishing with Trusted Publishing (OIDC), npm
<version>`, then `+ <package>@<version>` for each package. A skipped version
prints `<package>@<version> already on npm; skipping`.

Provenance:

```bash
npm view lv24-vigil dist.attestations
```

For `0.6.0` this returns a `https://slsa.dev/provenance/v1` attestation built
from `.github/workflows/npm-publish.yml` on a GitHub-hosted runner. The npm page
shows the matching provenance badge.

## Tags are immutable; follow-ups after a release

A published tag never moves and is never deleted: `v0.2.0` and later are Go
module versions, and `0.5.0`+ also name the binaries, npm packages and PyPI
artifacts that users install. A fix that lands after a tag lives on `main`;
`main` is the canonical documentation copy, and GitHub serves it by default.

Cut a patch release when a **shipped artifact** changes, or when a **shipped
example that users copy** is wrong:

| Changed after the tag | Patch release? |
|---|---|
| Go code under `cmd/`, `internal/` (binaries) | Yes |
| `npm/bin/vigil.js`, `npm/build.mjs`, `npm/README.md` (the npm page) | Yes |
| `python/src/**`, `python/pyproject.toml`, `python/README.md` (PyPI page) | Yes |
| `action.yml` (users pin `@vX.Y.Z`) | Yes |
| `examples/**`, CI snippets in `docs/ci.md`, or a version pin in the install docs | Yes, when the published snippet is wrong |
| Prose-only `docs/**`, root `README*.md`, `llms.txt`, `AGENTS.md`, CI workflows | No |

The npm tarball ships only `bin/vigil.js`, `README.md`, `LICENSE` and
`package.json` (`files: ['bin']`); the PyPI sdist ships `src/lv24_vigil/`,
`tests/` and `README.md`. Neither contains `examples/` or `docs/`, so template
fixes never reach an installed package. They do reach users who pin the **tag**
or copy `examples/` from it, which is why a wrong template justifies a patch
release: `v0.5.0` shipped `inputs.fail-on` and an unguarded GitLab pre-check,
and `0.5.1` replaces it.

Prose that is merely stale does not justify a re-tag: note it in the CHANGELOG
under `Unreleased`, keep the affected version sections untouched, and mention
the current release in "Current state" below.

Before deciding, verify what users actually have:

```bash
gh release view vX.Y.Z --json assets --jq '.assets[].name'   # binaries + checksums.txt
tar -tzf lv24-vigil-X.Y.Z.tgz                                 # npm: bin/, README, LICENSE
curl -s https://pypi.org/pypi/lv24-vigil/X.Y.Z/json | jq '.urls[].filename'
vigil version                                                 # reports the tag commit
```

### Decision log

- **0.6.0 adds 35 deterministic rules (2026-11-11).** Research compared the
  current catalog with gitleaks/trufflehog/detect-secrets, Semgrep, Bandit,
  gosec, FindSecBugs, Brakeman, nodejsscan, hadolint, Checkov/tfsec/KICS,
  kube-linter/kubesec, zizmor and OWASP guidance. Only P0/P1 high-signal rules
  were selected; noisy/taint-only candidates were rejected. Total: **198** rules
  (secrets 29, injection 47, crypto 16, auth 17, web 18, config/IaC 37, CI 19,
  dependencies 15). No engine/runtime changes beyond the rules; the action
  default moves to `0.6.0`.
- **Do not pin 0.5.0; warn on every surface we can still edit (2026-11-10).**
  The `v0.5.0` tag and its npm/PyPI artifacts are immutable, so only mutable
  surfaces remain. The GitHub **release body** for `v0.5.0` now opens with a
  warning; that is a release-object edit, so the tag still points at `2c26dfd`
  and `v0.5.1` at `600d850`. The npm package version is deprecated in place
  (`npm deprecate lv24-vigil@0.5.0`, a metadata change with no republish and no
  tag move) and the deprecation is live: `npm view lv24-vigil@0.5.0 deprecated`
  shows the warning. The six
  platform packages are **not** deprecated: their binaries are correct and a
  deprecation notice there would only add noise to `npm i` output.
- **0.5.4 hardcodes the action CLI version (2026-11-11).** `GITHUB_ACTION_REF` is
  empty in composite actions, so the 0.5.3 auto-ref logic fell back to `latest`
  (the Marketplace smoke test caught it). 0.5.4 sets the action's `version`
  default to `0.5.4` and installs it; an explicit `version` still overrides.
- **0.5.3 pins the action CLI to the action tag (2026-11-11; superseded).** The
  composite action tried to resolve the npm version from `GITHUB_ACTION_REF`
  when the `version` input was empty. That variable is empty in composite
  actions, so the smoke test installed `latest`; 0.5.4 replaces the approach with
  an explicit default. An explicit `version` input still overrides it.
- **0.5.2 packages the post-0.5.1 docs (2026-11-10).** `9e26aa6` (PyPI
  release-trigger clarification) and `7ca84a5` (do not pin 0.5.0) are
  docs-only. `v0.5.2` puts them in the tagged tree so a release pin carries the
  corrected instructions and the 0.5.0 warning. No Go, npm launcher or Python
  launcher behaviour changed.
- **0.5.1 supersedes 0.5.0 for the CI templates (2026-11-10).** The follow-ups
  `5a39740` (bracket notation for `inputs['fail-on']`) and `c4fe00f` (guard the
  GitLab pre-check on an existing `vigil.sarif`) fix the examples users copy
  from the tag. `v0.5.1` contains both plus the version metadata; no Go, npm
  launcher or Python launcher behaviour changed. `v0.5.0` stays published and
  immutable — it is not moved, retagged or deleted.
- **0.5.0 stays current (2026-11-10; superseded).** The earlier decision in
  `68c5149` kept `0.5.0` because the binaries and packages were byte-identical
  and the templates only lived in the repository. That reasoning missed the tag
  itself as a distribution surface: the examples on `v0.5.0` fail validation,
  so a patch release is allowed. Superseded by the `0.5.1` entry above.

## Re-run a failed npm publish

The GitHub release is already published; only the npm packages are missing.

```bash
gh workflow run npm-publish.yml -f tag=vX.Y.Z
gh run list --workflow npm-publish.yml --limit 1
```

- `workflow_dispatch` runs the workflow from the default branch and publishes
  the tag passed in `-f tag=`.
- The tag must match `v<major>.<minor>.<patch>` with an optional `-prerelease`
  suffix; anything else fails the first step.
- Versions already on npm are skipped, so re-running after a partial publish
  completes only the missing packages.
- Fix the cause first (missing trusted publisher, missing `id-token: write`, an
  npm older than 11.5.1), then re-run. See the troubleshooting table below.

## Local fallback

The workflows are the release path. The scripts in `scripts/` exist for a GitHub
outage, for cutting the GitHub release from a workstation, and for the one-time
trust bootstrap.

| Script | What it does | Notes |
|---|---|---|
| `scripts/release.ps1 -Version X.Y.Z` | Cross-compiles the six targets, writes `checksums.txt`, creates or reuses the GitHub release, uploads missing assets, builds npm packages, runs `npm/publish.sh` | Windows PowerShell 5.1+; needs `go`, `git`, `node`, authenticated `gh`, and `bash` for the npm step; `-SkipNpm` stops after the GitHub release |
| `scripts/release.sh --version X.Y.Z` | The same flow on macOS and Linux | `--skip-npm`, `--notes`, `--repo` |
| `scripts/npm-publish-and-trust.ps1 [-Version X.Y.Z] [-Otp 123456] [-SkipPublish]` | Downloads release assets if `dist/checksums.txt` is missing, builds the packages, publishes the six platform packages and then the launcher, then configures Trusted Publishing for all seven | Defaults to the latest release tag; needs `npm`, `node` and `gh`; skips versions already on npm; `-SkipPublish` only configures trust |
| `scripts/npm-trust-interactive.ps1` | Configures Trusted Publishing for the remaining packages with one browser approval each | Run it in a real PowerShell window; writes a transcript to `%TEMP%\vigil-npm-trust.log` |

`npm/publish.sh` always passes `--provenance`. npm generates provenance only on
GitHub Actions and GitLab CI, so a publish started from a workstation fails with
`EUSAGE Automatic provenance generation not supported for provider: ...`. Use
`-SkipNpm` / `--skip-npm` locally and let `npm-publish.yml` publish, or use
`scripts/npm-publish-and-trust.ps1`, which publishes with your own npm session
and no provenance.

The scripts are idempotent: an existing release is reused, present assets are
skipped, and versions already on npm are skipped.

## Release assets and repository size

Release assets are published to the GitHub release and never committed. The
workflows download them into `release-assets/`, and `/dist-*/`, `/dist/`,
`/npm-out/` and `*.exe` are gitignored. One `dist-0.1.4/` directory was committed
by mistake in `1c57bae` and removed in `601dfc3`; it still accounts for about
17.5 MiB of `.git`. That history is deliberately not rewritten, because
`v0.2.0` and later tags are immutable Go module versions. Measurements, the
reasoning and the procedure if a rewrite is ever required are in
[history.md](history.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `EOTP` / "This operation requires a one-time password" | The npm account has 2FA enabled | Pass `-Otp 123456` to the PowerShell script (or `--otp=123456` to npm), or run `scripts/npm-trust-interactive.ps1` and approve each browser prompt. `npm trust list` always needs 2FA |
| `E409` from `npm trust github` | The trusted publisher already exists | Nothing to do; confirm with `npm trust list <pkg>` |
| `E404` / "package not found" during the OIDC exchange | The package has no trusted publisher for this repository and workflow, or the new binding has not propagated yet | Run the bootstrap for that package, then re-run `npm-publish.yml`. `npm trust` also needs the package to exist, so a new package name has to be published once first |
| `403` "You cannot publish over the previously published versions" | That version is already on npm | `npm/publish.sh` skips it; bump the version and release again |
| Publish step skipped: "no OIDC token (id-token: write) and no NODE_AUTH_TOKEN" | The publishing job has no `id-token: write`, or it ran outside GitHub Actions | Keep `permissions: id-token: write` on the publish job; do not set `registry-url` in `actions/setup-node`, it writes a placeholder token that replaces OIDC |
| "npm <version> is too old for Trusted Publishing (needs >= 11.5.1)" | Old npm in the job | The workflow pins Node 24; keep it, or upgrade npm in the job |
| `EUSAGE Automatic provenance generation not supported for provider: ...` | `npm publish --provenance` outside GitHub Actions or GitLab CI | Publish from `npm-publish.yml`, not from a workstation |
| GitHub release is green, npm packages are missing | The npm job is `continue-on-error` by design | Read the warning on the run, fix the cause, re-run `npm-publish.yml` |
| `npm i -g lv24-vigil@X` installs the launcher but `vigil` fails to start | The matching platform package is missing or was published later | Check `npm view @lv24/vigil-<os>-<cpu> version`; re-run the publish for that tag |

## Security

- **No long-lived npm token in CI.** No `NPM_TOKEN` secret is configured in the
  repository (`gh secret list` returns nothing); the publish job exchanges its
  OIDC token for a short-lived credential. `release.yml` still accepts an
  `NPM_TOKEN` secret as a manual fallback, and `npm/publish.sh` prefers it when
  set — leave it unset.
- **Trust is bound to the repository and the workflow file.** A trusted
  publisher names `LevapVeeskela/lv24-vigil` and
  `.github/workflows/npm-publish.yml`; a fork, another repository or another
  workflow cannot publish these packages.
- **Minimal token scope.** Only the publish job requests `id-token: write`
  (`release.yml` grants it to the reusable workflow); `npm-publish.yml` runs with
  `contents: read` and `id-token: write` and nothing else.
- **GitHub-hosted runners only.** The publish job runs on `ubuntu-latest`; the
  provenance attestation records a `github-hosted` builder. Do not move
  publishing to a self-hosted runner.
- **Artifacts are verified before packaging.** `npm/build.mjs` checks every
  binary against `checksums.txt` from the GitHub release and writes nothing if
  one hash differs.
- **Provenance is public.** Each published package carries a SLSA provenance
  attestation, so a user can check which workflow and commit produced it.

## Current state

`0.1.4` (2026-11-10) was the first release published end-to-end through the OIDC
path. All seven npm packages and PyPI are live at `0.6.0`, and `latest` points
at it. `v0.6.0` adds 35 deterministic rules (198 total) and keeps the action's
npm CLI hardcoded to its release; `v0.5.4` is the previous action-pinning
release; `v0.5.3` contains the Marketplace listing and the superseded auto-ref
attempt. `v0.5.2` contains the corrected CI templates and the post-0.5.1 docs.
`v0.5.0` remains published and immutable, but its examples use
`inputs.fail-on` and an unguarded GitLab pre-check, so do not copy them.

The composite action is listed on the [GitHub Marketplace](https://github.com/marketplace/actions/vigil-security-scan)
as **Vigil security scan** (Security + Code quality).

**Do not pin `0.5.0`.** Use `0.6.0` or newer, or `@latest`. The `v0.5.0` tag is
immutable and still resolves, so pinning it silently keeps the stale templates;
its GitHub release body carries the warning. The npm package version is marked
with a deprecation notice (a metadata change, not a republish) once the npm 2FA
OTP is completed. Check both markers with:

```bash
npm view lv24-vigil@0.5.0 deprecated
gh release view v0.5.0 --json body --jq .body
```

```bash
npm view lv24-vigil version
npm view @lv24/vigil-linux-x64 version
```

Related: [install.md](install.md) for the user-facing install paths,
[ci.md](ci.md) for consuming the release in a workflow,
[troubleshooting.md](troubleshooting.md) for scan and provider problems.

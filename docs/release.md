# Release and npm publishing

Vigil ships from git tags. A tag produces the GitHub release with six static
binaries, Linux packages, a self-SBOM, a keyless cosign signature and a build
provenance attestation, and a second job publishes seven npm packages. Since
`0.1.4` the npm half runs on npm Trusted Publishing (OIDC): no npm token is
stored in the repository or in GitHub secrets, and npm records a provenance
attestation for each published package.

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
                         ->  6 Linux packages (deb/rpm/apk x amd64/arm64)
                         ->  checksums.txt.sigstore.json (cosign, keyless)
   vigil sbom .          ->  vigil-sbom-X.Y.Z.cdx.json
   asset check           ->  fail unless 6 binaries, 6 packages and checksums.txt exist
   cosign sign-blob      ->  release-assets/checksums.txt.sigstore.json
   attest-build-provenance ->  SLSA provenance for release-assets/*
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
| Linux packages | `release.yml` | `vigil-<version>-linux-<arch>.deb`, `.rpm` and `.apk` for amd64 and arm64, with `vigil` in `/usr/bin` |
| SBOM | `release.yml` | `vigil-sbom-<version>.cdx.json`, a CycloneDX 1.6 document generated from the tagged tree by the freshly built source |
| Signature | `release.yml` | `checksums.txt.sigstore.json`, a keyless cosign bundle over `checksums.txt` |
| Provenance | `release.yml` | `actions/attest-build-provenance` records SLSA provenance for every file in `release-assets/` |
| Asset check | `release.yml` | The run fails unless exactly six binaries, six Linux packages and `checksums.txt` are present |
| GitHub release | `release.yml` | Creates `vX.Y.Z` with generated notes; a tag containing `-` becomes a prerelease; on a re-run only missing assets are uploaded |
| Package build | `npm-publish.yml` | `npm/build.mjs` verifies each binary against `checksums.txt` and writes nothing unless all six match |
| npm publish | `npm-publish.yml` | Platform packages first, then the launcher; versions already on npm are skipped |

npm is a separate job on purpose. It `needs` the GitHub release, so the binaries
exist before packaging starts, and the publish step is `continue-on-error`, so a
failed npm publish leaves the release published and green. The job ends with a
warning that names the missing setup; re-run it after fixing the cause.

Two more workflows run around a tag. [`container.yml`](../.github/workflows/container.yml)
builds the multi-arch image (`linux/amd64`, `linux/arm64`) from the repository
`Dockerfile` and pushes it to `ghcr.io/levapveeskela/lv24-vigil` with BuildKit
provenance and SBOM attestations; it triggers on the same `v*` push and can be
dispatched for an existing tag. [`scorecard.yml`](../.github/workflows/scorecard.yml)
re-runs OpenSSF Scorecard on `main`, weekly and on branch-protection changes, and
uploads the SARIF result to code scanning.

`npm-publish.yml` is both a reusable workflow (called by `release.yml`) and a
`workflow_dispatch` workflow, so it can publish an existing tag on demand.
`release.yml` triggers on any `v*` tag; `npm-publish.yml` accepts only
`v<major>.<minor>.<patch>` with an optional `-prerelease` suffix. `ci.yml` runs a
GoReleaser snapshot and an npm package dry run on pull requests, so asset naming
and package layout mistakes fail before a tag is cut.

## Release assets

Every release carries these files:

| Asset | Purpose |
|---|---|
| `vigil_<version>_<goos>_<goarch>[.exe]` | Six static binaries: windows, linux and darwin on amd64 and arm64 |
| `vigil-<version>-linux-amd64.deb` / `...-arm64.deb` | Debian/Ubuntu package |
| `vigil-<version>-linux-amd64.rpm` / `...-arm64.rpm` | Fedora/RHEL/openSUSE package |
| `vigil-<version>-linux-amd64.apk` / `...-arm64.apk` | Alpine package |
| `vigil-sbom-<version>.cdx.json` | CycloneDX 1.6 self-SBOM of the tagged source; its digest is in the provenance attestation |
| `checksums.txt` | SHA-256 of the six binaries and the six Linux packages |
| `checksums.txt.sigstore.json` | Keyless cosign bundle over `checksums.txt` |
| `provenance.intoto.jsonl` | SLSA provenance bundle, attached since 0.10.2 (0.10.1 and earlier have 15 assets) |

The same tag also publishes `ghcr.io/levapveeskela/lv24-vigil` for
`linux/amd64` and `linux/arm64` (tags `X.Y.Z`, `X.Y`, `latest`, `sha-<commit>`),
with BuildKit provenance and SPDX SBOM attestations; see
[container.md](container.md).

The Linux packages are built by GoReleaser (`nfpms` in
[`deploy/goreleaser.yaml`](../deploy/goreleaser.yaml)) from the same `-ldflags`
as the binaries, so `vigil version` inside a package reports the tag. Each one
installs `LICENSE` as `/usr/share/doc/vigil/LICENSE` and the binary as
`/usr/bin/vigil_<version>_linux_<arch>`, with a `/usr/bin/vigil` symlink next to
it; deb and rpm also declare `Provides: vigil`. Every package is Apache-2.0.
Package files use a hyphenated name so they are never mistaken for one of the
six `vigil_*` binaries.

```bash
sudo apt install ./vigil-X.Y.Z-linux-amd64.deb                # Debian, Ubuntu
sudo dnf install --nogpgcheck ./vigil-X.Y.Z-linux-amd64.rpm   # Fedora, RHEL, openSUSE
sudo apk add --allow-untrusted ./vigil-X.Y.Z-linux-amd64.apk  # Alpine
vigil version
```

The packages carry no distribution key of their own: there is no GPG signature
on the rpm and no Alpine signing key, which is why `dnf` needs `--nogpgcheck`
and `apk` needs `--allow-untrusted`. What is signed is `checksums.txt`, which
lists the six binaries and the six packages, and the provenance attestation
covers the SBOM and the bundle as well.

The SBOM is generated on the runner from the tagged tree with
`go run ./cmd/vigil sbom . --format cyclonedx`. `vigil sbom` is offline: it
inventories `go.mod`, lockfiles and declared manifests and needs no network, so
the command works on a runner and on a detached checkout.

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

`v0.10.2` ships the asset list of `v0.10.1` plus `provenance.intoto.jsonl`: six
static binaries, six Linux packages (deb/rpm/apk × amd64/arm64),
`vigil-sbom-0.10.2.cdx.json`, `checksums.txt` and its cosign bundle, the
provenance bundle, and the GHCR image for both architectures. Download what you need from the release page;
the commands below verify it without trusting the download.

Signatures are keyless: there is no long-lived signing key in the repository or
in GitHub secrets. cosign exchanges the workflow's OIDC token for a short-lived
certificate, records the signature in the Rekor transparency log, and the
certificate identity names this repository, `release.yml` and the tag. Both
commands below need network access (Rekor, the OIDC issuer, GitHub).

```bash
gh release download vX.Y.Z --pattern checksums.txt --pattern checksums.txt.sigstore.json
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/LevapVeeskela/lv24-vigil/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

A passing run prints `Verified OK`. Then check what you downloaded against the
signed file (`--ignore-missing` skips assets you did not fetch):

```bash
sha256sum -c checksums.txt --ignore-missing
```

Provenance is a separate, GitHub-native attestation for every file in
`release-assets/` (binaries, packages, SBOM, checksums and bundle):

```bash
gh attestation verify vigil-X.Y.Z-linux-amd64.deb --repo LevapVeeskela/lv24-vigil
gh attestation verify vigil-sbom-X.Y.Z.cdx.json --repo LevapVeeskela/lv24-vigil
```

The attestation names the workflow, the commit and the digest the runner
produced. `gh attestation verify` fails if the file was rebuilt or altered
outside that run.

The container image carries BuildKit provenance and an SBOM instead of a cosign
signature. Compare its digest with the `container` run summary, or inspect the
attestations directly:

```bash
docker buildx imagetools inspect ghcr.io/levapveeskela/lv24-vigil:0.10.2 \
  --format '{{json .Manifest}}' | jq -r .digest
```

Installed CLI:

```bash
npm view lv24-vigil version          # 0.10.2
npm view lv24-vigil dist-tags        # { latest: '0.10.2' }
npm i -g lv24-vigil@0.10.2            # or @latest
vigil version                        # vigil 0.10.2 (<commit>, <date>, go<version>)
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
gh run list --workflow container.yml --limit 3
gh run view <run-id> --log
```

The publish step prints `npm: publishing with Trusted Publishing (OIDC), npm
<version>`, then `+ <package>@<version>` for each package. A skipped version
prints `<package>@<version> already on npm; skipping`.

Provenance:

```bash
npm view lv24-vigil dist.attestations
```

For `0.10.2` this returns a `https://slsa.dev/provenance/v1` attestation built
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
gh release view vX.Y.Z --json assets --jq '.assets[].name'   # binaries, packages, SBOM, checksums, bundle
tar -tzf lv24-vigil-X.Y.Z.tgz                                 # npm: bin/, README, LICENSE
curl -s https://pypi.org/pypi/lv24-vigil/X.Y.Z/json | jq '.urls[].filename'
vigil version                                                 # reports the tag commit
```

### Decision log

- **0.10.2 is a security patch release; upgrade from 0.10.1 (2026-11-17).** No rule or tool changes (**263** rules, ten families, 14 MCP tools). Two things made the patch release necessary. First, an adversarial review of 0.10.1 reproduced defects in shipped code: a project `output.path` reaching `.git` through a Windows 8.3 alias, raw secrets quoted in the snippets of other findings, a `--max-findings` cap applied before the sort that could drop a critical OSV advisory, understated OSV severities, and lockfile git URLs sent to the OSV API and the SBOM; the full list is in the CHANGELOG. Second, the 0.10.1 binaries were built with Go 1.27.0, for which `govulncheck` reports reachable standard-library vulnerabilities; `go.mod` now carries `toolchain go1.27.4` and CI runs `govulncheck` in the required `test` job. The toolchain line was chosen over a higher `go` directive so that building from source with an older Go 1.27 keeps working. 0.10.2 is also the first release with 16 assets (`provenance.intoto.jsonl`) and the first PyPI publish through the hash-pinned build tools. Finding IDs and fingerprints are unchanged.
- **0.10.1 validates the cosign-installer v4 path and ships the post-0.10.0 docs (2026-11-16).** No code or rule changes (**263** rules, ten families, 14 MCP tools): the release workflow installs cosign through `sigstore/cosign-installer` v4 with `cosign-release: v2.4.1`, and 0.10.1 confirms that the keyless `checksums.txt.sigstore.json` bundle still verifies with `cosign verify-blob --bundle`. The documentation catches up with the distribution work done after the 0.10.0 tag: per-channel status in `docs/distribution.md`, the AUR package renamed to `vigil-security-bin` (`vigil-bin` is occupied), and refreshed install, CI, PyPI, container, pre-commit and release pages. Release assets are unchanged from 0.10.0, and the action default moves to `0.10.1`.
- **0.10.0 adds baseline v2, hardening platform presets, config commands and JUnit (2026-11-16).** No rule changes (**263** rules, ten families, 14 MCP tools): the baseline file moves to version 2 with `ticket`, `expires`, `path` and `prune` (an expired entry stops suppressing), and SARIF is active-only so accepted risks do not open code-scanning alerts; `vigil hardening --platform` and the `platform` MCP argument narrow the VGL-ARE review to android, ios, electron, node, flutter, web or other; `vigil config validate|show` checks and explains the effective configuration without opening the store or a model; and `vigil report --format junit` adds a report-only JUnit document. Release assets are unchanged from 0.9.3, and the action default moves to `0.10.0`.
- **0.9.3 adds the official MCP Registry listing and AUR packaging (2026-11-15).** No code or rule changes (**263** rules, ten families, 14 MCP tools): the same engine as 0.9.2, with distribution-only additions. Vigil is now listed in the official MCP Registry as `io.github.LevapVeeskela/vigil` (`mcpName` plus `server.json`), so registry-aware clients can resolve the stdio server; the AUR `vigil-security-bin` packaging is prepared for the published release (publication awaits AUR registration); and `docs/mcp-registry.md`, `docs/aur.md` and `docs/mcp-directories.md` document registry publishing, AUR maintenance and the directory/CII submissions. Release assets are unchanged, and the action default moves to `0.9.3`.
- **0.9.2 fixes the release pipeline (2026-11-15).** Move cosign installation after the GoReleaser build so goreleaser-action verifies its own download with the bundled cosign; 0.9.1 failed before publishing. No code or rule changes.
- **0.9.1 makes the release installable everywhere and attributable
  (2026-11-15).** A patch release with no rule changes (**263** rules, ten
  families, 14 MCP tools): the same engine as 0.9.0, different delivery.
  Added native Linux packages (deb/rpm/apk for amd64 and arm64, built by
  GoReleaser `nfpms` from the same `-ldflags`), a CycloneDX 1.6 self-SBOM asset,
  a keyless cosign bundle over `checksums.txt`, SLSA build provenance for
  `release-assets/*`, a `pre-commit` hook definition, an OpenSSF Scorecard
  workflow and a multi-arch (`linux/amd64`, `linux/arm64`) distroless GHCR image
  with BuildKit provenance and SBOM. The pipeline also gained an asset check
  (six binaries, six packages, `checksums.txt`) so a partial tag fails before
  publishing, and the action default moves to `0.9.1`.
- **0.9.0 adds MCP audit, SBOM and inline suppression (2026-11-15).** Ten
  `VGL-MCP` rules and the offline `vigil mcp-audit` / `vigil_mcp_audit` tool
  audit MCP configs without starting a server. `vigil sbom` emits CycloneDX 1.6
  or SPDX 2.3, with config excludes limited to directories so lockfiles stay in
  the inventory. `vigil:ignore` suppresses a finding with an optional reason and
  expiry. Fifteen more deterministic rules on top of the 27-rule research pass
  (42 new since 0.8.0; 263 total); OSV withdrawn/MAL handling,
  Python `requirements*.txt`/`pyproject.toml` and staged pre-commit scanning are
  fixed.
- **0.8.0 fixes dependency severities and locks the OSV endpoint
  (2026-11-11).** OSV `querybatch` returns advisory IDs only, so every
  advisory in 0.7.x was `medium` and `--fail-on high` never fired on a
  dependency; 0.8.0 fetches each full record and follows result pages.
  Breaking for project files: `scan.osv_base_url` is rejected in a committed
  `.vigil.yaml` (user config or `VIGIL_OSV_BASE_URL` only), hence the minor
  bump. Also: OSV findings honour the baseline, `vigil doctor` explains config
  errors, `vigil hardening --rules` is limited to `VGL-ARE`, anti-RE false
  positives/negatives fixed and `openWorldHint` corrected on network-capable
  tools. No rule IDs changed; still 221 rules.
- **0.7.1 fixes two anti-RE false positives (2026-11-11).** `VGL-ARE-006`
  skips debug-variant network security configs; `VGL-ARE-053` no longer
  flags `COPY_PHASE_STRIP = NO` and reports only
  `DEBUG_INFORMATION_FORMAT = dwarf` and `STRIP_INSTALLED_PRODUCT = NO`.
  No rule IDs changed.
- **0.7.0 adds anti-RE hardening and dependency advisories (2026-11-11).**
  New `VGL-ARE` family (23 rules), `vigil_hardening` and `vigil_dependencies`
  MCP tools and CLI commands, wider OSV inventory, and the prompts
  `anti_re_hardening` / `dependency_audit`. Total: **221** rules. The action
  default moves to `0.7.0`.
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
skipped, and versions already on npm are skipped. They produce the six binaries
and `checksums.txt` only: the Linux packages, the SBOM, the cosign bundle and
the provenance attestation come from `release.yml`.

## Asset storage and repository size

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
- **Release assets are signed, not just hashed.** `checksums.txt` is signed with
  cosign in keyless mode: the runner exchanges its OIDC token for a short-lived
  certificate bound to `release.yml` and the tag, so there is no signing key to
  leak or rotate. The `checksums.txt.sigstore.json` bundle is uploaded next to
  the checksums and covers every package and binary.
- **Provenance is recorded for every asset.** `actions/attest-build-provenance`
  writes a SLSA provenance attestation for `release-assets/*`; `gh attestation
  verify <file> --repo LevapVeeskela/lv24-vigil` checks the digest against that
  run.
- **Minimal token scope.** `id-token: write` is granted to the publish job and
  to the release job that signs and attests; `release.yml` also passes it to the
  reusable npm workflow. `npm-publish.yml` runs with `contents: read` and
  `id-token: write` and nothing else; the release job adds `contents: write`
  (release upload) and `attestations: write` (provenance).
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
path. All seven npm packages and PyPI are live at `0.10.2`, and `latest` points
at it. `v0.10.2` is a **security patch release** (263 rules in ten families, 14
MCP tools): it ships the fixes from the adversarial review of 0.10.1 and is
built with Go 1.27.4 instead of 1.27.0. **Upgrade from 0.10.1.** Release assets
gain `provenance.intoto.jsonl` (16 files); verify them with
`cosign verify-blob` and `gh attestation verify`, images by digest.

`v0.10.1` is a patch release with **no code or rule changes** (263 rules
in ten families, 14 MCP tools): it validates cosign signing through
`sigstore/cosign-installer` v4 with cosign v2.4.1, and ships the post-0.10.0
distribution docs (per-channel status, AUR `vigil-security-bin`). Release assets
are unchanged from 0.10.0; verify them with `cosign verify-blob` and
`gh attestation verify`, images by digest.

`v0.10.0` is a feature release with **no rule changes** (263 rules in ten
families, 14 MCP tools): baseline format v2 (ticket, expiry, path and prune,
plus SARIF suppressions), hardening platform presets (`--platform` and the MCP
`platform` argument), `vigil config validate|show`, and report-only JUnit
(`vigil report --format junit`). Release assets are unchanged from 0.9.3; verify
them with `cosign verify-blob` and `gh attestation verify`, images by digest.

`v0.9.3` is a distribution-metadata release with **no code or rule
changes** (263 rules in ten families, 14 MCP tools): it adds the official MCP
Registry listing (`mcpName` in the npm package plus `server.json`), the AUR
`vigil-security-bin` package, and registry/AUR/directory documentation
(`docs/mcp-registry.md`, `docs/aur.md`, `docs/mcp-directories.md`). Release
assets are unchanged from 0.9.2; verify them with `cosign verify-blob` and
`gh attestation verify`, images by digest.

`v0.9.2` is a packaging and supply-chain release and supersedes the 0.9.1 tag, whose release workflow failed before publishing: **no rule or tool
changes** (263 rules in ten families, 14 MCP tools). It adds native deb/rpm/apk
packages for amd64 and arm64, a CycloneDX 1.6 SBOM asset, keyless cosign signing
of `checksums.txt`, SLSA build provenance for every release asset, a `pre-commit`
hook definition, an OpenSSF Scorecard workflow, and the multi-arch GHCR image
(`ghcr.io/levapveeskela/lv24-vigil`, distroless, nonroot, BuildKit provenance and
SBOM, not cosign-signed).
`v0.9.0` adds MCP configuration auditing (`vigil mcp-audit` /
`vigil_mcp_audit`), SBOM export (CycloneDX 1.6 / SPDX 2.3), inline
`vigil:ignore` suppression and 42 new rules since 0.8.0 (**263** total, 10
families).
`v0.8.0` made dependency severities real (0.7.x reported every OSV
advisory as `medium`), follows OSV result pages, rejects `scan.osv_base_url` in
project files and lets `vigil doctor` explain config errors. **Upgrade from
0.7.x** if you use `vigil dependencies` or `scan.osv`. `v0.7.1` fixes two
anti-RE false positives: debug-variant network security configs and the
modern Xcode `COPY_PHASE_STRIP = NO` default.
`v0.7.0` added 23 anti-RE hardening rules (221 total), the
`vigil_hardening` and `vigil_dependencies` tools and wider OSV inventory; the
action CLI defaults to its release. `v0.6.0` added 35 deterministic rules;
`v0.5.4` is the previous action-pinning release; `v0.5.3` contains the Marketplace listing and the superseded auto-ref
attempt. `v0.5.2` contains the corrected CI templates and the post-0.5.1 docs.
`v0.5.0` remains published and immutable, but its examples use
`inputs.fail-on` and an unguarded GitLab pre-check, so do not copy them.

The composite action is listed on the [GitHub Marketplace](https://github.com/marketplace/actions/vigil-security-scan)
as **Vigil security scan** (Security + Code quality).

**Do not pin `0.5.0`.** Use `0.10.2` or newer, or `@latest`. The `v0.5.0` tag is
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

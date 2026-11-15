# CII Best Practices badge

Preparation for the [OpenSSF CII Best Practices](https://bestpractices.coreinfrastructure.org)
badge. The project is **not registered yet**; registration needs a GitHub
account and is a maintainer action. This page holds the answers to paste into
the questionnaire and lists the gaps to close first.

## Badge placeholder

Replace `PROJECT_ID` with the numeric project id assigned after registration:

```markdown
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/PROJECT_ID/badge)](https://bestpractices.coreinfrastructure.org/projects/PROJECT_ID)
```

Registration: <https://bestpractices.coreinfrastructure.org/en/projects/new>
(sign in with GitHub). The `bestpractices.dev` hostname redirects to the same
service.

## Project description

Use this as the short project description in the questionnaire:

> Vigil is a local-first security auditor for source repositories. It runs 263
> deterministic rules across secrets, injection, crypto, auth, web, config/IaC,
> CI, dependencies, MCP configuration and anti-RE hardening, with optional LLM
> triage using a model the user configures. It is a CLI and a stdio MCP server
> with 14 tools, 4 resources and 5 prompts. Deterministic scans are offline and
> telemetry-free, fixes are proposed as diffs and never committed, and releases
> ship signed checksums, SBOMs and build provenance.

Longer text, if the form allows it: reuse the 500-character block in
[mcp-directories.md](mcp-directories.md) and append the packaging list (npm,
PyPI launcher, GitHub binaries, deb/rpm/apk, Homebrew, Scoop, GHCR).

## Answers by criterion

| Criterion | Answer | Evidence |
|---|---|---|
| Website | https://github.com/LevapVeeskela/lv24-vigil | repository |
| Source control | Git, public GitHub repository | https://github.com/LevapVeeskela/lv24-vigil |
| Bug tracker | GitHub Issues | https://github.com/LevapVeeskela/lv24-vigil/issues |
| Discussion | GitHub Issues and pull requests; no separate forum or chat | repository |
| License | Apache-2.0 | [`LICENSE`](../LICENSE) |
| Documentation | README (English and Russian), `docs/`, compact machine index | [`README.md`](../README.md), [`docs/`](.), [`llms.txt`](../llms.txt) |
| Installation docs | npm, PyPI, release binaries, packages, container, AUR (pending) | [`docs/install.md`](install.md), [`docs/container.md`](container.md), [`docs/aur.md`](aur.md) |
| Build system | Go 1.27+, `go build ./cmd/vigil`, Makefile targets | [`Makefile`](../Makefile), [`go.mod`](../go.mod) |
| Tests | `go test ./...`; 6,730 test, fuzz and benchmark functions in 2,838 `*_test.go` files; CI runs the suite on every push and pull request | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| New features have tests | Project policy: new rules, validators and fixes ship with tests | [`CONTRIBUTING.md`](../CONTRIBUTING.md) |
| Security policy | Documented scope, out-of-scope list, response expectations, safe harbour | [`SECURITY.md`](../SECURITY.md) |
| Vulnerability reporting | GitHub private vulnerability reporting; no public issue for an unfixed report; coordinated disclosure | https://github.com/LevapVeeskela/lv24-vigil/security/advisories/new |
| HTTPS | All project, documentation, package and API endpoints use HTTPS | repository links |
| English | Documentation, CLI output and reports are in English | repository |
| Signed releases | Keyless cosign signature over `checksums.txt`; GitHub build provenance attestations for every release asset; BuildKit provenance and SBOM for the container image | [`docs/release.md`](release.md#verify-a-release) |
| SBOM | CycloneDX 1.6 release asset (SPDX 2.3 also supported); generated offline by `vigil sbom` | `vigil-sbom-0.9.3.cdx.json` |
| Provenance | GitHub-native attestations name the workflow, commit and digest; `gh attestation verify` fails on a rebuilt or altered file | [`docs/release.md`](release.md) |

## Release integrity answers in detail

**Signed releases.** `checksums.txt` lists the six binaries and the six Linux
packages. It is signed with cosign in keyless mode; the bundle is
`checksums.txt.sigstore.json` and the certificate identity is
`https://github.com/LevapVeeskela/lv24-vigil/.github/workflows/release.yml@refs/tags/vX.Y.Z`.
Each file in the release also has a GitHub build provenance attestation.

```bash
gh release download v0.9.3 --pattern checksums.txt --pattern checksums.txt.sigstore.json
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/LevapVeeskela/lv24-vigil/.github/workflows/release.yml@refs/tags/v0.9.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

gh attestation verify vigil_0.9.3_linux_amd64 --repo LevapVeeskela/lv24-vigil
```

**SBOM.** Generate and inspect it locally:

```bash
vigil sbom . --format cyclonedx --output vigil-sbom-0.9.3.cdx.json
vigil sbom . --format spdx --output vigil-sbom-0.9.3.spdx.json
```

The release publishes `vigil-sbom-0.9.3.cdx.json`. It inventories declared
dependencies; it does not resolve version ranges or prove the absence of
vulnerabilities.

**Vulnerability reporting.** Reports go through GitHub private advisories. The
policy covers the CLI, MCP server, scanner, rule engine, report renderers, path
and baseline handling, prompt construction, provider handling, packaging and the
GitHub Action. Findings in scanned third-party code, provider outages and
missing detections without a concrete rule defect are out of scope. Handling is
best-effort with no paid SLA; confirmed issues get a coordinated disclosure
date and credit unless the reporter asks to stay anonymous.

**Security design.** Deterministic scans are local and make no network calls;
LLM context goes only to the configured endpoint; scans are read-only by default;
only `vigil_fix` with `apply=true` writes source files and it never commits.
See [`docs/security-model.md`](security-model.md).

## Gaps to close before applying

These are honest gaps; fix them before or shortly after registration rather
than overstating an answer.

| Gap | Action |
|---|---|
| No `CODE_OF_CONDUCT.md` | Add a code of conduct (for example Contributor Covenant) and link it from `CONTRIBUTING.md` |
| `SECURITY.md` supported-versions table still says `0.1.x` | Update it to the current `0.9.x` line and state the support window |
| No published coverage number or threshold | Add coverage reporting to CI if the questionnaire asks for it; do not claim a percentage that is not measured |
| AUR package not published | Complete the account/SSH steps in [aur.md](aur.md); this is not a CII criterion |
| No CII project yet | Register, paste the answers, save, and copy the assigned project id |
| Badge not in `README.md` | Add the badge after registration; this is a separate edit to the README |

## Registration flow

1. Sign in at <https://bestpractices.coreinfrastructure.org/en/projects/new>
   with GitHub and create the project for
   `https://github.com/LevapVeeskela/lv24-vigil`.
2. Answer the passing-level criteria using the table above. Save after each
   section; the site keeps a per-criterion rationale and evidence URL.
3. Copy the numeric id from the project URL and replace `PROJECT_ID` in the
   badge snippet.
4. Add the badge to the README (outside the scope of this document).
5. Re-check the answers after each release: version numbers, test counts and
   release assets change, and stale answers weaken the badge.

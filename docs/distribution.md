# Distribution status

Where Vigil `0.11.0` is actually published, what each channel installs, and
which channels are still gated. This page records the live state, not the
intended roadmap: a channel is "available" only when the published artifact was
resolved on the date below.

**Last verified: 2026-11-19.** Current release: **0.11.0**. Verification
commands are in [Re-verify](#re-verify).

## Channels

| Channel | Version | Status | Install | Verify |
| --- | --- | --- | --- | --- |
| [GitHub Release](https://github.com/LevapVeeskela/lv24-vigil/releases/tag/v0.11.0) | `v0.11.0` | **Available** — latest, 16 assets | Binaries, deb/rpm/apk and installers: [install.md](install.md) | `gh attestation verify <asset> --repo LevapVeeskela/lv24-vigil` |
| [npm](https://www.npmjs.com/package/lv24-vigil) | `0.11.0` | **Available** — `latest`, 7/7 packages (launcher + 6 platform) | `npm i -g lv24-vigil@0.11.0` | `npm view lv24-vigil version` |
| [PyPI](https://pypi.org/project/lv24-vigil/) | `0.11.0` | **Available** — thin launcher, delegates to npm (Node.js 18+) | `pip install lv24-vigil==0.11.0` | `pip show lv24-vigil` |
| [GHCR](https://github.com/LevapVeeskela/lv24-vigil/pkgs/container/lv24-vigil) | `0.11.0` | **Available** — multi-arch `linux/amd64`, `linux/arm64`; tags `0.11.0`, `0.11`, `latest`, `sha-5cf9844` | `docker pull ghcr.io/levapveeskela/lv24-vigil:0.11.0` | `docker buildx imagetools inspect ghcr.io/levapveeskela/lv24-vigil:0.11.0` |
| [Go proxy](https://pkg.go.dev/github.com/levapveeskela/lv24-vigil) | `v0.11.0` | **Available** — module `github.com/levapveeskela/lv24-vigil` | `go install github.com/levapveeskela/lv24-vigil/cmd/vigil@v0.11.0` | `go list -m github.com/levapveeskela/lv24-vigil@v0.11.0` |
| [GitHub Marketplace](https://github.com/marketplace/actions/vigil-security-scan) | `v0.11.0` | **Available** — action listing live, `v0.11.0` tag present | `uses: LevapVeeskela/lv24-vigil@v0.11.0` | Listing page shows the tag; add `version: 0.11.0` when the CLI must match |
| [Scoop](https://github.com/LevapVeeskela/scoop-bucket) | `0.11.0` | **Available** — manifest tracks releases; hashes from the signed `checksums.txt` | `scoop bucket add lv24 https://github.com/LevapVeeskela/scoop-bucket`<br>`scoop install lv24/vigil` | `scoop info lv24/vigil` then `vigil version` |
| [Homebrew](https://github.com/LevapVeeskela/homebrew-tap) | `0.11.0` | **Available** — builds from the tagged source tarball | `brew install LevapVeeskela/tap/vigil` | `brew info LevapVeeskela/tap/vigil` |
| [GitLab mirror](https://gitlab.com/lv24-company/lv24-vigil) | `main`, `v0.11.0` | **Available** — private mirror, `main` and `v0.11.0` present; not an install channel | `git clone https://gitlab.com/lv24-company/lv24-vigil.git` | `git ls-remote --tags https://gitlab.com/lv24-company/lv24-vigil.git` |
| [WinGet](https://github.com/microsoft/winget-pkgs/pull/480713) | `0.10.1` | **Pending** — PR 480713 (0.10.1) open, awaiting moderator; not installable. 0.11.0 is not submitted | — | `gh pr checks 480713 -R microsoft/winget-pkgs` |
| [Official MCP Registry](https://registry.modelcontextprotocol.io) | `0.10.1` | **Behind** — 0.10.1 is active and latest; 0.11.0 is in `server.json` and needs the owner's `mcp-publisher publish` | `npx -y lv24-vigil@0.11.0 mcp` | `curl "https://registry.modelcontextprotocol.io/v0/servers?search=io.github.LevapVeeskela/vigil"` |
| [AUR](aur.md) | `0.11.0` PKGBUILD, `vigil-security-bin` | **Not published** — registration paused (HTTP 503); renamed from the occupied `vigil-bin` to the free `vigil-security-bin` | — **never run `yay -S vigil-bin`** (unrelated package); `yay -S vigil-security-bin` only after it appears | `curl -s "https://aur.archlinux.org/rpc/v5/info?arg[]=vigil-bin&arg[]=vigil-security-bin"` |
| Glama, Smithery, mcp.so, PulseMCP | — | **Not listed** — account-gated submissions, metadata ready | — | [mcp-directories.md](mcp-directories.md) |
| [CII Best Practices](https://bestpractices.coreinfrastructure.org) | — | **Not registered** — checklist prepared, no project id | — | No badge in the README; [cii-best-practices.md](cii-best-practices.md) |
| [analysis-tools.dev](https://analysis-tools.dev) | — | **Not eligible** — the directory requires at least 6 months public, 20 stars and more than one human contributor; revisit later | — | — |

## Release assets (16)

`v0.11.0` counts 16 release assets:

- 6 static binaries: `linux`/`darwin`/`windows` on `amd64`/`arm64`;
- 6 Linux packages: deb, rpm and apk on `amd64`/`arm64`;
- `vigil-sbom-0.11.0.cdx.json` (CycloneDX 1.6 self-SBOM);
- `checksums.txt` and `checksums.txt.sigstore.json` (keyless cosign bundle);
- `provenance.intoto.jsonl` (SLSA build provenance bundle).

SLSA build provenance covers every asset except the bundle itself and is also
stored in GitHub's attestation store. 0.10.2 was the first release that attached
the bundle as `provenance.intoto.jsonl`; 0.10.1 and earlier have 15 assets.
0.10.2 and 0.11.0 are built with Go 1.27.4 (`go version -m <binary>`); 0.10.1
was built with Go 1.27.0. Asset list, signature identity and the full verification
flow:
[release.md](release.md#verify-a-release).

## Pending gates

| Gate | What is missing | Owner action |
| --- | --- | --- |
| WinGet | PR 480713 (0.10.1) passes its checks and waits for moderator review; 0.11.0 has no manifest yet | Wait for review; if changes are requested, add commits. Never force-push this branch: it permanently blocks reopening (see [release.md](release.md)). Submit 0.11.0 as a new version once the package exists |
| Official MCP Registry | The registry entry is 0.10.1; `server.json` is 0.11.0 | `mcp-publisher login github`, then `mcp-publisher publish`; [mcp-registry.md](mcp-registry.md) |
| AUR | Registration paused (HTTP 503, no manual queue); the original `vigil-bin` name belongs to `valeriansaliou/vigil`, so this package is renamed `vigil-security-bin` | Wait for the aur-general/Arch announcement; do not script retries; [aur.md](aur.md) |
| MCP directories | No listing accepted yet; every submission is an account-gated web action | Use the prepared metadata in [mcp-directories.md](mcp-directories.md) for Glama, Smithery, mcp.so, PulseMCP and the awesome lists |
| CII Best Practices | No project registered, so no project id and no badge | Register, answer the prepared questionnaire, replace `PROJECT_ID`; [cii-best-practices.md](cii-best-practices.md) |
| analysis-tools.dev | Eligibility not met | Revisit after the repository meets the directory's age, star and contributor gates |

## Re-verify

Run these read-only checks to confirm the table without trusting this page:

```bash
gh release view v0.11.0 --json tagName,assets --jq '.tagName, (.assets | length)'
npm view lv24-vigil version
curl -s https://pypi.org/pypi/lv24-vigil/json | jq -r .info.version
docker buildx imagetools inspect ghcr.io/levapveeskela/lv24-vigil:0.11.0
go list -m github.com/levapveeskela/lv24-vigil@v0.11.0
brew info LevapVeeskela/tap/vigil
scoop info lv24/vigil
curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=io.github.LevapVeeskela/vigil"
curl -s "https://aur.archlinux.org/rpc/v5/info?arg[]=vigil-bin&arg[]=vigil-security-bin"
```

The WinGet PR state needs the API or the PR page:

```bash
gh pr view 480713 --repo microsoft/winget-pkgs --json state,mergedAt
```

## Related documentation

- [install.md](install.md) — every install path, first scan and `vigil version`
- [release.md](release.md) — release pipeline and release verification
- [mcp-registry.md](mcp-registry.md) — official registry publishing and checks
- [aur.md](aur.md) — `vigil-security-bin` PKGBUILD, manual build and publication
- [mcp-directories.md](mcp-directories.md) — directory metadata and submission state
- [cii-best-practices.md](cii-best-practices.md) — CII questionnaire and badge
- [pre-commit.md](pre-commit.md) — pre-commit framework hooks
- [container.md](container.md) — GHCR tags, provenance and SBOM
- [scorecard.md](scorecard.md) — OpenSSF Scorecard workflow and badge

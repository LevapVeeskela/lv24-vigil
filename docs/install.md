# Install Vigil

Vigil ships as a single static binary. Pick the install path that fits your
environment; all of them expose the same `vigil` command. You do not need Docker
for a normal scan.

## npm

```bash
npm i -g lv24-vigil@latest     # or pin a release: lv24-vigil@0.10.3
vigil version
```

The `lv24-vigil` package selects a platform package at install time, named
`@lv24/vigil-<os>-<cpu>` (Windows, macOS and Linux on x64 and arm64). The
platform packages contain the binary only and run no install scripts. Keep
optional dependencies enabled: `--no-optional` and `--omit=optional` skip the
platform package, and `vigil` then exits with `platform package ... is not
installed`.

Releases are published from GitHub Actions with npm Trusted Publishing (OIDC).
`0.10.3` is the current version on the `latest` tag. Pipeline, verification and
re-run steps: [release.md](release.md).

For a one-off run without a global install:

```bash
npx -y lv24-vigil scan --no-llm
npx -y lv24-vigil mcp
```

## MCP Registry

Vigil is listed in the official MCP Registry as
`io.github.LevapVeeskela/vigil`; the npm package carries `mcpName` and the
repository ships the matching `server.json`, so registry-aware clients can add
it and still run the same stdio server:

```bash
npx -y lv24-vigil mcp
```

Registry layout, publishing and verification: [mcp-registry.md](mcp-registry.md).
Other MCP catalogues Vigil is submitted to: [mcp-directories.md](mcp-directories.md).

## Go

Go 1.27 or newer:

```bash
go install github.com/levapveeskela/lv24-vigil/cmd/vigil@latest
```

Make sure `$(go env GOPATH)/bin` is on `PATH`.

To build from a checkout:

```bash
git clone https://github.com/LevapVeeskela/lv24-vigil
cd lv24-vigil
go build -o vigil ./cmd/vigil
./vigil version
```

## Installers

The repository includes installers that resolve a release, verify the SHA-256
checksum from `checksums.txt`, install atomically and keep the previous binary.

macOS and Linux:

```bash
git clone https://github.com/LevapVeeskela/lv24-vigil
cd lv24-vigil
bash installers/unix/install.sh
```

Useful options: `--version vX.Y.Z`, `--dir PATH`, `--yes`, `--uninstall`.

Windows (PowerShell 5.1 or newer):

```powershell
git clone https://github.com/LevapVeeskela/lv24-vigil
cd lv24-vigil
.\installers\windows\install.ps1
```

Useful options: `-Version vX.Y.Z`, `-Dir PATH`, `-Yes`, `-Uninstall`. The
installer never requires administrator rights and never stores secrets.

## Linux packages

Every release also ships native packages for `amd64` and `arm64`, built from the
same `-ldflags` as the binaries, so `vigil version` inside a package reports the
release tag:

```text
vigil-<version>-linux-amd64.deb   vigil-<version>-linux-arm64.deb
vigil-<version>-linux-amd64.rpm   vigil-<version>-linux-arm64.rpm
vigil-<version>-linux-amd64.apk   vigil-<version>-linux-arm64.apk
```

Download the file for your distribution from the release page and install it
with the local path (`0.10.3`, `amd64` shown):

```bash
sudo apt install ./vigil-0.10.3-linux-amd64.deb                # Debian, Ubuntu
sudo dnf install --nogpgcheck ./vigil-0.10.3-linux-amd64.rpm   # Fedora, RHEL, openSUSE
sudo apk add --allow-untrusted ./vigil-0.10.3-linux-amd64.apk  # Alpine
vigil version
```

Each package installs the binary, a `/usr/bin/vigil` symlink and the license as
`/usr/share/doc/vigil/LICENSE`; deb and rpm declare `Provides: vigil`, so they
do not conflict with a distribution package of the same name. The packages carry
no distribution key of their own, which is why `dnf` needs `--nogpgcheck` and
`apk` needs `--allow-untrusted`. Integrity comes from `checksums.txt`, which
lists the packages and is signed with cosign keyless:
[release.md](release.md#verify-a-release).

## Scoop (Windows)

```powershell
scoop bucket add lv24 https://github.com/LevapVeeskela/scoop-bucket
scoop install lv24/vigil
```

The manifest tracks releases through `checkver` and `autoupdate`.

## Homebrew (macOS and Linux)

```bash
brew install LevapVeeskela/tap/vigil
```

The tap builds from the tagged source tarball and runs `vigil version` as its
test.

## AUR (Arch Linux)

AUR registration is temporarily paused, so `vigil-security-bin` is not published yet.
The PKGBUILD in this repository is refreshed from the published release assets. After the package appears on
AUR it installs the release binary instead of building from source:

```bash
yay -S vigil-security-bin          # or: paru -S vigil-security-bin
vigil version
```

The PKGBUILD downloads the release asset, checks it against the published
`checksums.txt` and installs the binary and license. Details, manual build and
verification: [aur.md](aur.md).

## Standalone binaries

Each GitHub release publishes six raw binaries and a `checksums.txt`:

```text
vigil_<version>_linux_amd64
vigil_<version>_linux_arm64
vigil_<version>_darwin_amd64
vigil_<version>_darwin_arm64
vigil_<version>_windows_amd64.exe
vigil_<version>_windows_arm64.exe
```

Download the file for your platform from the release page, verify it against
`checksums.txt`, and put it on `PATH` (rename it to `vigil` or `vigil.exe`).

https://github.com/LevapVeeskela/lv24-vigil/releases

Release binaries are built with CGO disabled and are statically linked; they do
not need a runtime or a shared library. On macOS, the first run may require
allowing the binary in System Settings if it was downloaded through a browser.

## Container

Prebuilt multi-arch images (`linux/amd64`, `linux/arm64`) are published to
GitHub Container Registry with every release:

```bash
docker pull ghcr.io/levapveeskela/lv24-vigil:0.10.3
docker run --rm -v "$PWD:/workspace" \
  ghcr.io/levapveeskela/lv24-vigil:0.10.3 scan --no-llm --path /workspace
```

The image is distroless (`gcr.io/distroless/static-debian12:nonroot`): no shell,
no package manager, entrypoint `vigil`, user `nonroot:nonroot`, working directory
`/workspace`. Tags are `<version>` (`0.10.3`), `<major>.<minor>` (`0.10`), `latest`
(non-prerelease only) and `sha-<commit>`. A tag can move; pin the manifest-list
digest in CI:

```bash
docker buildx imagetools inspect ghcr.io/levapveeskela/lv24-vigil:0.10.3 \
  --format '{{json .Manifest}}' | jq -r .digest

docker run --rm -v "$PWD:/workspace" \
  ghcr.io/levapveeskela/lv24-vigil@sha256:<digest> scan --no-llm --path /workspace
```

The `container` workflow builds with `provenance: true` and `sbom: true`, so a
BuildKit SLSA provenance record and an SPDX SBOM are attached to the image; the
run summary prints the tags, the digest and both platforms. The image itself is
not cosign-signed, so that digest is the integrity anchor. Inspecting the
attestations, the image limitations and the tag table:
[container.md](container.md).

On PowerShell, replace `$PWD` with `${PWD}` or an absolute path. The container
does not include Docker and does not scan other containers; it runs Vigil against
the mounted tree only.

### Build it locally

The repository also contains the distroless Dockerfile, so you can build the same
image from a checkout:

```bash
docker build -t lv24-vigil .
docker run --rm -v "$PWD:/workspace" -w /workspace lv24-vigil scan --no-llm
```

## Verify the install

```bash
vigil version
vigil status
vigil rules
```

`vigil status` prints the resolved provider, model, rule count, store directory,
baseline path, last scan and the source of a value when known. If no provider is
configured, it says so; deterministic scans still work.

## First scan

```bash
cd your-repo
vigil scan --no-llm
```

Then add a model if you want triage, deep review, fixes or a threat model:

```bash
export OPENAI_API_KEY=sk-...
vigil scan
```

Provider setup: [providers.md](providers.md). Commands: [cli.md](cli.md). MCP
clients: [mcp.md](mcp.md). CI: [ci.md](ci.md). Local hooks, including the
[pre-commit](https://pre-commit.com) framework: [pre-commit.md](pre-commit.md).

## Updating

- npm: `npm i -g lv24-vigil@latest`
- Go: `go install github.com/levapveeskela/lv24-vigil/cmd/vigil@latest`
- installer: run it again, or pass `--force` / `-Force` to reinstall the same
  version
- standalone: download the new binary and replace the old one
- Debian/Ubuntu, Fedora/RHEL/openSUSE, Alpine: install the new `.deb`/`.rpm`/
  `.apk` asset; the package replaces the previous one
- Scoop: `scoop update vigil`
- Homebrew: `brew upgrade vigil`
- Arch Linux (AUR): `yay -Syu vigil-security-bin` after the package is published and
  the PKGBUILD version is bumped
- container: `docker pull ghcr.io/levapveeskela/lv24-vigil:<new-version>`, or
  rebuild the local image

Check the changelog before a major update: [../CHANGELOG.md](../CHANGELOG.md).

## Uninstalling

- npm: `npm uninstall -g lv24-vigil`
- Unix installer: `bash installers/unix/install.sh --uninstall`
- Windows installer: `.\installers\windows\install.ps1 -Uninstall`
- Go: remove the binary from `$(go env GOPATH)/bin`
- standalone: delete the binary
- Linux package: `sudo apt remove vigil`, `sudo dnf remove vigil` or
  `sudo apk del vigil`
- Arch Linux (AUR): `sudo pacman -Rns vigil-security-bin`

Vigil does not install a daemon, a service, a scheduled task or a browser
extension. Scan history lives in the repository under `.vigil/scans` or in the
user cache directory; remove it manually if you want a clean slate.

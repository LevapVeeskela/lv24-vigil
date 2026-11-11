# Install Vigil

Vigil ships as a single static binary. Pick the install path that fits your
environment; all of them expose the same `vigil` command. You do not need Docker
for a normal scan.

## npm

```bash
npm i -g lv24-vigil@latest     # or pin a release: lv24-vigil@0.7.1
vigil version
```

The `lv24-vigil` package selects a platform package at install time, named
`@lv24/vigil-<os>-<cpu>` (Windows, macOS and Linux on x64 and arm64). The
platform packages contain the binary only and run no install scripts. Keep
optional dependencies enabled: `--no-optional` and `--omit=optional` skip the
platform package, and `vigil` then exits with `platform package ... is not
installed`.

Releases are published from GitHub Actions with npm Trusted Publishing (OIDC).
`0.7.1` is the current version on the `latest` tag. Pipeline, verification and
re-run steps: [release.md](release.md).

For a one-off run without a global install:

```bash
npx -y lv24-vigil scan --no-llm
npx -y lv24-vigil mcp
```

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

The repository includes a distroless Dockerfile. Build it from the repository
root:

```bash
docker build -t lv24-vigil .
```

The image runs as a non-root user and uses `/workspace` as its working directory:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  -e OPENAI_API_KEY \
  lv24-vigil scan
```

For a deterministic scan, no key is needed:

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace lv24-vigil scan --no-llm
```

On PowerShell, replace `$PWD` with `${PWD}` or an absolute path. The container
does not include Docker and does not scan other containers; it runs Vigil against
the mounted tree only.

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
clients: [mcp.md](mcp.md). CI: [ci.md](ci.md).

## Updating

- npm: `npm i -g lv24-vigil@latest`
- Go: `go install github.com/levapveeskela/lv24-vigil/cmd/vigil@latest`
- installer: run it again, or pass `--force` / `-Force` to reinstall the same
  version
- standalone: download the new binary and replace the old one
- container: rebuild the image

Check the changelog before a major update: [../CHANGELOG.md](../CHANGELOG.md).

## Uninstalling

- npm: `npm uninstall -g lv24-vigil`
- Unix installer: `bash installers/unix/install.sh --uninstall`
- Windows installer: `.\installers\windows\install.ps1 -Uninstall`
- Go: remove the binary from `$(go env GOPATH)/bin`
- standalone: delete the binary

Vigil does not install a daemon, a service, a scheduled task or a browser
extension. Scan history lives in the repository under `.vigil/scans` or in the
user cache directory; remove it manually if you want a clean slate.

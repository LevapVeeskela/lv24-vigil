# Container image

Vigil is published as a multi-arch container image on GitHub Container Registry
by [`.github/workflows/container.yml`](../.github/workflows/container.yml) when a
`v*` release tag is pushed, or on demand with `workflow_dispatch`.

| | |
| --- | --- |
| Image | `ghcr.io/levapveeskela/lv24-vigil` |
| Platforms | `linux/amd64`, `linux/arm64` |
| Base image | `gcr.io/distroless/static-debian12:nonroot` |
| Entrypoint | `vigil` (no shell, no package manager) |
| User | `nonroot:nonroot`, working directory `/workspace` |

The binary is static and the container runs as a non-root user. There is no
shell and no `sh`, so `docker run --entrypoint sh` does not work; the image only
runs `vigil` and its subcommands.

## Tags

| Tag | Example | Meaning |
| --- | --- | --- |
| `<version>` | `0.10.1` | exact release |
| `<major>.<minor>` | `0.10` | newest `0.10.x`, including a prerelease if one is tagged |
| `latest` | `latest` | newest non-prerelease release only |
| `sha-<short>` | `sha-f5686bb` | one commit, for bisecting |

For a reproducible pipeline, prefer a version tag with a digest (below), not
`latest`.

## Scan a repository

`0.10.1` is the release tag; use the version you actually run.

```bash
docker run --rm -v "$PWD:/workspace" ghcr.io/levapveeskela/lv24-vigil:0.10.1 scan --no-llm --path /workspace
```

`/workspace` is the image's working directory, so `--path /workspace` is
explicit rather than required. On PowerShell use `${PWD}` or an absolute path in
place of `$PWD`. Reports written with `--output` must point inside the mounted
tree (for example `--output /workspace/vigil.sarif`), otherwise they are lost
when the container exits.

## Pin a digest

A tag can move; a digest cannot. Resolve it once and pin it in CI:

```bash
docker buildx imagetools inspect ghcr.io/levapveeskela/lv24-vigil:0.10.1 \
  --format '{{json .Manifest}}' | jq -r .digest
```

```bash
docker run --rm -v "$PWD:/workspace" \
  ghcr.io/levapveeskela/lv24-vigil@sha256:<manifest-list-digest> \
  scan --no-llm --path /workspace
```

The printed digest is the multi-platform index digest: the same pin resolves to
the `amd64` or `arm64` image for the host. `docker buildx imagetools inspect`
without `--format` also prints the digest, plus the per-platform manifests.

## Verify SBOM and provenance

The workflow builds with `provenance: true` (SLSA, `mode=min`) and `sbom: true`,
so both attestations are pushed next to the image. Inspect them with Buildx:

```bash
# SBOM (SPDX) for one platform
docker buildx imagetools inspect ghcr.io/levapveeskela/lv24-vigil:0.10.1 \
  --format '{{json (index .SBOM "linux/amd64")}}'

# provenance for one platform
docker buildx imagetools inspect ghcr.io/levapveeskela/lv24-vigil:0.10.1 \
  --format '{{json (index .Provenance "linux/amd64")}}'
```

Pipe the output through `jq` for readable JSON. A quick check that the
attestations exist at all:

```bash
docker buildx imagetools inspect ghcr.io/levapveeskela/lv24-vigil:0.10.1 \
  --format '{{json .Manifest}}' | jq -r '.manifests[].annotations["vnd.docker.reference.type"] // empty' | sort -u
```

That prints `attestation-manifest` once per attestation type. The provenance is
BuildKit's SLSA record of the build inputs and the builder; it is `mode=min`, so
it does not contain every build parameter. The SBOM is an SPDX document from
BuildKit's default scanner (syft). A distroless image has no OS package database,
so expect a short package list dominated by the base image files; it is not a
substitute for `go version -m` on the binary.

The image is **not signed**: there is no cosign key or GitHub attestation on the
manifest list. The digest from `imagetools inspect` is the integrity anchor —
compare it with the digest printed in the workflow run summary, which the
`container` workflow writes for every build.

## Offline by default

The image is offline for a normal scan: `scan --no-llm` runs all rules with no
model, no key and no network call. Nothing is downloaded at run time.

- The rules and prompts are Go source compiled into the `vigil` binary. There is
  no external rules directory, and no packed asset (such as an ASAR archive) to
  mount or unpack. Apart from the binary the image holds only the distroless
  base files (CA bundle, passwd/group), so there is no rule file to update or to
  keep in sync with the binary version.
- Network access is only used when you pass a provider key and let the optional
  LLM passes run (triage in `scan`, `review`, `fix`, `threat-model`). Those calls
  go to the endpoint you configured, never to a Vigil service.
- Docker itself is not in the image, and the container cannot scan other
  containers; it scans the tree you mount.

## Container limitations

- **No `git` binary.** `vigil scan --changed --base <ref>` shells out to `git`,
  which the distroless image does not contain. Use `--path`, or feed a diff on
  stdin from the host:

  ```bash
  git diff | docker run -i --rm -v "$PWD:/workspace" \
    ghcr.io/levapveeskela/lv24-vigil:0.10.1 scan --diff - --no-llm
  ```

- **No shell.** `sh -c` wrappers and shell redirection are not available; use
  `--output`, `--format` and `--fail-on` instead.
- **Writable paths:** the root filesystem is writable like any Docker container,
  but it disappears with `--rm`. Write the report, baseline and store under
  `/workspace` so they survive the run; add `--read-only --tmpfs /tmp` if you
  want to enforce an immutable container.

## Build it locally

The same Dockerfile builds outside CI; `VERSION`, `COMMIT` and `DATE` are the
build args the workflow passes.

```bash
docker build -t vigil-test .
docker run --rm vigil-test version
```

See [install.md](install.md#container) for the local-build instructions and
[ci.md](ci.md) for the deterministic gate the image runs.

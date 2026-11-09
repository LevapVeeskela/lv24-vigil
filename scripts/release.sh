#!/usr/bin/env bash
#
# Local fallback release for Vigil when GitHub Actions is unavailable.
#
# Cross-compiles the six release targets with `go build`, writes checksums.txt,
# creates a GitHub release with `gh`, uploads missing assets, then builds and
# publishes the npm packages. The script is idempotent: an existing release is
# reused, assets already present are skipped, and npm versions already
# published are skipped by npm/publish.sh.

set -euo pipefail

REPO="LevapVeeskela/lv24-vigil"
VERSION=""
NOTES=""
SKIP_NPM=0
TAG=""
COMMIT=""
DATE=""
DIST=""
NOTES_FILE=""
RELEASE_EXISTS=0

usage() {
    cat <<'USAGE'
Create a Vigil release locally.

Usage:
  scripts/release.sh --version X.Y.Z [options]

Options:
  --version, -v X.Y.Z   Release version (v1.2.3 and 1.2.3 are both accepted).
  --notes, -n TEXT      Release notes (default: "Vigil X.Y.Z").
  --repo OWNER/NAME     GitHub repository (default: LevapVeeskela/lv24-vigil).
  --skip-npm            Build the GitHub release but do not build/publish npm.
  -h, --help            Show this help.

Requires go, git and an authenticated gh. npm/publish.sh publishes only when
npm Trusted Publishing (OIDC) or NODE_AUTH_TOKEN is available; otherwise it
skips with a notice, which is not an error.
USAGE
}

die() {
    printf 'release.sh: %s\n' "$1" >&2
    exit 1
}

step() {
    printf '==> %s\n' "$1"
}

note() {
    printf '    %s\n' "$1"
}

cleanup() {
    if [ -n "${NOTES_FILE:-}" ] && [ -f "$NOTES_FILE" ]; then
        rm -f "$NOTES_FILE" || true
    fi
}

parse_args() {
    local arg
    local normalized
    normalized=()
    for arg in "$@"; do
        case "$arg" in
            --*=*|-Version=*|-version=*|-Notes=*|-notes=*|-Repo=*|-repo=*)
                normalized+=("${arg%%=*}" "${arg#*=}")
                ;;
            *) normalized+=("$arg") ;;
        esac
    done
    if [ "${#normalized[@]}" -gt 0 ]; then
        set -- "${normalized[@]}"
    else
        set --
    fi

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version|-version|-Version|-v)
                [ "$#" -ge 2 ] || die "$1 requires a value"
                VERSION="$2"
                shift 2
                ;;
            --notes|-notes|-Notes|-n)
                [ "$#" -ge 2 ] || die "$1 requires a value"
                NOTES="$2"
                shift 2
                ;;
            --repo|-repo|-Repo)
                [ "$#" -ge 2 ] || die "$1 requires a value"
                REPO="$2"
                shift 2
                ;;
            --skip-npm|-SkipNpm)
                SKIP_NPM=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
    done
}

build_target() {
    local goos="$1" goarch="$2" ext="$3" name out ldflags
    name="vigil_${VERSION}_${goos}_${goarch}${ext}"
    out="$DIST/$name"
    ldflags="-s -w -X github.com/levapveeskela/lv24-vigil/internal/version.Version=${VERSION} -X github.com/levapveeskela/lv24-vigil/internal/version.Commit=${COMMIT} -X github.com/levapveeskela/lv24-vigil/internal/version.Date=${DATE}"
    step "Building $name"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$ldflags" -o "$out" ./cmd/vigil
}

main() {
    local root bash_bin count file base existing

    parse_args "$@"
    [ -n "$VERSION" ] || { usage >&2; exit 2; }
    VERSION="${VERSION#v}"
    if ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
        die "version must look like 1.2.3 or 1.2.3-beta.1 (got '$VERSION')"
    fi
    TAG="v$VERSION"

    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cd "$root"

    command -v go >/dev/null 2>&1 || die "go is required but was not found on PATH"
    command -v git >/dev/null 2>&1 || die "git is required but was not found on PATH"
    command -v gh >/dev/null 2>&1 || die "gh is required but was not found on PATH"
    gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run gh auth login first"

    COMMIT="$(git rev-parse HEAD)" || die "could not resolve HEAD; run this script inside the git repository"
    [ -n "$COMMIT" ] || die "could not resolve HEAD"
    DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    DIST="$root/dist"
    rm -rf "$DIST"
    mkdir -p "$DIST"

    build_target windows amd64 .exe
    build_target windows arm64 .exe
    build_target darwin amd64 ''
    build_target darwin arm64 ''
    build_target linux amd64 ''
    build_target linux arm64 ''

    step "Writing checksums.txt"
    (
        cd "$DIST"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum vigil_* >checksums.txt
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 vigil_* >checksums.txt
        else
            echo "release.sh: sha256sum or shasum is required" >&2
            exit 1
        fi
    )

    count=0
    for file in "$DIST"/vigil_*; do
        if [ -f "$file" ]; then
            count=$((count + 1))
        fi
    done
    [ "$count" -eq 6 ] || die "expected 6 binaries in $DIST, found $count"

    NOTES_FILE="$(mktemp "${TMPDIR:-/tmp}/vigil-release-notes.XXXXXX")" || die "cannot create a temporary notes file"
    trap cleanup EXIT
    printf '%s\n' "${NOTES:-Vigil $VERSION}" >"$NOTES_FILE"

    if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
        RELEASE_EXISTS=1
        step "Release $TAG already exists; uploading missing assets"
    else
        step "Creating release $TAG"
        tag_exists=0
        if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
            tag_exists=1
        fi
        args=(release create "$TAG" --repo "$REPO" --title "Vigil $VERSION" --notes-file "$NOTES_FILE")
        if [ "$tag_exists" -eq 0 ]; then
            args+=(--target "$COMMIT")
        fi
        case "$VERSION" in
            *-*) args+=(--prerelease) ;;
        esac
        gh "${args[@]}" || die "gh release create failed for $TAG"
    fi

    existing=""
    if [ "$RELEASE_EXISTS" -eq 1 ]; then
        existing="$(gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name')" ||
            die "could not list assets of release $TAG"
    fi

    for file in "$DIST"/vigil_* "$DIST/checksums.txt"; do
        base="$(basename "$file")"
        if [ -n "$existing" ] && printf '%s\n' "$existing" | grep -Fxq "$base"; then
            note "skip existing asset $base"
            continue
        fi
        step "Uploading $base"
        gh release upload "$TAG" "$file" --repo "$REPO" || die "gh release upload failed for $base"
    done

    if [ "$SKIP_NPM" -eq 1 ]; then
        step "npm build/publish skipped (--skip-npm)"
    else
        step "Building npm packages"
        node npm/build.mjs --version "$VERSION" --dist "$DIST" --out "$root/npm-out"
        step "Publishing npm packages"
        bash_bin="$(command -v bash 2>/dev/null || true)"
        [ -n "$bash_bin" ] || die "bash is required to run npm/publish.sh"
        "$bash_bin" npm/publish.sh "$VERSION" "$root/npm-out"
    fi

    printf '\n'
    step "Release complete"
    note "tag:     $TAG"
    note "commit:  $COMMIT"
    note "assets:  $DIST"
    note "release: https://github.com/$REPO/releases/tag/$TAG"
}

main "$@"

#!/usr/bin/env bash
#
# Vigil installer for macOS and Linux.
#
# Resolves a published GitHub release, verifies the SHA-256 checksum from
# checksums.txt, installs the vigil binary atomically, and prints the installed
# version. The previous binary is kept as vigil.previous.
#
# The installer never asks for, writes, or logs secrets, never uses sudo, and
# never pipes a download into a shell. Compatible with bash 3.2 (macOS).

set -euo pipefail

REPO="LevapVeeskela/lv24-vigil"
API_ROOT="https://api.github.com"
RELEASE_ROOT="https://github.com"

REQUESTED_VERSION=""
INSTALL_DIR=""
ASSUME_YES=0
UNINSTALL=0
NO_PATH_HINT=0
FORCE=0

OS=""
ARCH=""
TAG=""
VERSION_NUMBER=""
ASSET_NAME=""
EXPECTED_SHA=""
TARGET_PATH=""
TMP_DIR=""
STAGED_BIN=""
CURL=""
WGET=""
SHA_TOOL=""

print_usage() {
    cat <<'USAGE'
Install the Vigil security auditor on macOS or Linux.

Usage:
  install.sh [options]

Options:
  --version vX.Y.Z   Install an exact release instead of the latest one.
  --dir PATH         Binary directory (default: ~/.local/bin).
  --yes              Non-interactive; also skips the uninstall confirmation.
  --force            Reinstall even when the same version is already installed.
  --uninstall        Remove vigil, vigil.previous and install leftovers from
                     --dir. Keeps .vigil.yaml and scan history. Refuses without
                     --yes when stdin is not a terminal (exit 2).
  --no-path-hint     Do not print a PATH hint.
  -h, --help         Show this help.

Environment:
  GITHUB_TOKEN       Optional read-only token; raises GitHub API limits.
  TMPDIR             Optional parent directory for the temporary workspace.

Examples:
  install.sh
  install.sh --version v1.2.3 --dir "$HOME/bin"
  install.sh --uninstall --yes

Every download is HTTPS-only and is verified against the release SHA-256
checksum before the binary is installed. No secrets are stored.
USAGE
}

die() {
    printf 'install.sh: %s\n' "$1" >&2
    exit 1
}

usage_error() {
    printf 'install.sh: %s\n\n' "$1" >&2
    print_usage >&2
    exit 2
}

step() {
    printf '==> %s\n' "$1"
}

note() {
    printf '    %s\n' "$1"
}

warn() {
    printf 'install.sh: warning: %s\n' "$1" >&2
}

flag_value() {
    # Prints the value for a long option or returns 1 when it is missing.
    if [ -z "${2:-}" ]; then
        return 1
    fi
    case "$2" in
        --*) return 1 ;;
    esac
    printf '%s' "$2"
}

expand_path() {
    case "${1:-}" in
        '~') printf '%s' "$HOME" ;;
        '~/'*) printf '%s/%s' "$HOME" "${1#\~/}" ;;
        *) printf '%s' "$1" ;;
    esac
}

absolute_path() {
    case "${1:-}" in
        /*) printf '%s' "$1" ;;
        *) printf '%s/%s' "$(pwd)" "$1" ;;
    esac
}

parse_args() {
    local arg
    local normalized
    normalized=()
    # Accept --flag=value by splitting it into two arguments first.
    for arg in "$@"; do
        case "$arg" in
            --*=*) normalized+=("${arg%%=*}" "${arg#*=}") ;;
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
            -h|--help)
                print_usage
                exit 0
                ;;
            --version)
                REQUESTED_VERSION="$(flag_value "$1" "${2:-}")" || usage_error "$1 requires a value"
                shift 2
                ;;
            --dir)
                INSTALL_DIR="$(flag_value "$1" "${2:-}")" || usage_error "$1 requires a value"
                shift 2
                ;;
            --yes)
                ASSUME_YES=1
                shift
                ;;
            --force)
                FORCE=1
                shift
                ;;
            --uninstall)
                UNINSTALL=1
                shift
                ;;
            --no-path-hint)
                NO_PATH_HINT=1
                shift
                ;;
            -*)
                usage_error "unknown option: $1"
                ;;
            *)
                usage_error "unexpected argument: $1"
                ;;
        esac
    done
}

validate_args() {
    case "$REQUESTED_VERSION" in
        ''|latest) REQUESTED_VERSION="" ;;
        *)
            case "$REQUESTED_VERSION" in
                v*) ;;
                *) REQUESTED_VERSION="v$REQUESTED_VERSION" ;;
            esac
            if ! printf '%s' "$REQUESTED_VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
                usage_error "--version must look like v1.2.3"
            fi
            ;;
    esac
}

check_prereqs() {
    if command -v curl >/dev/null 2>&1; then
        CURL="$(command -v curl)"
    elif command -v wget >/dev/null 2>&1; then
        WGET="$(command -v wget)"
    else
        die "curl or wget is required"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        SHA_TOOL="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        SHA_TOOL="shasum"
    elif command -v openssl >/dev/null 2>&1; then
        SHA_TOOL="openssl"
    else
        die "sha256sum, shasum, or openssl is required to verify the download"
    fi

    if [ -n "${GITHUB_TOKEN:-}" ]; then
        case "$GITHUB_TOKEN" in
            *[[:space:]]*) die "GITHUB_TOKEN must not contain whitespace" ;;
        esac
    fi
}

http_get() {
    # http_get URL DESTINATION
    local url destination
    url="$1"
    destination="$2"

    case "$url" in
        https://*) ;;
        *) die "refusing non-HTTPS URL: $url" ;;
    esac

    if [ -n "$CURL" ]; then
        "$CURL" -q -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout 15 --retry 2 --retry-delay 1 --max-redirs 5 \
            --max-time 300 -o "$destination" "$url"
    else
        # --https-only prevents a redirect from downgrading the download to
        # plain HTTP; --max-redirect keeps the chain bounded.
        "$WGET" -q -T 30 -t 2 --https-only --max-redirect=5 -O "$destination" "$url"
    fi
}

api_get() {
    # api_get PATH DESTINATION. The optional token is sent only as a header.
    local path destination
    path="$1"
    destination="$2"

    if [ -n "$CURL" ]; then
        local -a args
        args=(-q -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2
            --connect-timeout 15 --retry 2 --retry-delay 1 --max-redirs 5
            --max-time 60
            -H 'Accept: application/vnd.github+json'
            -H 'User-Agent: lv24-vigil-installer')
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            args+=(-H "Authorization: Bearer $GITHUB_TOKEN")
        fi
        "$CURL" "${args[@]}" -o "$destination" "$API_ROOT$path"
    else
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            "$WGET" -q -T 30 -t 2 --https-only --max-redirect=5 -O "$destination" \
                --header='Accept: application/vnd.github+json' \
                --header='User-Agent: lv24-vigil-installer' \
                --header="Authorization: Bearer $GITHUB_TOKEN" \
                "$API_ROOT$path"
        else
            "$WGET" -q -T 30 -t 2 --https-only --max-redirect=5 -O "$destination" \
                --header='Accept: application/vnd.github+json' \
                --header='User-Agent: lv24-vigil-installer' \
                "$API_ROOT$path"
        fi
    fi
}

json_flat() {
    tr -d '\r\n' <"$1"
}

json_string() {
    # json_string TEXT KEY: prints the last string value for KEY.
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

json_true() {
    # json_true TEXT KEY: succeeds when KEY is the JSON literal true.
    printf '%s' "$1" | grep -Eq "\"$2\"[[:space:]]*:[[:space:]]*true"
}

is_sha256() {
    [ -n "${1:-}" ] || return 1
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
    esac
    return 0
}

sha256_file() {
    case "$SHA_TOOL" in
        sha256sum) sha256sum "$1" | awk '{print $1}' ;;
        shasum) shasum -a 256 "$1" | awk '{print $1}' ;;
        openssl) openssl dgst -sha256 "$1" | awk '{print $NF}' ;;
        *) return 1 ;;
    esac
}

checksum_from_file() {
    # checksum_from_file FILE ASSET_NAME: prints the matching sha256, if any.
    local file want line digest name
    file="$1"
    want="$2"
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        case "$line" in
            ''|'#'*) continue ;;
        esac
        read -r digest name _ <<<"$line"
        [ -n "$digest" ] && [ -n "$name" ] || continue
        name=${name#\*}
        if [ "$name" = "$want" ]; then
            tr 'A-Z' 'a-z' <<<"$digest"
            return 0
        fi
    done <"$file"
    return 0
}

binary_reports_version() {
    # binary_reports_version VERSION: succeeds when the installed binary names VERSION.
    local want line
    want="${1#v}"
    [ -x "$TARGET_PATH" ] || return 1
    line="$("$TARGET_PATH" version 2>/dev/null | sed -n '1p')" || return 1
    printf '%s\n' "$line" | awk -v want="$want" '
        { for (i = 1; i <= NF; i++) { f = $i; sub(/^v/, "", f); if (f == want) found = 1 } }
        END { exit (found ? 0 : 1) }'
}

resolve_release() {
    local release_file body
    release_file="$TMP_DIR/release.json"

    if [ -n "$REQUESTED_VERSION" ]; then
        TAG="$REQUESTED_VERSION"
        step "Looking up release $TAG"
        api_get "/repos/$REPO/releases/tags/$TAG" "$release_file" ||
            die "release $TAG was not found in $REPO (or GitHub was unreachable)"
    else
        step "Looking up the latest release"
        api_get "/repos/$REPO/releases/latest" "$release_file" ||
            die "could not read the latest release for $REPO; set GITHUB_TOKEN for rate limits or pin --version"
    fi

    body="$(json_flat "$release_file")"
    if [ -z "$REQUESTED_VERSION" ]; then
        TAG="$(json_string "$body" tag_name)"
    fi
    [ -n "$TAG" ] || die "the GitHub response did not contain a release tag"
    case "$TAG" in
        v[0-9]*) ;;
        *) die "unexpected release tag from GitHub: $TAG" ;;
    esac
    case "$TAG" in
        *[!0-9A-Za-z.+-]*) die "release tag contains unexpected characters: $TAG" ;;
    esac
    VERSION_NUMBER="${TAG#v}"
    [ -n "$VERSION_NUMBER" ] || die "release tag has no version: $TAG"

    if json_true "$body" draft; then
        die "release $TAG is still a draft and cannot be installed; pin another --version"
    fi
    note "release: $TAG"
}

resolve_package() {
    local checksums_url
    ASSET_NAME="vigil_${VERSION_NUMBER}_${OS}_${ARCH}"
    checksums_url="$RELEASE_ROOT/$REPO/releases/download/$TAG/checksums.txt"

    step "Downloading checksums.txt"
    http_get "$checksums_url" "$TMP_DIR/checksums.txt" || die "could not download $checksums_url"
    EXPECTED_SHA="$(checksum_from_file "$TMP_DIR/checksums.txt" "$ASSET_NAME" | tr 'A-Z' 'a-z')"
    is_sha256 "$EXPECTED_SHA" || die "no SHA-256 checksum found for $ASSET_NAME; refusing to install"
}

install_binary() {
    local url actual
    url="$RELEASE_ROOT/$REPO/releases/download/$TAG/$ASSET_NAME"

    if [ "$FORCE" -eq 0 ] && binary_reports_version "$VERSION_NUMBER"; then
        step "vigil $VERSION_NUMBER is already installed at $TARGET_PATH; download skipped (use --force to reinstall)"
        return 0
    fi

    step "Downloading $ASSET_NAME"
    http_get "$url" "$TMP_DIR/vigil-download" || die "download failed: $url"

    actual="$(sha256_file "$TMP_DIR/vigil-download")" || die "could not compute SHA-256 for $ASSET_NAME"
    if [ "$actual" != "$EXPECTED_SHA" ]; then
        die "SHA-256 mismatch for $ASSET_NAME: got $actual, expected $EXPECTED_SHA"
    fi
    note "checksum verified: $EXPECTED_SHA"

    mkdir -p "$INSTALL_DIR" || die "cannot create $INSTALL_DIR"
    [ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable; choose another --dir (sudo is never used)"

    STAGED_BIN="$INSTALL_DIR/.vigil.install.$$"
    cp "$TMP_DIR/vigil-download" "$STAGED_BIN" || die "cannot stage the new binary in $INSTALL_DIR"
    chmod 0755 "$STAGED_BIN" || die "cannot make $STAGED_BIN executable"
    if [ -f "$TARGET_PATH" ]; then
        cp -p "$TARGET_PATH" "$TARGET_PATH.previous" || die "cannot keep the previous binary as $TARGET_PATH.previous"
    fi
    mv -f "$STAGED_BIN" "$TARGET_PATH" || die "cannot replace $TARGET_PATH"
    STAGED_BIN=""
    note "installed: $TARGET_PATH"
}

verify_binary() {
    local line
    if line="$("$TARGET_PATH" version 2>/dev/null | sed -n '1p')" && [ -n "$line" ]; then
        note "binary check: $line"
    else
        warn "the installed binary did not answer 'version'; it may not match this platform"
    fi
}

print_path_hint() {
    if [ "$NO_PATH_HINT" -eq 1 ]; then
        return 0
    fi
    case ":$PATH:" in
        *":$INSTALL_DIR:"*)
            note "$INSTALL_DIR is already on PATH"
            ;;
        *)
            note "Add $INSTALL_DIR to PATH to run vigil from any shell:"
            printf '      export PATH="%s:$PATH"\n' "$INSTALL_DIR"
            note "Add that line to ~/.zshrc (macOS) or ~/.profile (Linux)."
            ;;
    esac
}

finish() {
    step "Install complete"
    note "binary:  $TARGET_PATH"
    note "version: $VERSION_NUMBER"
    print_path_hint
    note "Next: $TARGET_PATH scan ."
    note "      $TARGET_PATH init"
    note "      $TARGET_PATH mcp   # MCP server over stdio"
    note "No secrets were stored. Keep tokens and .env values out of scanned repositories."
}

cleanup() {
    if [ -n "${STAGED_BIN:-}" ] && [ -f "$STAGED_BIN" ]; then
        rm -f "$STAGED_BIN" || true
    fi
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR" || true
    fi
}

uninstall_targets() {
    local candidate
    for candidate in "$INSTALL_DIR/vigil" "$INSTALL_DIR/vigil.previous" \
        "$INSTALL_DIR"/.vigil.install.*; do
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            printf '%s\n' "$candidate"
        fi
    done
}

uninstall() {
    local targets path answer
    targets="$(uninstall_targets)"
    if [ -z "$targets" ]; then
        step "Uninstall: nothing to remove in $INSTALL_DIR"
        return 0
    fi

    step "Uninstalling vigil from $INSTALL_DIR"
    while IFS= read -r path; do
        note "will remove: $path"
    done <<<"$targets"

    if [ "$ASSUME_YES" -eq 0 ]; then
        if [ ! -t 0 ]; then
            printf 'install.sh: uninstall needs confirmation; rerun with --yes when stdin is not a terminal\n' >&2
            exit 2
        fi
        printf 'Remove the files listed above? [y/N] '
        answer=""
        IFS= read -r answer || answer=""
        case "$answer" in
            y|Y|yes|YES) ;;
            *) step "Uninstall cancelled; nothing was removed."; exit 1 ;;
        esac
    fi

    while IFS= read -r path; do
        rm -f "$path" || die "cannot remove $path"
        note "removed: $path"
    done <<<"$targets"

    step "Kept (never removed by the uninstaller)"
    note ".vigil.yaml and scan history (default ~/.local/share/vigil or .vigil/)"
    note "Remove any PATH export you added to your shell profile yourself; this installer does not add one."
}

main() {
    local uname_s uname_m

    parse_args "$@"
    validate_args

    if [ -z "${HOME:-}" ] && [ -z "$INSTALL_DIR" ]; then
        die "HOME is not set; pass --dir to choose an install directory"
    fi
    if [ -z "$INSTALL_DIR" ]; then
        INSTALL_DIR="$HOME/.local/bin"
    fi
    INSTALL_DIR="$(absolute_path "$(expand_path "$INSTALL_DIR")")"
    TARGET_PATH="$INSTALL_DIR/vigil"

    # Uninstall only removes local files, so it does not need a supported platform check.
    if [ "$UNINSTALL" -eq 1 ]; then
        uninstall
        return 0
    fi

    uname_s="$(uname -s)"
    case "$uname_s" in
        Linux) OS="linux" ;;
        Darwin) OS="darwin" ;;
        *) die "unsupported operating system: $uname_s (releases cover Linux and macOS)" ;;
    esac
    uname_m="$(uname -m)"
    case "$uname_m" in
        x86_64|amd64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *) die "unsupported architecture: $uname_m (releases cover amd64 and arm64)" ;;
    esac

    check_prereqs
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lv24-vigil-install.XXXXXX")" || die "cannot create a temporary directory"
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    step "Installing vigil for $OS/$ARCH into $INSTALL_DIR"
    resolve_release
    resolve_package
    install_binary
    verify_binary
    finish
}

# Tests source this file with LV24_VIGIL_INSTALLER_SOURCE_ONLY=1 to call helpers.
if [ "${LV24_VIGIL_INSTALLER_SOURCE_ONLY:-0}" != 1 ]; then
    main "$@"
fi

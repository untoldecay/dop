#!/usr/bin/env bash
# One-line installer for `dop`.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/untoldecay/dop/main/scripts/install.sh | bash
#   curl -fsSL ... | DOP_INSTALL_DIR=~/.local/bin DOP_VERSION=v0.2.0 bash
#
# Env overrides:
#   DOP_INSTALL_DIR   default: ~/.local/bin
#   DOP_VERSION       default: latest release
#   DOP_REPO          default: untoldecay/dop
#
# Runtime dependencies NOT bundled (installer will refuse without them):
#   - sops (brew install sops  |  apt install age sops  |  releases)
#   - git

set -euo pipefail

DOP_INSTALL_DIR="${DOP_INSTALL_DIR:-$HOME/.local/bin}"
DOP_VERSION="${DOP_VERSION:-latest}"
DOP_REPO="${DOP_REPO:-untoldecay/dop}"

log() { echo "[dop-install] $*"; }
err() { echo "[dop-install] error: $*" >&2; }

require_dep() {
    local bin=$1
    local hint=$2
    if ! command -v "$bin" >/dev/null 2>&1; then
        err "$bin is required on \$PATH — $hint"
        exit 1
    fi
}

# Detect OS/arch → goreleaser artifact naming
detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch=amd64 ;;
        arm64|aarch64) arch=arm64 ;;
        *) err "unsupported arch: $arch"; exit 1 ;;
    esac
    case "$os" in
        linux|darwin) ;;
        *) err "unsupported OS: $os"; exit 1 ;;
    esac
    echo "${os}_${arch}"
}

resolve_version() {
    if [[ "$DOP_VERSION" != "latest" ]]; then
        echo "$DOP_VERSION"
        return
    fi
    # `curl` for GitHub API — no gh CLI required
    local tag
    tag=$(curl -fsSL "https://api.github.com/repos/${DOP_REPO}/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    if [[ -z "$tag" ]]; then
        err "could not resolve latest release from GitHub"
        exit 1
    fi
    echo "$tag"
}

main() {
    log "resolving install location..."
    require_dep curl "install via https://curl.se or your package manager"
    require_dep tar  "part of base install on every unix"
    # sops + git are runtime deps for dop itself; warn if missing but don't block install
    for dep in sops git; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "warning: $dep not on \$PATH — dop will fail at runtime without it"
        fi
    done

    local platform version
    platform=$(detect_platform)
    version=$(resolve_version)
    version_no_v="${version#v}" # goreleaser archive names strip the v prefix

    local archive="dop_${version_no_v}_${platform}.tar.gz"
    local url="https://github.com/${DOP_REPO}/releases/download/${version}/${archive}"

    log "downloading $url"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    if ! curl -fsSL "$url" -o "$tmpdir/dop.tar.gz"; then
        err "download failed. Check network + that $DOP_REPO has a release for platform $platform."
        exit 1
    fi

    log "extracting"
    tar -xzf "$tmpdir/dop.tar.gz" -C "$tmpdir"

    mkdir -p "$DOP_INSTALL_DIR"
    install -m 0755 "$tmpdir/dop" "$DOP_INSTALL_DIR/dop"
    log "installed: $DOP_INSTALL_DIR/dop"

    # Warn if not in PATH
    if ! echo ":$PATH:" | grep -q ":$DOP_INSTALL_DIR:"; then
        log "note: $DOP_INSTALL_DIR is not in \$PATH — add it to your shell config:"
        log "  echo 'export PATH=\"$DOP_INSTALL_DIR:\$PATH\"' >> ~/.zshrc"
    fi

    log "verify: $DOP_INSTALL_DIR/dop help"
}

main "$@"

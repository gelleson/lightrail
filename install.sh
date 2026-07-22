#!/bin/sh
set -eu

# Lightrail One-Line Installer Script
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/gelleson/lightrail/main/install.sh | sh
# Options via environment variables:
#   PREFIX=/custom/path       Installation directory (default: ~/.local or /usr/local)
#   VERSION=v0.1.0            Specific release tag to install (default: latest)
#   REPO=gelleson/lightrail   GitHub repository

REPO="${REPO:-gelleson/lightrail}"
VERSION="${VERSION:-latest}"

if [ "$(id -u)" -eq 0 ]; then
    PREFIX="${PREFIX:-/usr/local}"
else
    PREFIX="${PREFIX:-$HOME/.local}"
fi

DESTDIR="${DESTDIR:-}"
TARGET_DIR="${DESTDIR}${PREFIX}/bin"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64)
        ARCH="x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

case "$OS" in
    linux)
        TARGET="${ARCH}-unknown-linux-musl"
        ;;
    darwin)
        TARGET="aarch64-apple-darwin"
        ;;
    *)
        echo "Error: Unsupported operating system: $OS" >&2
        exit 1
        ;;
esac

echo "==> Lightrail Installer"
echo "    Target: $TARGET"
echo "    Destination: $TARGET_DIR"

BINARIES="lightrail lightrail-plugin-compose lightrail-plugin-fly lightrail-plugin-hetzner lightrail-plugin-kubernetes lightrail-plugin-ssh"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'lightrail')"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

INSTALLED=0

# Check if local release binaries exist in repo
if [ -f "target/release/lightrail" ]; then
    echo "==> Using local release build from target/release..."
    mkdir -p "$TARGET_DIR"
    for bin in $BINARIES; do
        if [ -f "target/release/$bin" ]; then
            install -m 0755 "target/release/$bin" "$TARGET_DIR/"
        fi
    done
    INSTALLED=1
else
    # Fetch from GitHub Releases
    if [ "$VERSION" = "latest" ]; then
        DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/lightrail-${TARGET}.tar.gz"
    else
        DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/lightrail-${VERSION}-${TARGET}.tar.gz"
    fi

    echo "==> Downloading release package from $DOWNLOAD_URL..."
    if curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/lightrail.tar.gz" 2>/dev/null; then
        tar -xzf "$TMP_DIR/lightrail.tar.gz" -C "$TMP_DIR"
        mkdir -p "$TARGET_DIR"
        for bin in $BINARIES; do
            if [ -f "$TMP_DIR/$bin" ]; then
                install -m 0755 "$TMP_DIR/$bin" "$TARGET_DIR/"
            fi
        done
        INSTALLED=1
    elif command -v cargo >/dev/null 2>&1 && [ -f "Cargo.toml" ]; then
        echo "==> Download not found. Building locally using Cargo..."
        cargo build --release --locked
        mkdir -p "$TARGET_DIR"
        for bin in $BINARIES; do
            if [ -f "target/release/$bin" ]; then
                install -m 0755 "target/release/$bin" "$TARGET_DIR/"
            fi
        done
        INSTALLED=1
    fi
fi

if [ "$INSTALLED" -eq 1 ]; then
    echo "==> Lightrail successfully installed to $TARGET_DIR:"
    for bin in $BINARIES; do
        if [ -f "$TARGET_DIR/$bin" ]; then
            echo "  - $TARGET_DIR/$bin"
        fi
    done

    case ":$PATH:" in
        *":$TARGET_DIR:"*) ;;
        *)
            echo ""
            echo "Note: $TARGET_DIR is not in your PATH."
            echo "Add it to your shell configuration:"
            echo "  export PATH=\"$TARGET_DIR:\$PATH\""
            ;;
    esac
else
    echo "Error: Could not install Lightrail. Please build manually using 'make release' or 'cargo build --release'." >&2
    exit 1
fi

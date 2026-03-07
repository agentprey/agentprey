#!/bin/sh

set -eu

INSTALL_DIR=${INSTALL_DIR:-"$HOME/.local/bin"}
RELEASES_BASE_URL=${AGENTPREY_RELEASES_BASE_URL:-"https://github.com/agentprey/agentprey/releases"}
VERSION=""

usage() {
  cat <<'EOF'
Install AgentPrey from GitHub release binaries.

Usage:
  curl -fsSL https://agentprey.com/install | sh
  curl -fsSL https://agentprey.com/install | sh -s -- --version v0.1.6

Options:
  --install-dir <dir>  Install into a custom directory (default: ~/.local/bin)
  --version <tag>      Install a specific release tag (default: latest stable release)
  -h, --help           Show this help text

Environment:
  INSTALL_DIR                  Override the install directory
  AGENTPREY_RELEASES_BASE_URL  Override the releases base URL
EOF
}

say() {
  printf '%s\n' "$*"
}

err() {
  printf 'agentprey install: %s\n' "$*" >&2
}

die() {
  err "$1"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

normalize_version() {
  case "$1" in
    v*) printf '%s\n' "$1" ;;
    *) printf 'v%s\n' "$1" ;;
  esac
}

compute_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
    return
  fi

  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$1" | awk '{ print $1 }'
    return
  fi

  die "missing checksum tool (expected sha256sum, shasum, or openssl)"
}

detect_target() {
  os=$(uname -s 2>/dev/null || printf 'unknown')
  arch=$(uname -m 2>/dev/null || printf 'unknown')

  case "$os:$arch" in
    Linux:x86_64|Linux:amd64)
      TARGET_TRIPLE="x86_64-unknown-linux-gnu"
      ;;
    Darwin:arm64|Darwin:aarch64)
      TARGET_TRIPLE="aarch64-apple-darwin"
      ;;
    *)
      die "unsupported platform '$os' '$arch'; use 'cargo install agentprey --locked' instead"
      ;;
  esac

  ARCHIVE_NAME="agentprey-$TARGET_TRIPLE.tar.gz"
  CHECKSUM_NAME="$ARCHIVE_NAME.sha256"
  PACKAGE_DIR="agentprey-$TARGET_TRIPLE"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --install-dir)
      [ $# -ge 2 ] || die "--install-dir requires a value"
      INSTALL_DIR=$2
      shift 2
      ;;
    --version)
      [ $# -ge 2 ] || die "--version requires a value"
      VERSION=$(normalize_version "$2")
      shift 2
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

need_cmd curl
need_cmd tar
need_cmd awk
need_cmd mktemp

detect_target

if [ -n "$VERSION" ]; then
  RELEASE_PATH="download/$VERSION"
else
  RELEASE_PATH="latest/download"
fi

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/agentprey-install.XXXXXX")
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

ARCHIVE_PATH="$TMP_DIR/$ARCHIVE_NAME"
CHECKSUM_PATH="$TMP_DIR/$CHECKSUM_NAME"
EXTRACT_DIR="$TMP_DIR/extract"

say "Downloading $ARCHIVE_NAME..."
curl -fsSL "$RELEASES_BASE_URL/$RELEASE_PATH/$ARCHIVE_NAME" -o "$ARCHIVE_PATH" || die "failed to download release archive"
curl -fsSL "$RELEASES_BASE_URL/$RELEASE_PATH/$CHECKSUM_NAME" -o "$CHECKSUM_PATH" || die "failed to download checksum file"

EXPECTED_SHA=$(awk '{ print $1 }' "$CHECKSUM_PATH")
[ -n "$EXPECTED_SHA" ] || die "checksum file did not include a SHA256 digest"

ACTUAL_SHA=$(compute_sha256 "$ARCHIVE_PATH")
[ "$EXPECTED_SHA" = "$ACTUAL_SHA" ] || die "checksum verification failed for $ARCHIVE_NAME"

mkdir -p "$EXTRACT_DIR"
tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR" || die "failed to extract $ARCHIVE_NAME"

BIN_SOURCE="$EXTRACT_DIR/$PACKAGE_DIR/agentprey"
[ -f "$BIN_SOURCE" ] || die "release archive did not contain $PACKAGE_DIR/agentprey"

mkdir -p "$INSTALL_DIR" || die "failed to create install directory $INSTALL_DIR"
BIN_TARGET="$INSTALL_DIR/agentprey"
TMP_TARGET="$INSTALL_DIR/.agentprey.$$"

cp "$BIN_SOURCE" "$TMP_TARGET" || die "failed to copy agentprey into $INSTALL_DIR"
chmod 755 "$TMP_TARGET" || die "failed to mark agentprey executable"
mv "$TMP_TARGET" "$BIN_TARGET" || die "failed to place agentprey into $INSTALL_DIR"

say "Installed agentprey to $BIN_TARGET"

case ":${PATH:-}:" in
  *:"$INSTALL_DIR":*)
    ;;
  *)
    say "Add $INSTALL_DIR to your PATH to run 'agentprey' directly."
    ;;
esac

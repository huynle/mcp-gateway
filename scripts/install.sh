#!/bin/sh
# Install the mcp-gateway client CLI (and its mcp-gateway-tunnel alias)
# from a GitHub Release, verifying the archive against checksums.txt.
#
#   curl -fsSL https://github.com/huynle/mcp-gateway/releases/latest/download/install.sh | sh
#
# Environment:
#   VERSION       release tag to install (e.g. v1.2.3); default: the latest
#   INSTALL_DIR   where to put the binaries; default: $HOME/.local/bin
#   MCP_GATEWAY_RELEASES_URL  releases base URL; default:
#                 https://github.com/huynle/mcp-gateway/releases
#
# No sudo: choose a writable INSTALL_DIR (or run the script with sudo
# yourself). POSIX sh; needs curl or wget, tar (unzip on Windows) and
# sha256sum or shasum.
set -eu

RELEASES_URL="${MCP_GATEWAY_RELEASES_URL:-https://github.com/huynle/mcp-gateway/releases}"
INSTALL_DIR="${INSTALL_DIR:-${HOME:?}/.local/bin}"
VERSION="${VERSION:-}"

say() { printf 'mcp-gateway install: %s\n' "$*" >&2; }
die() {
	say "error: $*"
	exit 1
}

detect_os() {
	case "$(uname -s)" in
	Darwin) echo darwin ;;
	Linux) echo linux ;;
	MINGW* | MSYS* | CYGWIN* | Windows_NT) echo windows ;;
	*) die "unsupported operating system: $(uname -s)" ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	arm64 | aarch64) echo arm64 ;;
	*) die "unsupported architecture: $(uname -m)" ;;
	esac
}

download() { # URL FILE
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,file' -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "curl or wget is required"
	fi
}

sha256_of() { # FILE
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d ' ' -f 1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d ' ' -f 1
	else
		die "sha256sum or shasum is required"
	fi
}

main() {
	os="$(detect_os)"
	arch="$(detect_arch)"
	ext=tar.gz
	exe=""
	if [ "$os" = windows ]; then
		ext=zip
		exe=.exe
	fi
	archive="mcp-gateway_${os}_${arch}.${ext}"

	if [ -n "$VERSION" ]; then
		case "$VERSION" in
		v*) ;;
		*) VERSION="v$VERSION" ;;
		esac
		base="$RELEASES_URL/download/$VERSION"
	else
		base="$RELEASES_URL/latest/download"
	fi

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT INT TERM

	say "downloading $archive (${VERSION:-latest})"
	download "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
	download "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"

	want="$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")"
	[ -n "$want" ] || die "no checksum for $archive in checksums.txt"
	got="$(sha256_of "$tmp/$archive")"
	[ "$got" = "$want" ] || die "checksum mismatch for $archive (got $got, want $want)"

	mkdir "$tmp/x"
	if [ "$ext" = zip ]; then
		command -v unzip >/dev/null 2>&1 || die "unzip is required"
		unzip -q "$tmp/$archive" -d "$tmp/x"
	else
		tar -xzf "$tmp/$archive" -C "$tmp/x"
	fi
	for b in mcp-gateway mcp-gateway-tunnel; do
		[ -f "$tmp/x/$b$exe" ] || die "$b$exe missing from $archive"
	done

	mkdir -p "$INSTALL_DIR"
	for b in mcp-gateway mcp-gateway-tunnel; do
		# Copy next to the target, then rename: no half-written binary.
		cp "$tmp/x/$b$exe" "$INSTALL_DIR/.$b$exe.tmp"
		chmod 0755 "$INSTALL_DIR/.$b$exe.tmp"
		mv -f "$INSTALL_DIR/.$b$exe.tmp" "$INSTALL_DIR/$b$exe"
	done
	say "installed mcp-gateway and mcp-gateway-tunnel into $INSTALL_DIR"

	case ":${PATH}:" in
	*":$INSTALL_DIR:"*) ;;
	*) say "note: $INSTALL_DIR is not on your PATH; add it, e.g. export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
	esac
	say "next: mcp-gateway tunnel --help"
}

main "$@"

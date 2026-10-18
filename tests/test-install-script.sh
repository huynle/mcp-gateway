#!/usr/bin/env bash
# Tests scripts/install.sh against a fake local release (file:// URLs) and a
# fake `uname`: the OS/arch -> archive mapping, the latest and $VERSION
# download paths, the checksum check and the unsupported-platform errors.
# Needs curl, tar and sha256sum or shasum; zip/unzip for the Windows case.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
script="$root/scripts/install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# A fake uname: -s prints $FAKE_UNAME_S, -m prints $FAKE_UNAME_M.
mkdir -p "$work/fakebin"
cat >"$work/fakebin/uname" <<'SH'
#!/bin/sh
case "$1" in
  -s) echo "$FAKE_UNAME_S" ;;
  -m) echo "$FAKE_UNAME_M" ;;
  *) echo "fake uname: unexpected $*" >&2; exit 1 ;;
esac
SH
chmod +x "$work/fakebin/uname"

# make_release DIR TAG: archives for every target with stub binaries that
# print "<name> <tag>", plus checksums.txt.
make_release() {
  local dir="$1" tag="$2" os arch stage ext
  mkdir -p "$dir"
  for os in darwin linux windows; do
    for arch in amd64 arm64; do
      stage="$work/stage-$tag-$os-$arch"
      mkdir -p "$stage"
      ext=""
      [ "$os" = windows ] && ext=".exe"
      for b in mcp-gateway mcp-gateway-tunnel; do
        printf '#!/bin/sh\necho "%s %s %s_%s"\n' "$b" "$tag" "$os" "$arch" >"$stage/$b$ext"
        chmod +x "$stage/$b$ext"
      done
      echo readme >"$stage/README.md"
      if [ "$os" = windows ]; then
        command -v zip >/dev/null 2>&1 || continue
        (cd "$stage" && zip -q "$dir/mcp-gateway_${os}_${arch}.zip" ./*)
      else
        tar -czf "$dir/mcp-gateway_${os}_${arch}.tar.gz" -C "$stage" .
      fi
    done
  done
  (cd "$dir" && sha256 mcp-gateway_* >checksums.txt)
}

releases="$work/releases"
make_release "$releases/latest/download" v9.9.9
make_release "$releases/download/v1.2.3" v1.2.3

# install_with OS ARCH DEST [VAR=VALUE...]: run the script, output in $out.
install_with() {
  local os="$1" arch="$2" dest="$3"
  shift 3
  set +e
  out="$(env PATH="$work/fakebin:$PATH" FAKE_UNAME_S="$os" FAKE_UNAME_M="$arch" \
    MCP_GATEWAY_RELEASES_URL="file://$releases" INSTALL_DIR="$dest" "$@" sh "$script" 2>&1)"
  rc=$?
  set -e
}

# OS/arch mapping (uname values -> archive), from the latest release.
for case in "Darwin x86_64 darwin_amd64" "Darwin arm64 darwin_arm64" \
  "Linux x86_64 linux_amd64" "Linux aarch64 linux_arm64" "Linux arm64 linux_arm64" \
  "Linux amd64 linux_amd64"; do
  read -r -a f <<<"$case"; set -- "${f[@]}"
  dest="$work/bin-$1-$2"
  install_with "$1" "$2" "$dest"
  [ "$rc" = 0 ] || fail "$1/$2: exit $rc: $out"
  [ -x "$dest/mcp-gateway" ] && [ -x "$dest/mcp-gateway-tunnel" ] || fail "$1/$2: binaries not installed: $out"
  [ "$("$dest/mcp-gateway")" = "mcp-gateway v9.9.9 $3" ] || fail "$1/$2: installed $("$dest/mcp-gateway"), want $3"
  [ "$("$dest/mcp-gateway-tunnel")" = "mcp-gateway-tunnel v9.9.9 $3" ] || fail "$1/$2: wrong alias"
  [ ! -e "$dest/README.md" ] || fail "$1/$2: README.md installed into the bin dir"
  pass "$1 $2 -> $3"
done

# Windows (Git Bash / MSYS) uses the zip and .exe names.
if command -v zip >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
  dest="$work/bin-win"
  install_with MINGW64_NT-10.0 x86_64 "$dest"
  [ "$rc" = 0 ] || fail "windows: exit $rc: $out"
  [ "$(sh "$dest/mcp-gateway.exe")" = "mcp-gateway v9.9.9 windows_amd64" ] || fail "windows: wrong binary"
  [ -e "$dest/mcp-gateway-tunnel.exe" ] || fail "windows: alias missing"
  pass "MINGW64 x86_64 -> windows_amd64 (zip)"
else
  echo "skip windows case (zip/unzip not installed)"
fi

# $VERSION selects /download/<tag>; a missing "v" is added.
for v in v1.2.3 1.2.3; do
  dest="$work/bin-version-$v"
  install_with Linux x86_64 "$dest" VERSION="$v"
  [ "$rc" = 0 ] || fail "VERSION=$v: exit $rc: $out"
  [ "$("$dest/mcp-gateway")" = "mcp-gateway v1.2.3 linux_amd64" ] || fail "VERSION=$v: installed $("$dest/mcp-gateway")"
  pass "VERSION=$v -> download/v1.2.3"
done

# Unsupported platforms fail before downloading anything.
for case in "Linux i686 architecture" "Linux armv7l architecture" "SunOS x86_64 operating"; do
  read -r -a f <<<"$case"; set -- "${f[@]}"
  dest="$work/bin-unsupported-$1-$2"
  install_with "$1" "$2" "$dest"
  [ "$rc" != 0 ] || fail "$1/$2: accepted"
  grep -qi "unsupported $3" <<<"$out" || fail "$1/$2: no 'unsupported $3' message: $out"
  [ ! -e "$dest/mcp-gateway" ] || fail "$1/$2: installed something"
  pass "$1 $2 refused"
done

# A tampered archive fails the checksum and installs nothing.
bad="$work/bad-releases"
mkdir -p "$bad/latest/download"
cp "$releases/latest/download/"* "$bad/latest/download/"
echo tampered >>"$bad/latest/download/mcp-gateway_linux_amd64.tar.gz"
dest="$work/bin-tampered"
mkdir -p "$dest"
echo old >"$dest/mcp-gateway"
install_with Linux x86_64 "$dest" MCP_GATEWAY_RELEASES_URL="file://$bad"
[ "$rc" != 0 ] || fail "tampered archive accepted: $out"
grep -qi "checksum mismatch" <<<"$out" || fail "tampered archive: no 'checksum mismatch' message: $out"
[ "$(cat "$dest/mcp-gateway")" = old ] || fail "tampered archive: existing binary replaced"
[ ! -e "$dest/mcp-gateway-tunnel" ] || fail "tampered archive: alias installed"
pass "checksum mismatch refused"

# An archive missing from checksums.txt is refused too.
grep -v linux_arm64 "$releases/latest/download/checksums.txt" >"$bad/latest/download/checksums.txt"
cp "$releases/latest/download/mcp-gateway_linux_amd64.tar.gz" "$bad/latest/download/"
dest="$work/bin-nosum"
install_with Linux aarch64 "$dest" MCP_GATEWAY_RELEASES_URL="file://$bad"
[ "$rc" != 0 ] || fail "archive without checksum accepted: $out"
grep -qi "no checksum" <<<"$out" || fail "missing checksum: no 'no checksum' message: $out"
[ ! -e "$dest/mcp-gateway" ] || fail "missing checksum: installed something"
pass "missing checksum refused"

# The script is POSIX sh and shellcheck-clean (when shellcheck is present).
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -s sh "$script" || fail "shellcheck"
  pass "shellcheck -s sh"
else
  echo "skip shellcheck (not installed)"
fi

echo "install.sh tests passed"

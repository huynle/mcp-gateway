#!/usr/bin/env bash
set -euo pipefail

workflow="${1:-.github/workflows/ci.yml}"

top_level="$(sed -n '/^permissions:/,/^[^ ]/p' "$workflow")"
release="$(sed -n '/^  release:/,$p' "$workflow")"

grep -q '^  contents: read$' <<<"$top_level"
if grep -q 'packages: write' <<<"$top_level"; then
  echo "package write must not be granted at workflow scope" >&2
  exit 1
fi
grep -q '^    permissions:$' <<<"$release"
grep -q '^      contents: read$' <<<"$release"
grep -q '^      packages: write$' <<<"$release"
grep -q "if: github.event_name == 'push' && github.ref == 'refs/heads/main'" <<<"$release"
grep -q '^    uses: huynle/.github/.github/workflows/container-release.yml@v1$' <<<"$release"

for gate in fmt lint test test-integration test-e2e image oauth-attack helm vulncheck image-scan test-security; do
  grep -q "^      - $gate$" <<<"$release" || {
    echo "release is missing required gate: $gate" >&2
    exit 1
  }
done

grep -q 'aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0' "$workflow"
echo "mcp-gateway release workflow contract passed"

# --- CLI release (release.yml + .goreleaser.yaml) ---------------------------
cli="${2:-.github/workflows/release.yml}"
goreleaser_cfg="${3:-.goreleaser.yaml}"

grep -q '^    tags: \["v\*"\]$' "$cli" || { echo "release.yml must run on v* tags only" >&2; exit 1; }
grep -q '^permissions: {}$' "$cli" || { echo "release.yml must grant nothing at workflow scope" >&2; exit 1; }
job_perms="$(sed -n '/^    permissions:$/,/^    steps:$/p' "$cli" | grep -E '^      [a-z-]+:' | sed 's/ *#.*//' | sort)"
want_perms="$(printf '      attestations: write\n      contents: write\n      id-token: write\n')"
if [ "$job_perms" != "$want_perms" ]; then
  echo "release.yml job permissions must be exactly contents/id-token/attestations: write, got:" >&2
  echo "$job_perms" >&2
  exit 1
fi
# Every action is pinned by a full commit SHA.
if grep -E '^\s*-?\s*uses:' "$cli" | grep -vqE 'uses: [^@]+@[0-9a-f]{40}( |$)'; then
  echo "release.yml: every action must be pinned by a full commit SHA:" >&2
  grep -E '^\s*-?\s*uses:' "$cli" | grep -vE 'uses: [^@]+@[0-9a-f]{40}( |$)' >&2
  exit 1
fi
grep -q 'actions/attest-build-provenance@' "$cli" || { echo "release.yml must attest build provenance" >&2; exit 1; }
# shellcheck disable=SC2016 # a literal GitHub expression
grep -q 'HOMEBREW_TAP_DEPLOY_KEY: ${{ secrets.HOMEBREW_TAP_DEPLOY_KEY }}' "$cli" || { echo "release.yml must pass the tap deploy key secret" >&2; exit 1; }
# The tap push is skipped without the key (forks), and uses SSH, not a PAT.
grep -q "skip_upload: '{{ if index .Env \"HOMEBREW_TAP_DEPLOY_KEY\" }}auto{{ else }}true{{ end }}'" "$goreleaser_cfg" || { echo ".goreleaser.yaml must skip the tap without HOMEBREW_TAP_DEPLOY_KEY" >&2; exit 1; }
grep -q 'url: "git@github.com:huynle/homebrew-tap.git"' "$goreleaser_cfg" || { echo ".goreleaser.yaml must push the tap over SSH" >&2; exit 1; }
for b in ./cmd/mcp-gateway ./cmd/mcp-gateway-tunnel; do
  grep -q "main: $b$" "$goreleaser_cfg" || { echo ".goreleaser.yaml must build $b" >&2; exit 1; }
done
echo "mcp-gateway CLI release workflow contract passed"

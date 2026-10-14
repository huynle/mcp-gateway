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

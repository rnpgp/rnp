#!/usr/bin/env bash
# ci/check_reproducibility.sh
#
# Build the same (target, backend, version) twice on the same host
# and compare the resulting tarballs byte-for-byte. Reports a summary
# of differences if the build is not fully reproducible.
#
# Reproducibility is documented as best-effort in docs/packaging.adoc:
# SOURCE_DATE_EPOCH=0 normalizes the gzip header; .a archive member
# mtimes and object-file path embedding remain non-reproducible.
# This script does NOT fail when the tarballs differ -- it just
# surfaces the difference so maintainers can track progress.
#
# Usage: check_reproducibility.sh <backend> <version> <target>
#
# Output:
#   Two tarballs in /tmp/repro-{1,2}/
#   A summary on stdout. Exit code 0 unless a build itself fails.

set -euo pipefail

BACKEND="${1:?usage: check_reproducibility.sh <backend> <version> <target>}"
VERSION="${2:?missing version}"
TARGET="${3:?missing target triple}"

OUT1="$(mktemp -d)/1"
OUT2="$(mktemp -d)/2"
mkdir -p "$OUT1" "$OUT2"
trap 'rm -rf "$OUT1" "$OUT2"' EXIT

WORK1="$(mktemp -d)"
WORK2="$(mktemp -d)"
trap 'rm -rf "$WORK1" "$WORK2"' EXIT

echo "=== Build 1 ==="
RNP_ARTIFACT_DIR="$OUT1" bash "$(dirname "$0")/build_prebuilt.sh" \
    "$BACKEND" "$VERSION" "$TARGET" "$WORK1"

echo "=== Build 2 ==="
RNP_ARTIFACT_DIR="$OUT2" bash "$(dirname "$0")/build_prebuilt.sh" \
    "$BACKEND" "$VERSION" "$TARGET" "$WORK2"

T1="$(echo "$OUT1"/rnp-*.tar.gz)"
T2="$(echo "$OUT2"/rnp-*.tar.gz)"

H1="$(shasum -a 256 "$T1" | awk '{print $1}')"
H2="$(shasum -a 256 "$T2" | awk '{print $1}')"
S1="$(wc -c < "$T1" | tr -d ' ')"
S2="$(wc -c < "$T2" | tr -d ' ')"

echo ""
echo "=== Result ==="
echo "build 1: $H1 ($S1 bytes)"
echo "build 2: $H2 ($S2 bytes)"

if [[ "$H1" == "$H2" ]]; then
    echo "REPRODUCIBLE: byte-identical tarballs."
    exit 0
fi

echo "NOT REPRODUCIBLE: tarballs differ."
# Show per-file differences inside the tarballs. Useful for tracking
# down what changed.
TMP1="$(mktemp -d)"
TMP2="$(mktemp -d)"
tar xzf "$T1" -C "$TMP1"
tar xzf "$T2" -C "$TMP2"

echo ""
echo "=== Per-file differences ==="
( cd "$TMP1" && find . -type f -exec shasum -a 256 {} \; | sort ) > /tmp/sums1
( cd "$TMP2" && find . -type f -exec shasum -a 256 {} \; | sort ) > /tmp/sums2
diff /tmp/sums1 /tmp/sums2 | head -20 || true

rm -rf "$TMP1" "$TMP2" /tmp/sums1 /tmp/sums2

# Exit 0 -- this is informational, not a CI blocker.
exit 0

#!/bin/sh
# Regenerate the pre-built man pages in docs/man/ from the .adoc sources.
#
# The cache exists so packagers can build/install man pages without
# asciidoctor installed (#2395): CMake falls back to docs/man/ when no
# AsciiDoc processor is found. Run this on a machine with asciidoctor
# whenever a .adoc man source changes, and before cutting a release
# (the roff files embed the component version).
#
# Usage: ci/regen-man-pages.sh [version]
#   version defaults to the CMake-derived version (cmake/version.cmake).

set -e

cd "$(dirname "$0")/.."

if ! command -v asciidoctor >/dev/null 2>&1; then
    echo "error: asciidoctor is required to regenerate man pages" >&2
    exit 1
fi

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    VERSION=$(cmake -P cmake/version.cmake 2>/dev/null | tail -1)
fi
if [ -z "$VERSION" ]; then
    VERSION="0.0.0"
fi

mkdir -p docs/man

for adoc in src/rnp/rnp.1.adoc src/rnpkeys/rnpkeys.1.adoc src/lib/librnp.3.adoc; do
    out="docs/man/$(basename "${adoc}" .adoc)"
    asciidoctor -b manpage -a component-version="${VERSION}" -o "${out}" "${adoc}"
    echo "regenerated ${out} (component-version=${VERSION})"
done

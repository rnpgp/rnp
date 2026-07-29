#!/usr/bin/env bash
# ci/test_prebuilt.sh
#
# Validate that a prebuilt static-library tarball conforms to the
# layout and behavior contract in docs/specs/tarball-layout.adoc.
#
# Usage: test_prebuilt.sh <tarball-path>
#
# What this checks:
#   1. Naming convention (rnp-v<version>-<target>-<backend>.tar.gz)
#   2. Top-level layout (include/, lib/, MANIFEST.txt)
#   3. Required headers under include/rnp/
#   4. Required static archives under lib/
#   5. CMake config + pkg-config files present
#   6. pkg-config files don't leak absolute build paths
#   7. MANIFEST.txt is internally consistent
#   8. End-to-end: compile, link, and run a minimal C consumer that
#      calls rnp_ffi_create() and expects RNP_SUCCESS.
#
# Returns 0 if everything passes; non-zero (with diagnostic) otherwise.
#
# Flags:
#   --no-link   Skip the end-to-end compile+link+run check (sections 8).
#               Useful on Windows where invoking MSVC from bash isn't
#               practical; structural checks (1-7) still run.

set -euo pipefail

NO_LINK=0
TARBALL=""
for arg in "$@"; do
    case "$arg" in
        --no-link) NO_LINK=1 ;;
        --*) echo "unknown flag: $arg" >&2; exit 2 ;;
        *) TARBALL="$arg" ;;
    esac
done
if [[ -z "$TARBALL" ]]; then
    echo "usage: $0 [--no-link] <tarball-path>" >&2
    exit 2
fi
TARBALL_BASENAME="$(basename "$TARBALL")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# 1. Naming
# ---------------------------------------------------------------------------
# Structure: rnp-v<version>-<target>-<backend>.tar.gz
#   * Always starts with `rnp-v`.
#   * Always ends with `-botan.tar.gz` or `-openssl.tar.gz`.
#   * <version> may include suffixes like `-pr-test` (PR placeholder),
#     `-rc1` (release candidate), `+build.42` (semver build). Match
#     permissively and parse precisely below.
if [[ ! "$TARBALL_BASENAME" =~ ^rnp-v.+-(botan|openssl)\.tar\.gz$ ]]; then
    echo "FAIL: tarball name '$TARBALL_BASENAME' does not match rnp-v<version>-<target>-<backend>.tar.gz" >&2
    exit 1
fi
echo "PASS naming: $TARBALL_BASENAME"

# Extract the triple + backend from the filename.
# Filename: rnp-v<version>-<triple-as-dashed>-<backend>.tar.gz
# Strip the leading `rnp-v` and trailing `.tar.gz`, then split:
#   * backend = last `-`-delimited token
#   * version = first `-`-delimited token (bare version, no leading v)
#   * target = everything between them
STEM="${TARBALL_BASENAME%.tar.gz}"           # rnp-v<...>-<backend>
STEM="${STEM#rnp-v}"                          # <version>-<triple>-<backend>
BACKEND="${STEM##*-}"                         # backend
STEM="${STEM%-"$BACKEND"}"                    # <version>-<triple>
VERSION="${STEM%%-*}"                         # first token (bare version)
TARGET="${STEM#"${VERSION}-"}"                # everything after first -

if [[ ! "$BACKEND" =~ ^(botan|openssl)$ ]]; then
    echo "FAIL: backend '$BACKEND' must be botan or openssl" >&2
    exit 1
fi
if [[ -z "$VERSION" || -z "$TARGET" ]]; then
    echo "FAIL: could not parse version or target from filename" >&2
    exit 1
fi
echo "PASS parsed: version=$VERSION target=$TARGET backend=$BACKEND"

# ---------------------------------------------------------------------------
# 2. Extract
# ---------------------------------------------------------------------------
EXTRACT_DIR="$WORK/extract"
mkdir -p "$EXTRACT_DIR"
tar xzf "$TARBALL" -C "$EXTRACT_DIR"

STAGING_NAME="rnp-v${VERSION}-${TARGET}-${BACKEND}"
STAGING="$EXTRACT_DIR/$STAGING_NAME"

if [[ ! -d "$STAGING" ]]; then
    echo "FAIL: tarball did not extract to '$STAGING_NAME' -- top-level dir mismatch" >&2
    echo "  actual contents of $EXTRACT_DIR:" >&2
    ls -la "$EXTRACT_DIR" >&2
    exit 1
fi
echo "PASS extracts to $STAGING_NAME/"

# ---------------------------------------------------------------------------
# 3. Top-level layout
# ---------------------------------------------------------------------------
for required in include lib MANIFEST.txt; do
    if [[ ! -e "$STAGING/$required" ]]; then
        echo "FAIL: missing top-level entry: $required" >&2
        exit 1
    fi
done
echo "PASS top-level layout has include/ lib/ MANIFEST.txt"

# Source the same backend + target config files the build script uses
# (TODOs 01, 02). All backend/target-specific data (required libs,
# link flags, archive extension, platform link flags) comes from
# here; the test has zero `case "$BACKEND" in` or
# `case "$TARGET" in` branches.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1090
source "${SCRIPT_DIR}/backends/${BACKEND}.env"
# shellcheck disable=SC1090
source "${SCRIPT_DIR}/targets/${TARGET}.env"

# ---------------------------------------------------------------------------
# 4. Required headers
# ---------------------------------------------------------------------------
for h in rnp.h rnp_err.h rnp_export.h rnp_ver.h; do
    if [[ ! -f "$STAGING/include/rnp/$h" ]]; then
        echo "FAIL: missing required FFI header: include/rnp/$h" >&2
        exit 1
    fi
done
echo "PASS include/rnp/{rnp.h,rnp_err.h,rnp_export.h,rnp_ver.h}"

for required_header in bzlib.h zlib.h; do
    if [[ ! -f "$STAGING/include/$required_header" ]]; then
        echo "FAIL: missing required header: include/$required_header" >&2
        exit 1
    fi
done
echo "PASS include/bzlib.h include/zlib.h"

if [[ ! -d "$STAGING/include/$BACKEND_HEADERS_DIR" ]]; then
    echo "FAIL: $BACKEND backend requires include/$BACKEND_HEADERS_DIR/" >&2
    exit 1
fi
echo "PASS backend headers present ($BACKEND, include/$BACKEND_HEADERS_DIR/)"

if [[ ! -d "$STAGING/include/json-c" ]]; then
    echo "FAIL: missing include/json-c/" >&2
    exit 1
fi
echo "PASS include/json-c/"

# ---------------------------------------------------------------------------
# 5. Required static archives
# ---------------------------------------------------------------------------
# Archive extension comes from the target config (.a on Unix,
# .lib on Windows). The lib-name list is OS-specific: Unix backends use
# lib<name>.a (BACKEND_LIB_NAMES); Windows uses vcpkg-style names like
# zs.lib / bz2.lib (BACKEND_WINDOWS_LIB_NAMES) which differ from the
# Unix names because vcpkg renames some libraries.
ARCHIVE_EXT="$TARGET_ARCHIVE_EXT"
if [[ "$TARGET_OS" == "windows" ]]; then
    _lib_list="${BACKEND_WINDOWS_LIB_NAMES}"
else
    _lib_list="${BACKEND_LIB_NAMES}"
fi
IFS=',' read -ra _names <<< "$_lib_list"
REQUIRED_LIBS=()
for n in "${_names[@]}"; do
    # BACKEND_LIB_NAMES uses the "lib<name>" form on Unix and "<name>"
    # on Windows. Strip a leading "lib" if present so we can append
    # the right extension below.
    case "$n" in
        lib*) base="${n#lib}" ;;
        *)    base="$n" ;;
    esac
    REQUIRED_LIBS+=("${base}${ARCHIVE_EXT}")
done

for lib in "${REQUIRED_LIBS[@]}"; do
    # Allow either lib<name>.<ext> or <name>.<ext> spelling.
    if [[ ! -f "$STAGING/lib/lib$lib" && ! -f "$STAGING/lib/$lib" ]]; then
        echo "FAIL: missing required static archive: lib/$lib (or lib/lib$lib)" >&2
        echo "  contents of $STAGING/lib/:" >&2
        ls -la "$STAGING/lib/" >&2
        exit 1
    fi
done
echo "PASS required static archives present"

for required_dir in cmake/rnp pkgconfig; do
    if [[ ! -d "$STAGING/lib/$required_dir" ]]; then
        echo "FAIL: missing lib/$required_dir/" >&2
        exit 1
    fi
done
echo "PASS lib/cmake/rnp/ and lib/pkgconfig/"

# ---------------------------------------------------------------------------
# 6. pkg-config: no leaked absolute build paths
# ---------------------------------------------------------------------------
LEAKED_PATHS_RE='/tmp/|/home/|/Users/|C:\\\\|D:\\\\a\\\\|/var/folders/'
leak=0
for pc in "$STAGING/lib/pkgconfig"/*.pc; do
    [[ -f "$pc" ]] || continue
    if grep -E "$LEAKED_PATHS_RE" "$pc" >/dev/null; then
        echo "FAIL: $pc leaks absolute build paths:" >&2
        grep -nE "$LEAKED_PATHS_RE" "$pc" >&2
        leak=1
    fi
done
if [[ $leak -ne 0 ]]; then exit 1; fi
echo "PASS pkg-config files have no leaked build paths"

# ---------------------------------------------------------------------------
# 7. MANIFEST.txt exists and is non-empty
# ---------------------------------------------------------------------------
if [[ ! -s "$STAGING/MANIFEST.txt" ]]; then
    echo "FAIL: MANIFEST.txt is missing or empty" >&2
    exit 1
fi
# Should mention the target and backend.
if ! grep -q "$TARGET" "$STAGING/MANIFEST.txt"; then
    echo "FAIL: MANIFEST.txt does not mention target '$TARGET'" >&2
    exit 1
fi
if ! grep -qi "$BACKEND" "$STAGING/MANIFEST.txt"; then
    echo "FAIL: MANIFEST.txt does not mention backend '$BACKEND'" >&2
    exit 1
fi
echo "PASS MANIFEST.txt present and references target+backend"

# ---------------------------------------------------------------------------
# 8. End-to-end compile + link + run
# ---------------------------------------------------------------------------
CONSUMER_SRC="$WORK/consumer.c"
cat > "$CONSUMER_SRC" <<'EOF'
#include <rnp/rnp.h>
#include <rnp/rnp_err.h>
#include <stdio.h>

int main(void) {
    rnp_ffi_t ffi = NULL;
    rnp_result_t r = rnp_ffi_create(&ffi, "GPG", "GPG");
    if (r != RNP_SUCCESS) {
        fprintf(stderr, "rnp_ffi_create failed: %u\n", (unsigned) r);
        return 2;
    }
    rnp_ffi_destroy(ffi);
    return 0;
}
EOF

CONSUMER_BIN="$WORK/consumer"

# Per-platform link flags come from the target config (TODO 02).
# Windows MSVC end-to-end is skipped (would require pwsh toolchain
# from bash); the build step already validated that the libraries
# compile and install.
if [[ "$NO_LINK" == "1" ]]; then
    echo "SKIP end-to-end link check (--no-link)"
    echo ""
    echo "ALL CHECKS PASSED (end-to-end skipped)"
    exit 0
fi

if [[ "$TARGET_OS" == "windows" ]]; then
    echo "SKIP end-to-end on Windows MSVC (would require pwsh toolchain from bash)"
    echo ""
    echo "ALL CHECKS PASSED (end-to-end skipped on Windows)"
    exit 0
fi
# shellcheck disable=SC2207 # word-splitting of $TARGET_PLATFORM_LINK is intentional
IFS=' ' read -r -a PLATFORM_LINK <<< "$TARGET_PLATFORM_LINK"

# Use pkg-config to resolve the per-backend link list. Fall back to
# BACKEND_LINK_LIBS from the backend config (TODO 01) if pkg-config
# isn't available.
LINK_FLAGS=()
if command -v pkg-config >/dev/null; then
    # shellcheck disable=SC2207 # pkg-config output is a flat argv; word-splitting is intentional
    IFS=' ' read -r -a LINK_FLAGS <<< "$(PKG_CONFIG_PATH="$STAGING/lib/pkgconfig" pkg-config --cflags --libs --static librnp 2>/dev/null || true)"
fi
if [[ ${#LINK_FLAGS[@]} -eq 0 ]]; then
    LINK_FLAGS=(-I"$STAGING/include" -L"$STAGING/lib")
    # shellcheck disable=SC2207 # BACKEND_LINK_LIBS is space-separated; word-splitting is intentional
    IFS=' ' read -r -a _backend_flags <<< "$BACKEND_LINK_LIBS"
    LINK_FLAGS+=("${_backend_flags[@]}")
fi

# shellcheck disable=SC2086 # legacy comment; array is now properly expanded
cc -I"$STAGING/include" \
   "$CONSUMER_SRC" -o "$CONSUMER_BIN" \
   "${LINK_FLAGS[@]}" \
   "${PLATFORM_LINK[@]}"
echo "PASS consumer compiles+links against tarball"

"$CONSUMER_BIN"
echo "PASS consumer runs and rnp_ffi_create returned RNP_SUCCESS"

echo ""
echo "ALL CHECKS PASSED: $TARBALL_BASENAME"

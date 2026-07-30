#!/usr/bin/env bash
# ci/build_prebuilt.sh
#
# Build a self-contained static-library tarball of librnp plus its full
# dependency stack (Botan or OpenSSL, json-c, zlib, bzip2, sexpp), suitable
# for attaching to a GitHub release as a prebuilt asset for downstream
# language bindings (Cargo, etc.) that cannot reach a system package
# manager.
#
# Usage:
#   ci/build_prebuilt.sh <backend> <version> <target> [workdir]
#
#   backend   : botan | openssl
#   version   : tag being released (e.g. v0.18.1)
#   target    : Rust-style target triple from the workflow matrix
#               (e.g. x86_64-unknown-linux-gnu). The script sanity-
#               checks that the host platform matches the target's
#               OS family but does NOT auto-detect; the matrix is
#               authoritative.
#   workdir   : scratch directory (default: ./prebuilt-work)
#
# Output:
#   $RNP_ARTIFACT_DIR/rnp-<version>-<target>-<backend>.tar.gz
#   $RNP_ARTIFACT_DIR/rnp-<version>-<target>-<backend>.sha256
#
# The script runs natively on the runner matching the target triple
# (no cross-compilation).

set -euxo pipefail

# Two invocation modes:
#
#   build_prebuilt.sh deps <target> [workdir]
#       Phase 1 (called by the build-deps CI job): build the common
#       deps (zlib, bzip2, json-c) into $WORK/prefix and stop. The
#       workflow uploads that prefix as an artifact so both per-backend
#       rnp jobs can reuse it without rebuilding.
#
#   build_prebuilt.sh rnp <backend> <version> <target> [workdir]
#       Phase 2 (called by the build-rnp CI job): expects deps already
#       installed in $WORK/prefix. Builds the backend (botan/openssl),
#       then rnp, then packages the tarball.
#
#   build_prebuilt.sh <backend> <version> <target> [workdir]
#       Backward-compat single-pass mode (no subcommand): builds
#       everything from scratch. Used for local testing without the
#       CI orchestration.
MODE=""
case "${1:-}" in
    deps)
        MODE="deps"
        shift
        TARGET="${1:?usage: build_prebuilt.sh deps <target> [workdir]}"
        WORK="${2:-$(pwd)/prebuilt-work}"
        BACKEND="_deps_only"   # not used in deps mode, but sourced config requires a value
        VERSION="deps-only"    # ditto
        ;;
    rnp)
        MODE="rnp"
        shift
        BACKEND="${1:?usage: build_prebuilt.sh rnp <botan|openssl> <version> <target> [workdir]}"
        VERSION="${2:?missing version (e.g. v0.18.1)}"
        TARGET="${3:?missing target triple (e.g. x86_64-unknown-linux-gnu)}"
        WORK="${4:-$(pwd)/prebuilt-work}"
        ;;
    *)
        BACKEND="${1:?usage: build_prebuilt.sh [<backend> <version> <target> [workdir]] | [deps <target>] | [rnp <backend> <version> <target>]}"
        VERSION="${2:?missing version (e.g. v0.18.1)}"
        TARGET="${3:?missing target triple (e.g. x86_64-unknown-linux-gnu)}"
        WORK="${4:-$(pwd)/prebuilt-work}"
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RNP_SRC="$(cd "${SCRIPT_DIR}/.." && pwd)"
RNP_ARTIFACT_DIR="${RNP_ARTIFACT_DIR:-${WORK}/artifacts}"

# ---------------------------------------------------------------------------
# Detect-once: host OS / arch, sha256 cmd, portable sed. Cached at the top
# so downstream code reads $HOST_OS instead of re-running uname on every
# branch, and uses ${SHA256_CMD[@]} / ${SED_INPLACE[@]} uniformly.
# ---------------------------------------------------------------------------
HOST_OS="$(uname -s)"
IS_DARWIN=0
[[ "$HOST_OS" == "Darwin" ]] && IS_DARWIN=1

if command -v sha256sum >/dev/null; then
    SHA256_CMD=(sha256sum)
elif command -v shasum >/dev/null; then
    SHA256_CMD=(shasum -a 256)
else
    echo "ERROR: no sha256 command found (need sha256sum or shasum)" >&2
    exit 1
fi

# Portable in-place sed. GNU sed accepts `sed -i` with no backup arg;
# BSD sed requires `sed -i ''`. Probe by checking the --version output.
if sed --version 2>&1 | grep -q "GNU sed"; then
    SED_INPLACE=(sed -i)
else
    SED_INPLACE=(sed -i '')
fi

# ---------------------------------------------------------------------------
# Source pinned dep versions (ci/prebuilt-versions.env), backend config
# (ci/backends/<name>.env), and target config (ci/targets/<triple>.env).
# All three are the single source of truth for their respective slices.
# Adding a backend or target = adding a file; no edits to this script.
# ---------------------------------------------------------------------------

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/prebuilt-versions.env"
: "${ZLIB_VERSION:?missing in prebuilt-versions.env}"
: "${BZIP2_VERSION:?missing in prebuilt-versions.env}"
: "${JSONC_VERSION:?missing in prebuilt-versions.env}"
: "${BOTAN_VERSION:?missing in prebuilt-versions.env}"
: "${OPENSSL_VERSION:?missing in prebuilt-versions.env}"

# Backend config is only needed in rnp and single-pass mode; deps mode
# builds no backend-specific code.
if [[ "$MODE" != "deps" ]]; then
    BACKEND_CONFIG="${SCRIPT_DIR}/backends/${BACKEND}.env"
    if [[ ! -f "$BACKEND_CONFIG" ]]; then
        echo "ERROR: unknown backend '$BACKEND' -- expected config at $BACKEND_CONFIG" >&2
        echo "  Valid backends:" >&2
        (cd "${SCRIPT_DIR}/backends" && find . -maxdepth 1 -name '*.env' -exec sh -c 'for f; do echo "    $(basename "$f" .env)"; done' _ {} +) >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$BACKEND_CONFIG"
fi

TARGET_CONFIG="${SCRIPT_DIR}/targets/${TARGET}.env"
if [[ ! -f "$TARGET_CONFIG" ]]; then
    echo "ERROR: unknown target '$TARGET' -- expected config at $TARGET_CONFIG" >&2
    echo "  Valid targets:" >&2
    (cd "${SCRIPT_DIR}/targets" && find . -maxdepth 1 -name '*.env' -exec sh -c 'for f; do echo "    $(basename "$f" .env)"; done' _ {} +) >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$TARGET_CONFIG"

# ---------------------------------------------------------------------------
# Sanity-check: the target config's OS family must match the host
# platform. Catches mismatched (target, runner) matrix entries at
# build time so the tarball name doesn't lie about its contents.
# ---------------------------------------------------------------------------
case "$TARGET_OS" in
    linux)   [[ "$HOST_OS" == "Linux" ]]   || { echo "ERROR: target '$TARGET' (TARGET_OS=$TARGET_OS) requires Linux host" >&2; exit 1; } ;;
    darwin)  [[ "$HOST_OS" == "Darwin" ]]  || { echo "ERROR: target '$TARGET' (TARGET_OS=$TARGET_OS) requires macOS host" >&2; exit 1; } ;;
    windows) [[ "$HOST_OS" == MINGW* || "$HOST_OS" == MSYS* || "$HOST_OS" == CYGWIN* ]] || { echo "ERROR: target '$TARGET' (TARGET_OS=$TARGET_OS) requires Windows host" >&2; exit 1; } ;;
    *) echo "ERROR: unrecognized TARGET_OS='$TARGET_OS' in $TARGET_CONFIG (expected linux|darwin|windows)" >&2; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Global build flags. -fPIC is here (single source of truth, TODO 09) so
# the static archives can be linked into shared libraries downstream;
# -O2 for size/perf balance. macOS deployment target comes from the
# target config (TODO 02) so it's per-arch-correct (11.0 Intel vs 12.0
# Apple Silicon) instead of probed via uname.
# ---------------------------------------------------------------------------
export CFLAGS="${CFLAGS:-} -O2 -fPIC"
export CXXFLAGS="${CXXFLAGS:-} -O2 -fPIC"
if [[ -n "$TARGET_DEPLOY_TARGET" ]]; then
    export MACOSX_DEPLOYMENT_TARGET="$TARGET_DEPLOY_TARGET"
fi

# Detect CPU count for parallel make. macOS doesn't ship `nproc`;
# `sysctl -n hw.ncpu` is the BSD equivalent.
if [[ "$IS_DARWIN" == "1" ]]; then
    NPROC="$(sysctl -n hw.ncpu)"
else
    NPROC="$(nproc)"
fi

# Pin build time to the Unix epoch so that tools which embed build
# timestamps (gzip header, libtool archives, some debug info, Python
# bytecode in json-c, etc.) produce identical output across runs on the
# same platform. Consumers can verify reproducibility by rebuilding.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

# Set up scratch directories. Each dependency is built into $PREFIX; rnp
# is then configured against $PREFIX and installs into it as well.
mkdir -p "$WORK" "$WORK/src"
PREFIX="$WORK/prefix"
rm -rf "$PREFIX"
mkdir -p "$PREFIX/include" "$PREFIX/lib"
mkdir -p "$RNP_ARTIFACT_DIR"

# Source the GPG signing helper. sign_file() is called in package()
# for both MANIFEST.txt and the tarball.
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/sign.sh"

# Download a URL to a destination file, skipping if already present.
download() {
    local url="$1" dest="$2"
    if [[ -f "$dest" ]]; then
        echo "Cached: $dest"
        return
    fi
    echo "Downloading: $url"
    curl -fSL --retry 3 "$url" -o "$dest"
}

# Build zlib as a static library.
# Each build_xxx function below is idempotent: if the dep is already
# installed in $PREFIX (e.g. restored from the actions/cache), the
# function returns immediately. The cache key in prebuilt.yml includes
# the dep versions, so a bump in prebuilt-versions.env invalidates the
# cache and forces a fresh build.

build_zlib() {
    [[ -f "$PREFIX/lib/libz.a" ]] && { echo "=== zlib cached ==="; return; }
    echo "=== zlib $ZLIB_VERSION ==="
    cd "$WORK/src"
    download "https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz" "zlib-$ZLIB_VERSION.tar.gz"
    rm -rf "zlib-$ZLIB_VERSION"
    tar xzf "zlib-$ZLIB_VERSION.tar.gz"
    cd "zlib-$ZLIB_VERSION"
    ./configure --static --prefix="$PREFIX"
    make -j"$NPROC" install
}

# Build bzip2 as a static library. bzip2 has no cmake or autotools — its
# upstream Makefile is the canonical build system.
build_bzip2() {
    [[ -f "$PREFIX/lib/libbz2.a" ]] && { echo "=== bzip2 cached ==="; return; }
    echo "=== bzip2 $BZIP2_VERSION ==="
    cd "$WORK/src"
    download "https://sourceware.org/pub/bzip2/bzip2-$BZIP2_VERSION.tar.gz" "bzip2-$BZIP2_VERSION.tar.gz"
    rm -rf "bzip2-$BZIP2_VERSION"
    tar xzf "bzip2-$BZIP2_VERSION.tar.gz"
    cd "bzip2-$BZIP2_VERSION"
    make -j"$NPROC" CC="${CC:-cc}" CFLAGS="$CFLAGS" libbz2.a
    install -m644 libbz2.a "$PREFIX/lib/"
    install -m644 bzlib.h "$PREFIX/include/"
}

# Build json-c as a static library.
build_jsonc() {
    [[ -f "$PREFIX/lib/libjson-c.a" ]] && { echo "=== json-c cached ==="; return; }
    echo "=== json-c $JSONC_VERSION ==="
    cd "$WORK/src"
    download "https://s3.amazonaws.com/json-c_releases/releases/json-c-$JSONC_VERSION.tar.gz" "json-c-$JSONC_VERSION.tar.gz"
    rm -rf "json-c-$JSONC_VERSION"
    tar xzf "json-c-$JSONC_VERSION.tar.gz"
    rm -rf "json-c-$JSONC_VERSION/build"
    mkdir -p "json-c-$JSONC_VERSION/build"
    cd "json-c-$JSONC_VERSION/build"
    cmake -DCMAKE_INSTALL_PREFIX="$PREFIX" \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=OFF \
          -DBUILD_TESTING=OFF \
          -DENABLE_THREAD_SAFE=ON \
          ..
    make -j"$NPROC" install
}

# Build Botan as a static library, with the module set curated for rnp
# (includes PQC modules so ENABLE_PQC works downstream).
build_botan() {
    [[ -f "$PREFIX/lib/libbotan-3.a" ]] && { echo "=== Botan cached ==="; return; }
    echo "=== Botan $BOTAN_VERSION ==="
    cd "$WORK/src"
    download "https://botan.randombit.net/releases/Botan-$BOTAN_VERSION.tar.xz" "Botan-$BOTAN_VERSION.tar.xz"
    rm -rf "Botan-$BOTAN_VERSION"
    tar xJf "Botan-$BOTAN_VERSION.tar.xz"
    cd "Botan-$BOTAN_VERSION"
    local module_file="$SCRIPT_DIR/botan3-pqc-modules"
    local modules
    modules="$(tr '\n' ',' < "$module_file" | sed 's/,$//')"
    # Let Botan auto-detect the compiler family. Earlier iterations
    # tried to pass --cc / --cc-bin explicitly, but the family
    # detection via `${CXX:-c++} --version | grep -i clang` is
    # unreliable across distros (Ubuntu's c++ sometimes shows clang
    # in unexpected places), and passing the wrong family makes
    # Botan add compiler-specific flags (e.g. -Wshorten-64-to-32)
    # that the actual compiler then rejects. Auto-detection is
    # robust; we still pass --cc-abi-flags for our -O2 -fPIC.
    python3 ./configure.py \
        --cc-abi-flags="$CXXFLAGS" \
        --build-targets=static \
        --disable-shared-library \
        --without-documentation \
        --minimized-build \
        --enable-modules="$modules" \
        --prefix="$PREFIX"
    make -j"$NPROC"
    make install
}

# Build OpenSSL as a static library (no-shared, no-tests).
build_openssl() {
    [[ -f "$PREFIX/lib/libcrypto.a" ]] && { echo "=== OpenSSL cached ==="; return; }
    echo "=== OpenSSL $OPENSSL_VERSION ==="
    cd "$WORK/src"
    download "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz" "openssl-$OPENSSL_VERSION.tar.gz"
    rm -rf "openssl-$OPENSSL_VERSION"
    tar xzf "openssl-$OPENSSL_VERSION.tar.gz"
    cd "openssl-$OPENSSL_VERSION"
    # TARGET_OPENSSL_CC is from the target config (e.g.
    # "linux-x86_64", "darwin64-arm64-cc"). Empty on Windows (which
    # uses vcpkg and skips this function entirely).
    if [[ -z "$TARGET_OPENSSL_CC" ]]; then
        echo "ERROR: target '$TARGET' has no TARGET_OPENSSL_CC set in $TARGET_CONFIG" >&2
        echo "  (Windows targets use vcpkg and don't call build_openssl.)" >&2
        exit 1
    fi
    ./Configure "$TARGET_OPENSSL_CC" \
        no-shared no-tests \
        --prefix="$PREFIX" --libdir=lib
    make -j"$NPROC"
    make install_sw install_ssldirs
}

# Build librnp itself as a static library, configured against $PREFIX.
build_rnp() {
    echo "=== rnp $VERSION (backend: $BACKEND) ==="
    local bld="$WORK/rnp-build"
    rm -rf "$bld"
    mkdir -p "$bld"
    cd "$bld"
    # BACKEND_CMAKE_FLAGS comes from the backend config (e.g.
    # "-DENABLE_PQC=ON" for botan, empty for openssl). Split on
    # whitespace into an array so cmake sees each token as a separate
    # argv element.
    # BACKEND_CMAKE_FLAGS comes from the backend config (e.g.
    # "-DENABLE_PQC=ON" for botan, empty for openssl). Split on
    # whitespace into an array. Guard the expansion with the
    # ${arr[@]+"${arr[@]}"} pattern so bash 3.2 (macOS system bash)
    # doesn't throw "unbound variable" when the array is empty.
    local backend_flags_str="${BACKEND_CMAKE_FLAGS:-}"
    if [[ -n "$backend_flags_str" ]]; then
        # shellcheck disable=SC2206 # word-splitting is intentional for flag list
        local -a backend_flags=($backend_flags_str)
    else
        local -a backend_flags=()
    fi
    # ccache auto-detection: if ccache is in PATH, wire it into the
    # rnp build. Dramatically speeds up incremental rebuilds on CI.
    # The dep stack is already cached via actions/cache; ccache covers
    # just the rnp sources.
    local -a cc_launcher=()
    if command -v ccache >/dev/null 2>&1; then
        cc_launcher+=(
            -DCMAKE_C_COMPILER_LAUNCHER=ccache
            -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
        )
    fi
    cmake "$RNP_SRC" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTING=OFF \
        -DCRYPTO_BACKEND="$BACKEND" \
        -DCMAKE_PREFIX_PATH="$PREFIX" \
        "${backend_flags[@]+"${backend_flags[@]}"}" \
        "${cc_launcher[@]+"${cc_launcher[@]}"}"
    make -j"$NPROC" install
}

# Stage the install prefix into a release-ready tarball layout, omitting
# runtime-only files (shared libs, executables, manual pages, etc.).
package() {
    echo "=== packaging ==="
    local tarball_name="rnp-$VERSION-$TARGET-$BACKEND"
    local staging="$WORK/$tarball_name"
    rm -rf "$staging"
    mkdir -p "$staging/include" "$staging/lib"

    # Headers from every dependency.
    cp -a "$PREFIX/include/." "$staging/include/"

    # Static archives only — no .so, .dylib, .dll, executables.
    if compgen -G "$PREFIX/lib/*.a" > /dev/null; then
        cp -a "$PREFIX/lib/"*.a "$staging/lib/"
    fi
    # On Windows the static archives are .lib; keep them too.
    if compgen -G "$PREFIX/lib/*.lib" > /dev/null; then
        cp -a "$PREFIX/lib/"*.lib "$staging/lib/"
    fi

    # CMake config + pkg-config so downstream build systems can find_package(rnp)
    # or pkg-config --libs rnp.
    if [[ -d "$PREFIX/lib/cmake" ]]; then
        mkdir -p "$staging/lib/cmake"
        cp -a "$PREFIX/lib/cmake/." "$staging/lib/cmake/"
    fi
    if [[ -d "$PREFIX/lib/pkgconfig" ]]; then
        mkdir -p "$staging/lib/pkgconfig"
        cp -a "$PREFIX/lib/pkgconfig/." "$staging/lib/pkgconfig/"
        # The .pc files installed above contain the absolute build prefix
        # (e.g. prefix=/tmp/.../work/prefix). Replace it everywhere with
        # a pcfiledir-relative path so consumers can re-root the bundle
        # without editing the files. pkg-config interprets ${pcfiledir}
        # as the directory containing the .pc file; the bundle layout is
        # <root>/lib/pkgconfig/<name>.pc, so ${pcfiledir}/../.. is the
        # bundle root.
        # shellcheck disable=SC2016  # ${pcfiledir} is pkg-config syntax, not shell
        local rel_prefix='${pcfiledir}/../..'
        for pc in "$staging/lib/pkgconfig"/*.pc; do
            [[ -f "$pc" ]] || continue
            # Skip files that have no absolute build paths to rewrite.
            grep -q "$PREFIX" "$pc" || continue
            "${SED_INPLACE[@]}" -e "s|$PREFIX|$rel_prefix|g" "$pc"
            # Ensure prefix=/exec_prefix=/libdir=/includedir use the
            # canonical pkg-config variables, even if the original file
            # used non-standard layout.
            "${SED_INPLACE[@]}" \
                -e "s|^prefix=.*|prefix=${rel_prefix}|" \
                -e "s|^exec_prefix=.*|exec_prefix=\${prefix}|" \
                -e "s|^libdir=.*|libdir=\${prefix}/lib|" \
                -e "s|^includedir=.*|includedir=\${prefix}/include|" \
                "$pc"
        done
    fi

    # MANIFEST.txt: human-readable summary of what's in the tarball and
    # how to link against it. All backend-specific and target-specific
    # text comes from the config files; this template has zero
    # conditionals.
    local link_libs="$BACKEND_LINK_LIBS"
    local platform_link=""
    if [[ -n "$TARGET_PLATFORM_LINK" ]]; then
        platform_link="  * On $TARGET_OS also link: $TARGET_PLATFORM_LINK"
    fi
    cat > "$staging/MANIFEST.txt" <<EOF
rnp $VERSION — prebuilt static library bundle

Target:     $TARGET ($TARGET_DESCRIPTION)
Backend:    $BACKEND ($BACKEND_DESCRIPTION)
Build host: $(uname -srm)

Contents
--------
  include/rnp/                  public FFI headers (rnp.h, rnp_err.h, rnp_export.h, rnp_ver.h)
  include/$BACKEND_HEADERS_DIR/ backend headers
  include/json-c/               json-c headers
  include/bzlib.h               bzip2 header
  include/zlib.h                zlib header
$(
    # Generate one line per static archive declared in
    # BACKEND_LIB_NAMES (from the backend config). No backend-
    # specific text inlined here.
    IFS=',' read -ra _libs <<< "$BACKEND_LIB_NAMES"
    for lib in "${_libs[@]}"; do
        printf '  lib/%s%s  static archive\n' "$lib" "$TARGET_ARCHIVE_EXT"
    done
)
  lib/cmake/rnp/                CMake config (find_package(rnp))
  lib/pkgconfig/                pkg-config files

Linking
-------
Add include/ to your compiler's header search path, add lib/ to your
linker's library search path, then link:
  $link_libs
$platform_link

Source
------
Produced by ci/build_prebuilt.sh in the rnp repository
(https://github.com/rnpgp/rnp). Dependency versions used:
  zlib     $ZLIB_VERSION
  bzip2    $BZIP2_VERSION
  json-c   $JSONC_VERSION
EOF

    sign_file "$staging/MANIFEST.txt"

    # Tarball. Use gzip for max portability (zstd/xz are smaller but
    # require newer tooling on the consumer side).
    #
    # Reproducibility notes:
    #   * GZIP=-n suppresses the original filename and mtime in the gzip
    #     header — portable across gzip implementations.
    #   * tarball contents (the .a archives) are reproducible on a given
    #     platform: same compiler, same libc, same SOURCE_DATE_EPOCH =>
    #     byte-identical archives.
    #   * Archive-level metadata (per-entry mtime, uid/gid, file modes)
    #     is NOT normalized: BSD tar (macOS) lacks GNU tar's --owner /
    #     --mtime / --mode flags, so a portable normalization would
    #     require a Python tarfile wrapper. Filed as follow-up.
    GZIP="-n" tar -czf "$RNP_ARTIFACT_DIR/$tarball_name.tar.gz" \
        -C "$WORK" "$tarball_name"

    # sha256 sidecar, in the format GitHub releases + sha256sum -c
    # expect. SHA256_CMD is detected once at the top of the script
    # (TODO 05).
    (cd "$RNP_ARTIFACT_DIR" && "${SHA256_CMD[@]}" "$tarball_name.tar.gz" > "$tarball_name.sha256")

    sign_file "$RNP_ARTIFACT_DIR/$tarball_name.tar.gz"

    echo
    echo "=== Built: $RNP_ARTIFACT_DIR/$tarball_name.tar.gz ==="
    ls -la "$RNP_ARTIFACT_DIR/$tarball_name.tar.gz"
}

case "$MODE" in
    deps)
        # Phase 1: common deps only. Backend and rnp builds belong to
        # the per-backend Phase 2 jobs, which download this prefix.
        build_zlib
        build_bzip2
        build_jsonc
        echo
        echo "=== Phase 1 (deps) complete: $PREFIX ==="
        ls -la "$PREFIX/lib/"
        ;;
    rnp)
        # Phase 2: deps expected in $PREFIX (restored from the Phase 1
        # artifact). If they aren't there — e.g. because the deps fan-
        # out couldn't run on this target (alpine+ARM64 disallows JS
        # actions, so build-deps neither cached nor uploaded an
        # artifact) — build the common deps inline as a fallback. This
        # is the same work the monolithic single-pass mode does, so
        # the cost is identical to the no-fan-out baseline.
        if [ ! -f "$PREFIX/lib/libz.a" ]; then
            echo "WARNING: $PREFIX/lib/libz.a missing; building common deps inline." >&2
            build_zlib
            build_bzip2
            build_jsonc
        fi
        case "$BACKEND" in
            botan)   build_botan ;;
            openssl) build_openssl ;;
            *) echo "ERROR: unknown backend '$BACKEND'" >&2; exit 1 ;;
        esac
        build_rnp
        package
        ;;
    *)
        # Backward-compat single-pass mode.
        build_zlib
        build_bzip2
        build_jsonc
        case "$BACKEND" in
            botan)   build_botan ;;
            openssl) build_openssl ;;
            *) echo "ERROR: unknown backend '$BACKEND'" >&2; exit 1 ;;
        esac
        build_rnp
        package
        ;;
esac

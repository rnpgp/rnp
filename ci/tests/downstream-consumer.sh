#! /bin/bash
#
# Copyright (c) 2025 [Ribose Inc](https://www.ribose.com).
# All rights reserved.
# This file is a part of rnp
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

set -o errexit -o pipefail -o noclobber -o nounset

DIR0="$( cd "$( dirname "$0" )" && pwd )"
RNP_ROOT="$( cd "$DIR0"/../.. && pwd )"

# Smoke test for downstream consumers: builds and installs rnp (shared and
# static) into temporary prefixes and then builds a tiny C program, which
# calls rnp_ffi_create()/rnp_version_string()/rnp_ffi_destroy(), against
# each installation in three ways:
#
#   1. CMake, via find_package(rnp) and the rnp::librnp target
#   2. pkg-config, via the installed librnp.pc
#   3. raw compiler flags (-I/-L/-lrnp)
#
# For the static installation this exercises the transitive dependency
# propagation (crypto backend, JSON-C, zlib, bzip2, sexpp).
#
# Overridable environment:
#   WORK_DIR               - build/install scratch dir (default: mktemp)
#   CRYPTO_BACKEND         - backend rnp is built with (default: botan3)
#   CMAKE_DEPS_PREFIX_PATH - ';'-separated extra CMAKE_PREFIX_PATH entries
#                            used to locate rnp's dependencies (e.g.
#                            "/opt/homebrew/opt/botan@3;/opt/homebrew/opt/json-c")
#   SEXPP_PREFIX           - prefix of a sexpp installation, appended to
#                            CMAKE_PREFIX_PATH for the static consumers
#   RAW_DEP_LIBS           - extra libraries for the raw-flags static
#                            consumer (default: derived from the above)
#   KEEP_WORK_DIR          - set to 1 to keep WORK_DIR afterwards

: "${CRYPTO_BACKEND:=botan3}"
: "${CMAKE_DEPS_PREFIX_PATH:=}"
: "${SEXPP_PREFIX:=}"
: "${KEEP_WORK_DIR:=}"

CREATED_WORK_DIR=""
if [[ -z "${WORK_DIR:-}" ]]; then
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rnp-downstream.XXXXXX")"
    CREATED_WORK_DIR=1
fi

cleanup() {
    if [[ -n "$CREATED_WORK_DIR" && -z "$KEEP_WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

# Extra linker flags for the raw-flags static consumer: librnp.a does not
# carry its dependencies, so the consumer has to name them explicitly.
default_raw_dep_libs() {
    local libs="" prefix
    local IFS=';'
    for prefix in $CMAKE_DEPS_PREFIX_PATH; do
        [[ ! -d "$prefix/lib" ]] || libs="$libs -L$prefix/lib"
    done
    [[ -z "$SEXPP_PREFIX" ]] || libs="$libs -L$SEXPP_PREFIX/lib"
    case "$CRYPTO_BACKEND" in
        botan3)  libs="$libs -lbotan-3" ;;
        botan)   libs="$libs -lbotan-2" ;;
        openssl) libs="$libs -lcrypto" ;;
    esac
    printf '%s' "$libs -ljson-c -lz -lbz2"
}

write_consumer() {
    mkdir -p "$WORK_DIR/consumer"
    cat >| "$WORK_DIR/consumer/main.c" <<'EOF'
#include <stdio.h>

#include <rnp/rnp.h>
#include <rnp/rnp_err.h>

int
main(void)
{
    rnp_ffi_t ffi = NULL;
    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS) {
        fprintf(stderr, "rnp_ffi_create failed\n");
        return 1;
    }
    printf("librnp version: %s\n", rnp_version_string());
    rnp_ffi_destroy(ffi);
    return 0;
}
EOF
    cat >| "$WORK_DIR/consumer/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.18)
# CXX is enabled so that the C++ runtime is linked when librnp is a static
# library (librnp itself is written in C++).
project(rnp-consumer C CXX)

find_package(rnp REQUIRED)

add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE rnp::librnp)
EOF
}

build_rnp() {
    local linkage="$1" prefix="$2" shared_libs=ON
    [[ "$linkage" == shared ]] || shared_libs=OFF
    cmake -S "$RNP_ROOT" -B "$WORK_DIR/build-$linkage" \
        -DBUILD_SHARED_LIBS="$shared_libs" \
        -DCRYPTO_BACKEND="$CRYPTO_BACKEND" \
        -DBUILD_TESTING=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$prefix" \
        -DCMAKE_PREFIX_PATH="$CMAKE_DEPS_PREFIX_PATH"
    cmake --build "$WORK_DIR/build-$linkage" --parallel
    cmake --install "$WORK_DIR/build-$linkage"
}

cmake_prefix_path_for() {
    local prefix_path="$1"
    [[ -z "$CMAKE_DEPS_PREFIX_PATH" ]] || prefix_path="$prefix_path;$CMAKE_DEPS_PREFIX_PATH"
    if [[ "$2" == static && -n "$SEXPP_PREFIX" ]]; then
        prefix_path="$prefix_path;$SEXPP_PREFIX"
    fi
    printf '%s' "$prefix_path"
}

test_cmake_consumer() {
    local prefix="$1" linkage="$2"
    local build_dir="$WORK_DIR/consumer-cmake-$linkage"
    cmake -S "$WORK_DIR/consumer" -B "$build_dir" \
        -DCMAKE_PREFIX_PATH="$(cmake_prefix_path_for "$prefix" "$linkage")"
    cmake --build "$build_dir"
    "$build_dir/consumer"
}

pc_dir() {
    local pc
    pc="$(find "$1" -name librnp.pc -print -quit)"
    if [[ -z "$pc" ]]; then
        echo "librnp.pc not found under $1" >&2
        return 1
    fi
    dirname "$pc"
}

test_pkgconfig_consumer() {
    local prefix="$1" linkage="$2"
    local pcdir libdir cflags libs static_opt=""
    pcdir="$(pc_dir "$prefix")"
    libdir="$(dirname "$pcdir")"
    [[ "$linkage" != static ]] || static_opt="--static"
    cflags="$(PKG_CONFIG_PATH="$pcdir" pkg-config --cflags librnp)"
    # shellcheck disable=SC2086
    libs="$(PKG_CONFIG_PATH="$pcdir" pkg-config --libs $static_opt librnp)"
    # librnp is a C++ library, so link with the C++ driver.
    # shellcheck disable=SC2086
    "${CC:-cc}" $cflags -c "$WORK_DIR/consumer/main.c" -o "$WORK_DIR/consumer-pkgconfig-$linkage.o"
    # shellcheck disable=SC2086
    "${CXX:-c++}" "$WORK_DIR/consumer-pkgconfig-$linkage.o" $libs \
        -Wl,-rpath,"$libdir" -o "$WORK_DIR/consumer-pkgconfig-$linkage"
    "$WORK_DIR/consumer-pkgconfig-$linkage"
}

test_raw_consumer() {
    local prefix="$1" linkage="$2"
    local libdir
    libdir="$(dirname "$(pc_dir "$prefix")")"
    if [[ "$linkage" == shared ]]; then
        "${CC:-cc}" -I"$prefix/include" "$WORK_DIR/consumer/main.c" \
            -L"$libdir" -lrnp -Wl,-rpath,"$libdir" \
            -o "$WORK_DIR/consumer-raw-$linkage"
    else
        # librnp.a does not carry its dependencies: name them explicitly and
        # link with the C++ driver (librnp itself is written in C++).
        "${CC:-cc}" -I"$prefix/include" -c "$WORK_DIR/consumer/main.c" \
            -o "$WORK_DIR/consumer-raw-$linkage.o"
        # shellcheck disable=SC2086
        "${CXX:-c++}" "$WORK_DIR/consumer-raw-$linkage.o" \
            -L"$libdir" -lrnp -lsexpp $RAW_DEP_LIBS -Wl,-rpath,"$libdir" \
            -o "$WORK_DIR/consumer-raw-$linkage"
    fi
    "$WORK_DIR/consumer-raw-$linkage"
}

main() {
    if [[ ! -f "$RNP_ROOT/src/libsexpp/CMakeLists.txt" ]]; then
        echo "The src/libsexpp submodule is empty, run: git submodule update --init" >&2
        exit 1
    fi
    : "${RAW_DEP_LIBS:=$(default_raw_dep_libs)}"
    write_consumer
    local linkage prefix
    for linkage in shared static; do
        prefix="$WORK_DIR/$linkage"
        echo "==> Building and installing rnp ($linkage) to $prefix"
        build_rnp "$linkage" "$prefix"
        echo "==> Testing CMake find_package(rnp) consumer ($linkage)"
        test_cmake_consumer "$prefix" "$linkage"
        echo "==> Testing pkg-config consumer ($linkage)"
        test_pkgconfig_consumer "$prefix" "$linkage"
        echo "==> Testing raw-flags consumer ($linkage)"
        test_raw_consumer "$prefix" "$linkage"
    done
    echo "All downstream consumer checks passed."
}

main "$@"

#!/bin/sh
set -ex

export PATH=/usr/local/bin:$PATH
export LOCAL_BUILDS=${WORKSPACE}/local-builds
export BOTAN_INSTALL="${LOCAL_BUILDS}/builds/botan-install"
export CMOCKA_INSTALL="${LOCAL_BUILDS}/builds/cmocka-install"
export JSONC_INSTALL="${LOCAL_BUILDS}/builds/json-c-install"
export GPG_INSTALL="${LOCAL_BUILDS}/builds/gpg-install"
export BUILD_MODE=normal
export CLANG_FORMAT_DIFF="clang-format-diff-4.0"
export CC=clang
export MAKE=gmake

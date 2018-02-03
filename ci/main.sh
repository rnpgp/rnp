#!/bin/bash
set -eux

[ "$BUILD_MODE" = "style-check" ] && exec ci/style-check.sh

: "${CORES:=2}"

LD_LIBRARY_PATH="${BOTAN_INSTALL}/lib:${CMOCKA_INSTALL}/lib:${JSONC_INSTALL}/lib"
CFLAGS=""

[ "$BUILD_MODE" = "coverage" ] && CFLAGS+=" -O0 --coverage"

# CFLAGS for sanitize and sanitize-leaks
[ "$BUILD_MODE" = "sanitize" -o "$BUILD_MODE" = "sanitize-leaks" ] && CFLAGS+=" \
 -fsanitize=leak,address,undefined   \
 -fno-omit-frame-pointer             \
 -fno-common"

# No leak detection for main sanitize run (only for sanitize-leaks)
[ "$BUILD_MODE" = "sanitize" ] && export ASAN_OPTIONS=detect_leaks=0

export LD_LIBRARY_PATH CFLAGS

autoreconf -vfi
./configure \
  --with-botan=${BOTAN_INSTALL} \
  --with-jsonc=${JSONC_INSTALL} \
  --with-cmocka=${CMOCKA_INSTALL}
make clean
make -j${CORES}

: "${COVERITY_SCAN_BRANCH:=0}"
[[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

cd src/tests
./rnp_tests

LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${GPG_INSTALL}/lib"
export LD_LIBRARY_PATH
env RNPC_GPG_PATH="${GPG_INSTALL}/bin/gpg" RNPC_GPGCONF_PATH="${GPG_INSTALL}/bin/gpgconf" python2 cli_tests.py -w -v -d


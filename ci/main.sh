#!/bin/bash
set -eux

[ "$BUILD_MODE" = "style-check" ] && exec ci/style-check.sh

: "${CORES:=2}"
: "${RNP_TESTS:=all}"

[ "$BUILD_MODE" = "coverage" ] && CFLAGS+=" -O0 --coverage"

# CFLAGS for sanitize
[ "$BUILD_MODE" = "sanitize" ] && CFLAGS+=" \
 -O1                                 \
 -fsanitize=leak,address,undefined   \
 -fno-omit-frame-pointer             \
 -fno-common"

export CFLAGS

srcdir="$PWD"
mkdir "${LOCAL_BUILDS}/rnp-build"
pushd "${LOCAL_BUILDS}/rnp-build"
export LD_LIBRARY_PATH="${GPG_INSTALL}/lib"
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_PREFIX_PATH="${BOTAN_INSTALL};${CMOCKA_INSTALL};${JSONC_INSTALL};${GPG_INSTALL}" \
      -Dcmocka_DIR="${CMOCKA_INSTALL}/cmocka" \
      "$srcdir"
make -j${CORES} VERBOSE=1

: "${COVERITY_SCAN_BRANCH:=0}"
[[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

case "$RNP_TESTS" in
  cmocka)
    ctest -R rnp_tests --output-on-failure
    ;;
  cli)
    ctest -R cli_tests --output-on-failure
    ;;
  all)
    ctest -j${CORES} --output-on-failure
    ;;
  *) exit 1 ;;
esac

exit 0


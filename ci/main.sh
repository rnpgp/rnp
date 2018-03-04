#!/bin/bash
set -eux

[ "$BUILD_MODE" = "style-check" ] && exec ci/style-check.sh

: "${CORES:=2}"
: "${RNP_TESTS:=all}"

LD_LIBRARY_PATH="${BOTAN_INSTALL}/lib:${CMOCKA_INSTALL}/lib:${JSONC_INSTALL}/lib:${GPG_INSTALL}/lib"

[ "$BUILD_MODE" = "coverage" ] && CFLAGS+=" -O0 --coverage"

# CFLAGS for sanitize
[ "$BUILD_MODE" = "sanitize" ] && CFLAGS+=" \
 -O1                                 \
 -fsanitize=leak,address,undefined   \
 -fno-omit-frame-pointer             \
 -fno-common"

export LD_LIBRARY_PATH CFLAGS

autoreconf -vfi
./configure \
  --with-botan="${BOTAN_INSTALL}" \
  --with-jsonc="${JSONC_INSTALL}" \
  --with-cmocka="${CMOCKA_INSTALL}"
make clean
make -j${CORES}

: "${COVERITY_SCAN_BRANCH:=0}"
[[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

cd src/tests
run_cmocka=false
run_cli=false
case "$RNP_TESTS" in
  cmocka)
    run_cmocka=true
    ;;
  cli)
    run_cli=true
    ;;
  all)
    run_cmocka=true
    run_cli=true
    ;;
  *) exit 1 ;;
esac

[[ $run_cmocka = true ]] && ./rnp_tests
[[ $run_cli = true ]] && \
  env RNPC_GPG_PATH="${GPG_INSTALL}/bin/gpg" \
      RNPC_GPGCONF_PATH="${GPG_INSTALL}/bin/gpgconf" \
      python2 cli_tests.py -w -v -d

exit 0


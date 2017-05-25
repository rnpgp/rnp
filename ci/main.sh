#!/bin/bash
set -eu

LD_LIBRARY_PATH="${BOTAN_INSTALL}/lib:${CMOCKA_INSTALL}/lib"
LDFLAGS="-L${CMOCKA_INSTALL}/lib"
CFLAGS="-I${CMOCKA_INSTALL}/include"

[ "$BUILD_MODE" = "coverage" ] && CFLAGS+=" -O0 --coverage"
[ "$BUILD_MODE" = "sanitize" ] && CFLAGS+=" -fsanitize=leak,address,undefined"

export LD_LIBRARY_PATH CFLAGS LDFLAGS

autoreconf -vfi
./configure --with-botan=${BOTAN_INSTALL}
make -j2

: "${COVERITY_SCAN_BRANCH:=0}"
[[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

cd src/cmocka
./rnp_tests


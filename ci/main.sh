#!/bin/bash
set -eu

LD_LIBRARY_PATH="${BOTAN_INSTALL}/lib:${CMOCKA_INSTALL}/lib"

CFLAGS="--std=c11 -D_GNU_SOURCE -I${CMOCKA_INSTALL}/include"
CFLAGS+=" -O0 --coverage"
CFLAGS+=" -fsanitize=leak,address,undefined"

LDFLAGS="-L${CMOCKA_INSTALL}/lib"

export LD_LIBRARY_PATH CFLAGS LDFLAGS
autoreconf -vfi
./configure --with-botan=${BOTAN_INSTALL}
make
cd src/cmocka
./rnp_tests


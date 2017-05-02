#!/bin/bash
set -eu

export LD_LIBRARY_PATH=~/builds/botan-install/lib:~/builds/cmocka-install/lib

CFLAGS="--std=c11"
CFLAGS+=" -I/home/travis/builds/cmocka-install/include"
CFLAGS+=" -D_GNU_SOURCE"
CFLAGS+=" -fsanitize=leak -fsanitize=address -fsanitize=undefined"
export CFLAGS

export LDFLAGS="-L/home/travis/builds/cmocka-install/lib"
autoreconf -vfi
./configure --with-botan=/home/travis/builds/botan-install && make && src/cmocka/rnp_tests


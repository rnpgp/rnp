#!/bin/bash

cd /usr/local/rnp

ACFLAGS=--with-botan=/usr/local
LD_LIBRARY_PATH=/usr/lib:/usr/local/lib

packaging/redhat/extra/prepare_build.sh
./build.sh
make install

rnp_tests


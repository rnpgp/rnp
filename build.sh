#!/bin/bash
#
# (c) 2017 Ribose Inc.
#

autoreconf -ivf
pushd src/netpgpverify
./configure --mandir=/usr/share/man
popd
./configure
make

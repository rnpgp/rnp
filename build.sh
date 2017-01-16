#!/bin/bash
#
# (c) 2017 Ribose Inc.
#

[ ! -d m4 ] && \
  mkdir m4
autoreconf -ivf
pushd src/netpgpverify
./configure --mandir=/usr/share/man
popd
./configure
make

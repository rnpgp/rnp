#!/bin/bash
#
# (c) 2017 Ribose Inc.
#

openssl_dir=/usr/local/opt/openssl/
[ ! -d m4 ] && \
  mkdir m4
autoreconf -ivf
./configure --with-openssl=${openssl_dir}
make


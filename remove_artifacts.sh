#!/bin/bash -x
#
# (c) 2017 Ribose Inc.
#

# Post-make build artifacts that can't be removed via `make maintainer-clean`
artifacts="
  Makefile.in
  aclocal.m4
  buildaux/
  configure
  include/Makefile.in
  m4/libtool.m4
  m4/lt~obsolete.m4
  m4/ltoptions.m4
  m4/ltsugar.m4
  m4/ltversion.m4
  src/Makefile.in
  src/tests/Makefile.in
  src/lib/Makefile.in
  src/lib/config.h.in
  src/lib/config.h.in~
  src/rnp/Makefile.in
  src/rnpkeys/Makefile.in
  src/fuzzing/Makefile.in
  tests/Makefile.in
"

[[ -s Makefile ]] &&
  make maintainer-clean

for file in ${artifacts}; do
  rm -rf ${file}
done

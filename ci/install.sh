#!/bin/bash
set -eu

# botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ]; then
  git clone https://github.com/randombit/botan ~/builds/botan
  cd ~/builds/botan
  ./configure.py --prefix="${BOTAN_INSTALL}"
  make install
fi

# cmocka
if [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.so" ]; then
  git clone git://git.cryptomilk.org/projects/cmocka.git ~/builds/cmocka
  cd ~/builds/cmocka
  git checkout tags/cmocka-1.1.1

  cd ~/builds/
  mkdir -p cmocka-build
  cd cmocka-build
  cmake -DCMAKE_INSTALL_PREFIX="${CMOCKA_INSTALL}" ~/builds/cmocka
  make all install
fi


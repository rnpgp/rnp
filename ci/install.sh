#!/bin/bash
set -exu

[ "$BUILD_MODE" = "style-check" ] && exit 0

CORES="2" && [ -r /proc/cpuinfo ] && CORES=$(grep -c '^$' /proc/cpuinfo)

# botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ] && [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.dylib" ]; then
  git clone https://github.com/randombit/botan ~/builds/botan
  cd ~/builds/botan
  ./configure.py --cc=clang --prefix="${BOTAN_INSTALL}"
  make -j${CORES} install
fi

# cmocka
if [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.so" ] && [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.dylib" ]; then
  git clone git://git.cryptomilk.org/projects/cmocka.git ~/builds/cmocka
  cd ~/builds/cmocka
  git checkout tags/cmocka-1.1.1

  cd ~/builds/
  mkdir -p cmocka-build
  cd cmocka-build
  cmake \
    -DCMAKE_INSTALL_DIR="${CMOCKA_INSTALL}" \
    -DLIB_INSTALL_DIR="${CMOCKA_INSTALL}/lib" \
    -DINCLUDE_INSTALL_DIR="${CMOCKA_INSTALL}/include" \
    ~/builds/cmocka
  make -j${CORES} all install
fi

# json-c
if [ ! -e "${JSONC_INSTALL}/lib/libjson-c.so" ] && [ ! -e "${JSONC_INSTALL}/lib/libjson-c.dylib" ]; then
  mkdir ~/builds/json-c
  cd ~/builds/json-c
  wget https://s3.amazonaws.com/json-c_releases/releases/json-c-0.12.1.tar.gz -O json-c.tar.gz
  tar xzf json-c.tar.gz --strip 1

  autoreconf -ivf
  ./configure --prefix="${JSONC_INSTALL}"
  make -j${CORES} install
fi


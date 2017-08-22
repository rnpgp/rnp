#!/bin/bash
set -exu

[ "$BUILD_MODE" = "style-check" ] && exit 0

: "${CORES:=2}"

# botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ] && [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.dylib" ]; then
  git clone https://github.com/randombit/botan "${LOCAL_BUILDS}/botan"
  cd "${LOCAL_BUILDS}/botan"
  ./configure.py --prefix="${BOTAN_INSTALL}"
  make -j${CORES} install
fi

# cmocka
if [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.so" ] && [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.dylib" ]; then
  git clone git://git.cryptomilk.org/projects/cmocka.git "${LOCAL_BUILDS}/cmocka"
  cd "${LOCAL_BUILDS}/cmocka"
  git checkout tags/cmocka-1.1.1

  cd "${LOCAL_BUILDS}"
  mkdir -p cmocka-build
  cd cmocka-build
  cmake \
    -DCMAKE_INSTALL_DIR="${CMOCKA_INSTALL}" \
    -DLIB_INSTALL_DIR="${CMOCKA_INSTALL}/lib" \
    -DINCLUDE_INSTALL_DIR="${CMOCKA_INSTALL}/include" \
    "${LOCAL_BUILDS}/cmocka"
  make -j${CORES} all install
fi

# json-c
if [ ! -e "${JSONC_INSTALL}/lib/libjson-c.so" ] && [ ! -e "${JSONC_INSTALL}/lib/libjson-c.dylib" ]; then
  mkdir "${LOCAL_BUILDS}/json-c"
  cd "${LOCAL_BUILDS}/json-c"
  wget https://s3.amazonaws.com/json-c_releases/releases/json-c-0.12.1.tar.gz -O json-c.tar.gz
  tar xzf json-c.tar.gz --strip 1

  autoreconf -ivf
  ./configure --prefix="${JSONC_INSTALL}"
  make -j${CORES} install
fi

# gpg21
if [ ! -e "${GPG21_INSTALL}/bin/gpg2" ]; then
  mkdir "${LOCAL_BUILDS}/gpg21"
  cd "${LOCAL_BUILDS}/gpg21"

  gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 249B39D24F25E3B6 04376F3EE0856959 2071B08A33BD3F06 8A861B1C7EFD60D9

  wget -c https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.27.tar.gz
  wget -c https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.27.tar.gz.sig
  gpg --verify libgpg-error-1.27.tar.gz.sig
  tar -xzf libgpg-error-1.27.tar.gz
  cd libgpg-error-1.27/
  ./configure --prefix="${GPG21_INSTALL}"
  make -j${CORES} install
  cd ..

  wget -c https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.0.tar.gz
  wget -c https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.0.tar.gz.sig
  gpg --verify libgcrypt-1.8.0.tar.gz.sig
  tar -xzf libgcrypt-1.8.0.tar.gz
  cd libgcrypt-1.8.0
  ./configure --prefix="${GPG21_INSTALL}" --with-libgpg-error-prefix="${GPG21_INSTALL}"
  make -j${CORES} install
  cd ..

  wget -c https://www.gnupg.org/ftp/gcrypt/libassuan/libassuan-2.4.3.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/libassuan/libassuan-2.4.3.tar.bz2.sig
  gpg --verify libassuan-2.4.3.tar.bz2.sig
  tar -xjf libassuan-2.4.3.tar.bz2
  cd libassuan-2.4.3
  ./configure --prefix="${GPG21_INSTALL}" --with-libgpg-error-prefix="${GPG21_INSTALL}"
  make -j${CORES} install
  cd ..

  wget -c  https://www.gnupg.org/ftp/gcrypt/libksba/libksba-1.3.5.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/libksba/libksba-1.3.5.tar.bz2.sig
  gpg --verify libksba-1.3.5.tar.bz2.sig
  tar -xjf libksba-1.3.5.tar.bz2
  cd libksba-1.3.5
  ./configure --prefix="${GPG21_INSTALL}" --with-libgpg-error-prefix="${GPG21_INSTALL}"
  make -j${CORES} install
  cd ..

  wget -c https://www.gnupg.org/ftp/gcrypt/npth/npth-1.5.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/npth/npth-1.5.tar.bz2.sig
  gpg --verify npth-1.5.tar.bz2.sig
  tar -xjf npth-1.5.tar.bz2
  cd npth-1.5
  ./configure --prefix="${GPG21_INSTALL}"
  make -j${CORES} install
  cd ..

  wget -c https://www.gnupg.org/ftp/gcrypt/pinentry/pinentry-1.0.0.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/pinentry/pinentry-1.0.0.tar.bz2.sig
  gpg --verify pinentry-1.0.0.tar.bz2.sig
  tar -xjf pinentry-1.0.0.tar.bz2
  cd pinentry-1.0.0
  ./configure --prefix="${GPG21_INSTALL}" \
    --with-libgpg-error-prefix="${GPG21_INSTALL}" \
    --with-libassuan-prefix="${GPG21_INSTALL}" \
    --enable-pinentry-curses \
    --disable-pinentry-qt4
  make -j${CORES} install
  cd ..

  wget -c https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-2.1.23.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-2.1.23.tar.bz2.sig
  gpg --verify gnupg-2.1.23.tar.bz2.sig
  tar -xjf gnupg-2.1.23.tar.bz2
  cd gnupg-2.1.23
  ./configure --prefix="${GPG21_INSTALL}" \
    --with-libgpg-error-prefix="${GPG21_INSTALL}" \
    --with-libgcrypt-prefix="${GPG21_INSTALL}" \
    --with-libassuan-prefix="${GPG21_INSTALL}" \
    --with-ksba-prefix="${GPG21_INSTALL}" \
    --with-npth-prefix="${GPG21_INSTALL}"
  make -j${CORES} install

fi


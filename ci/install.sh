#!/bin/bash
set -exu

[ "$BUILD_MODE" = "style-check" ] && exit 0

: "${CORES:=2}"
: "${MAKE:=make}"

# botan
botan_build=${LOCAL_BUILDS}/botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ] && \
   [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.dylib" ]; then

  if [ -d "${botan_build}" ]; then
    rm -rf "${botan_build}"
  fi

  git clone https://github.com/randombit/botan "${botan_build}"
  pushd "${botan_build}"
  ./configure.py --prefix="${BOTAN_INSTALL}"
  ${MAKE} -j${CORES} install
  popd
fi

# cmocka
cmocka_build=${LOCAL_BUILDS}/cmocka
if [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.so" ] && \
   [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.dylib" ]; then

  if [ -d "${cmocka_build}" ]; then
    rm -rf "${cmocka_build}"
  fi

  git clone git://git.cryptomilk.org/projects/cmocka.git ${cmocka_build}
  cd ${cmocka_build}
  git checkout tags/cmocka-1.1.1

  cd "${LOCAL_BUILDS}"
  mkdir -p cmocka-build
  cd cmocka-build
  cmake \
    -DCMAKE_INSTALL_DIR="${CMOCKA_INSTALL}" \
    -DLIB_INSTALL_DIR="${CMOCKA_INSTALL}/lib" \
    -DINCLUDE_INSTALL_DIR="${CMOCKA_INSTALL}/include" \
    "${LOCAL_BUILDS}/cmocka"
  ${MAKE} -j${CORES} all install
fi

# json-c
jsonc_build=${LOCAL_BUILDS}/json-c
if [ ! -e "${JSONC_INSTALL}/lib/libjson-c.so" ] && \
   [ ! -e "${JSONC_INSTALL}/lib/libjson-c.dylib" ]; then

   if [ -d "${jsonc_build}" ]; then
     rm -rf "${jsonc_build}"
   fi

  mkdir -p "${jsonc_build}"
  pushd ${jsonc_build}
  wget https://s3.amazonaws.com/json-c_releases/releases/json-c-0.12.1.tar.gz -O json-c.tar.gz
  tar xzf json-c.tar.gz --strip 1

  autoreconf -ivf
  ./configure --prefix="${JSONC_INSTALL}"
  ${MAKE} -j${CORES} install
  popd
fi

# gpg21
gpg21_build=${LOCAL_BUILDS}/gpg21
if [ ! -e "${GPG21_INSTALL}/bin/gpg" ]; then
  mkdir -p "${gpg21_build}"
  cd "${gpg21_build}"

  gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 249B39D24F25E3B6 04376F3EE0856959 2071B08A33BD3F06 8A861B1C7EFD60D9

  for archive in npth:1.5 libgpg-error:1.27; do
    pkgname="${archive%:*}"
    version="${archive#*:}"

    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2
    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2.sig
    gpg --verify ${pkgname}-${version}.tar.bz2.sig
    tar -xjf ${pkgname}-${version}.tar.bz2
    cd ${pkgname}-${version}/
    # autoreconf -ivf
    ./configure --prefix="${GPG21_INSTALL}"
    ${MAKE} -j${CORES} install
    cd ..
  done

  for archive in libgcrypt:1.8.0 libassuan:2.4.3 libksba:1.3.5; do
    pkgname="${archive%:*}"
    version="${archive#*:}"

    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2
    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2.sig
    gpg --verify ${pkgname}-${version}.tar.bz2.sig
    tar -xjf ${pkgname}-${version}.tar.bz2
    cd ${pkgname}-${version}/
    # autoreconf -ivf
    ./configure --prefix="${GPG21_INSTALL}" --with-libgpg-error-prefix="${GPG21_INSTALL}"
    ${MAKE} -j${CORES} install
    cd ..
  done

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
  ${MAKE} -j${CORES} install
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
  ${MAKE} -j${CORES} install

fi

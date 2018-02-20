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
  ./configure.py --prefix="${BOTAN_INSTALL}" --with-debug-info --cxxflags="-fno-omit-frame-pointer"
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
  env CFLAGS="-fno-omit-frame-pointer -g" ./configure --prefix="${JSONC_INSTALL}"
  ${MAKE} -j${CORES} install
  popd
fi

build_gpg_stable() {
  local NPTH_VERSION=$1
  local LIBGPG_ERROR_VERSION=$2
  local LIBGCRYPT_VERSION=$3
  local LIBASSUAN_VERSION=$4
  local LIBKSBA_VERSION=$5
  local PINENTRY_VERSION=$6
  local GNUPG_VERSION=$7

  gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 249B39D24F25E3B6 04376F3EE0856959 2071B08A33BD3F06 8A861B1C7EFD60D9

  for archive in npth:${NPTH_VERSION} libgpg-error:${LIBGPG_ERROR_VERSION}; do
    pkgname="${archive%:*}"
    version="${archive#*:}"

    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2
    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2.sig
    gpg --verify ${pkgname}-${version}.tar.bz2.sig
    tar -xjf ${pkgname}-${version}.tar.bz2
    cd ${pkgname}-${version}/
    # autoreconf -ivf
    ./configure --prefix="${GPG_INSTALL}"
    ${MAKE} -j${CORES} install
    cd ..
  done

  for archive in libgcrypt:${LIBGCRYPT_VERSION} libassuan:${LIBASSUAN_VERSION} libksba:${LIBKSBA_VERSION}; do
    pkgname="${archive%:*}"
    version="${archive#*:}"

    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2
    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2.sig
    gpg --verify ${pkgname}-${version}.tar.bz2.sig
    tar -xjf ${pkgname}-${version}.tar.bz2
    cd ${pkgname}-${version}/
    # autoreconf -ivf
    ./configure --prefix="${GPG_INSTALL}" --with-libgpg-error-prefix="${GPG_INSTALL}"
    ${MAKE} -j${CORES} install
    cd ..
  done

  wget -c https://www.gnupg.org/ftp/gcrypt/pinentry/pinentry-${PINENTRY_VERSION}.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/pinentry/pinentry-${PINENTRY_VERSION}.tar.bz2.sig
  gpg --verify pinentry-${PINENTRY_VERSION}.tar.bz2.sig
  tar -xjf pinentry-${PINENTRY_VERSION}.tar.bz2
  cd pinentry-${PINENTRY_VERSION}
  ./configure --prefix="${GPG_INSTALL}" \
    --with-libgpg-error-prefix="${GPG_INSTALL}" \
    --with-libassuan-prefix="${GPG_INSTALL}" \
    --enable-pinentry-curses \
    --disable-pinentry-qt4
  ${MAKE} -j${CORES} install
  cd ..

  wget -c https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-${GNUPG_VERSION}.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-${GNUPG_VERSION}.tar.bz2.sig
  gpg --verify gnupg-${GNUPG_VERSION}.tar.bz2.sig
  tar -xjf gnupg-${GNUPG_VERSION}.tar.bz2
  cd gnupg-${GNUPG_VERSION}
  ./configure --prefix="${GPG_INSTALL}" \
    --with-libgpg-error-prefix="${GPG_INSTALL}" \
    --with-libgcrypt-prefix="${GPG_INSTALL}" \
    --with-libassuan-prefix="${GPG_INSTALL}" \
    --with-ksba-prefix="${GPG_INSTALL}" \
    --with-npth-prefix="${GPG_INSTALL}"
  ${MAKE} -j${CORES} install

}

build_gpg_beta() {
  mkdir gettext && cd gettext
  gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys D7E69871
  wget -c https://ftp.gnu.org/pub/gnu/gettext/gettext-latest.tar.xz
  wget -c https://ftp.gnu.org/pub/gnu/gettext/gettext-latest.tar.xz.sig
  gpg --verify gettext-latest.tar.xz.sig
  tar -xJf gettext-latest.tar.xz --strip 1
  ./configure --prefix="${GPG_INSTALL}"
  ${MAKE} -j${CORES} install
  cd ..
  export GETTEXT_PREFIX="${GPG_INSTALL}/bin/"

  # workaround https://github.com/travis-ci/travis-ci/issues/8613
  # alternatively, forcing the libgpg-error build to use gcc should work
  export LD_LIBRARY_PATH="/usr/local/clang-5.0.0/lib"
  for repo in npth libgpg-error; do
    git clone git://git.gnupg.org/${repo}
    cd ${repo}
    ./autogen.sh
    ./configure --prefix="${GPG_INSTALL}"
    ${MAKE} -j${CORES} install
    cd ..
  done

  for repo in libgcrypt libassuan libksba; do
    git clone git://git.gnupg.org/${repo}
    cd ${repo}
    ./autogen.sh
    ./configure --prefix="${GPG_INSTALL}" --disable-doc --with-libgpg-error-prefix="${GPG_INSTALL}"
    ${MAKE} -j${CORES} install
    cd ..
  done

  git clone git://git.gnupg.org/pinentry.git
  cd pinentry
  cat << 'END' | git apply -
diff --git a/Makefile.am b/Makefile.am
index 8c8b8e5..412244c 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -85,7 +85,7 @@ endif
 SUBDIRS = m4 secmem pinentry ${pinentry_curses} ${pinentry_tty} \
 	${pinentry_emacs} ${pinentry_gtk_2} ${pinentry_gnome_3} \
 	${pinentry_qt} ${pinentry_tqt} ${pinentry_w32} \
-	${pinentry_fltk} doc
+	${pinentry_fltk}
 
 
 install-exec-local:
END
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" \
    --with-libgpg-error-prefix="${GPG_INSTALL}" \
    --with-libassuan-prefix="${GPG_INSTALL}" \
    --enable-pinentry-curses \
    --disable-pinentry-qt5
  ${MAKE} -j${CORES} install
  cd ..

  git clone git://git.gnupg.org/gnupg.git
  cd gnupg
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" \
    --with-libgpg-error-prefix="${GPG_INSTALL}" \
    --with-libgcrypt-prefix="${GPG_INSTALL}" \
    --with-libassuan-prefix="${GPG_INSTALL}" \
    --with-ksba-prefix="${GPG_INSTALL}" \
    --with-npth-prefix="${GPG_INSTALL}" \
    --disable-doc \
    --enable-maintainer-mode
  ${MAKE} -j${CORES} install
  cd ..
}

# gpg
gpg_build=${LOCAL_BUILDS}/gpg
if [ ! -e "${GPG_INSTALL}/bin/gpg" ]; then
  mkdir -p "${gpg_build}"
  cd "${gpg_build}"

  if [ "$GPG_VERSION" = "stable" ]; then
    #                npth libgpg-error libgcrypt libassuan libksba pinentry gnupg
    build_gpg_stable 1.5  1.27         1.8.2     2.5.1     1.3.5   1.1.0    2.2.4
  elif [ "$GPG_VERSION" = "beta" ]; then
    build_gpg_beta
  else
    echo "\$GPG_VERSION is set to invalid value: $GPG_VERSION"
    exit 1
  fi

fi

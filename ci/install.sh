#!/usr/bin/env bash
set -exu

# botan
botan_build=${LOCAL_BUILDS}/botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ] && \
   [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.dylib" ]; then

  if [ -d "${botan_build}" ]; then
    rm -rf "${botan_build}"
  fi

  git clone --depth 1 --branch 2.9.0 https://github.com/randombit/botan "${botan_build}"
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

  git clone --depth 1 --branch cmocka-1.1.1 git://git.cryptomilk.org/projects/cmocka.git ${cmocka_build}
  cd "${LOCAL_BUILDS}"
  mkdir -p cmocka-build
  pushd cmocka-build
  cmake -DCMAKE_INSTALL_PREFIX="${CMOCKA_INSTALL}" \
        -DCMAKE_BUILD_TYPE=release \
        -DUNIT_TESTING=OFF \
        "${LOCAL_BUILDS}/cmocka"
  ${MAKE} -j${CORES} install
  popd
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
    pushd ${pkgname}-${version}/
    # autoreconf -ivf
    ./configure --prefix="${GPG_INSTALL}"
    ${MAKE} -j${CORES} install
    popd
  done

  for archive in libgcrypt:${LIBGCRYPT_VERSION} libassuan:${LIBASSUAN_VERSION} libksba:${LIBKSBA_VERSION}; do
    pkgname="${archive%:*}"
    version="${archive#*:}"

    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2
    wget -c https://www.gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${version}.tar.bz2.sig
    gpg --verify ${pkgname}-${version}.tar.bz2.sig
    tar -xjf ${pkgname}-${version}.tar.bz2
    pushd ${pkgname}-${version}/
    # autoreconf -ivf
    ./configure --prefix="${GPG_INSTALL}" --with-libgpg-error-prefix="${GPG_INSTALL}"
    ${MAKE} -j${CORES} install
    popd
  done

  wget -c https://www.gnupg.org/ftp/gcrypt/pinentry/pinentry-${PINENTRY_VERSION}.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/pinentry/pinentry-${PINENTRY_VERSION}.tar.bz2.sig
  gpg --verify pinentry-${PINENTRY_VERSION}.tar.bz2.sig
  tar -xjf pinentry-${PINENTRY_VERSION}.tar.bz2
  pushd pinentry-${PINENTRY_VERSION}
  ./configure --prefix="${GPG_INSTALL}" \
    --with-libgpg-error-prefix="${GPG_INSTALL}" \
    --with-libassuan-prefix="${GPG_INSTALL}" \
    --enable-pinentry-curses \
    --disable-pinentry-qt4
  ${MAKE} -j${CORES} install
  popd

  wget -c https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-${GNUPG_VERSION}.tar.bz2
  wget -c https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-${GNUPG_VERSION}.tar.bz2.sig
  gpg --verify gnupg-${GNUPG_VERSION}.tar.bz2.sig
  tar -xjf gnupg-${GNUPG_VERSION}.tar.bz2
  pushd gnupg-${GNUPG_VERSION}
  ./configure --prefix="${GPG_INSTALL}" \
    --with-libgpg-error-prefix="${GPG_INSTALL}" \
    --with-libgcrypt-prefix="${GPG_INSTALL}" \
    --with-libassuan-prefix="${GPG_INSTALL}" \
    --with-ksba-prefix="${GPG_INSTALL}" \
    --with-npth-prefix="${GPG_INSTALL}" \
    --disable-ldap
  ${MAKE} -j${CORES} install
  popd
}

build_gpg_beta() {
  local GETTEXT_VERSION=$1
  local NPTH_VERSION=$2
  local LIBGPG_ERROR_VERSION=$3
  local LIBGCRYPT_VERSION=$4
  local LIBASSUAN_VERSION=$5
  local LIBKSBA_VERSION=$6
  local PINENTRY_VERSION=$7
  local GNUPG_VERSION=$8

  mkdir gettext
  pushd gettext
  gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys D7E69871
  wget -c "https://ftp.gnu.org/pub/gnu/gettext/gettext-${GETTEXT_VERSION}.tar.xz"
  wget -c "https://ftp.gnu.org/pub/gnu/gettext/gettext-${GETTEXT_VERSION}.tar.xz.sig"
  gpg --verify "gettext-${GETTEXT_VERSION}.tar.xz.sig"
  tar -xJf "gettext-${GETTEXT_VERSION}.tar.xz" --strip 1
  ./configure --prefix="${GPG_INSTALL}"
  ${MAKE} -j${CORES} install
  popd
  export GETTEXT_PREFIX="${GPG_INSTALL}/bin/"

  # workaround https://github.com/travis-ci/travis-ci/issues/8613
  # alternatively, forcing the libgpg-error build to use gcc should work
  export LD_LIBRARY_PATH="/usr/local/clang/lib"

  git clone git://git.gnupg.org/npth
  pushd npth
  git checkout "$NPTH_VERSION"
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" --disable-doc
  ${MAKE} -j${CORES} install
  popd

  git clone git://git.gnupg.org/libgpg-error
  pushd libgpg-error
  git checkout "$LIBGPG_ERROR_VERSION"
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" --disable-doc
  ${MAKE} -j${CORES} install
  popd

  git clone git://git.gnupg.org/libgcrypt
  pushd libgcrypt
  git checkout "$LIBGCRYPT_VERSION"
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" --disable-doc --with-libgpg-error-prefix="${GPG_INSTALL}"
  ${MAKE} -j${CORES} install
  popd

  git clone git://git.gnupg.org/libassuan
  pushd libassuan
  git checkout "$LIBASSUAN_VERSION"
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" --disable-doc --with-libgpg-error-prefix="${GPG_INSTALL}"
  ${MAKE} -j${CORES} install
  popd

  git clone git://git.gnupg.org/libksba
  pushd libksba
  git checkout "$LIBKSBA_VERSION"
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" --disable-doc --with-libgpg-error-prefix="${GPG_INSTALL}"
  ${MAKE} -j${CORES} install
  popd

  git clone git://git.gnupg.org/pinentry.git
  pushd pinentry
  git checkout "$PINENTRY_VERSION"
  cat << 'END' | git apply -
diff --git a/Makefile.am b/Makefile.am
index 8c8b8e5..412244c 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -85,7 +85,7 @@ endif
 SUBDIRS = m4 secmem pinentry ${pinentry_curses} ${pinentry_tty} \
 	${pinentry_emacs} ${pinentry_gtk_2} ${pinentry_gnome_3} \
 	${pinentry_qt} ${pinentry_tqt} ${pinentry_w32} \
-	${pinentry_fltk} ${pinentry_efl} doc
+	${pinentry_fltk} ${pinentry_efl}
 
 
 install-exec-local:
END
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" \
    --with-libgpg-error-prefix="${GPG_INSTALL}" \
    --with-libassuan-prefix="${GPG_INSTALL}" \
    --enable-pinentry-curses \
    --disable-pinentry-emacs \
    --disable-pinentry-gtk2 \
    --disable-pinentry-gnome3 \
    --disable-pinentry-qt \
    --disable-pinentry-qt5 \
    --disable-pinentry-tqt \
    --disable-pinentry-fltk
  ${MAKE} -j${CORES} install
  popd

  git clone git://git.gnupg.org/gnupg.git
  pushd gnupg
  git checkout "$GNUPG_VERSION"
  ./autogen.sh
  ./configure --prefix="${GPG_INSTALL}" \
    --with-libgpg-error-prefix="${GPG_INSTALL}" \
    --with-libgcrypt-prefix="${GPG_INSTALL}" \
    --with-libassuan-prefix="${GPG_INSTALL}" \
    --with-ksba-prefix="${GPG_INSTALL}" \
    --with-npth-prefix="${GPG_INSTALL}" \
    --disable-ldap \
    --disable-doc \
    --enable-maintainer-mode
  ${MAKE} -j${CORES} install
  popd
}

# gpg
gpg_build=${LOCAL_BUILDS}/gpg
if [ ! -e "${GPG_INSTALL}/bin/gpg" ]; then
  mkdir -p "${gpg_build}"
  cd "${gpg_build}"

  if [ "$GPG_VERSION" = "stable" ]; then
    #                npth libgpg-error libgcrypt libassuan libksba pinentry gnupg
    build_gpg_stable 1.6  1.32         1.8.4     2.5.1     1.3.5   1.1.0    2.2.11
  elif [ "$GPG_VERSION" = "beta" ]; then
    #              gettext npth libgpg-error libgcrypt libassuan libksba pinentry gnupg
    build_gpg_beta latest 377c1b9 f4d139b 66d2b7f eac43aa c37cdbd d0eaec8 e154fba
  else
    echo "\$GPG_VERSION is set to invalid value: $GPG_VERSION"
    exit 1
  fi
fi

# ruby-rnp
sudo gem install bundler -v 1.16.4
if [ ! -e "${RUBY_RNP_INSTALL}/Gemfile" ]; then
  git clone --depth 1 --branch "$RUBY_RNP_VERSION" https://github.com/riboseinc/ruby-rnp "$RUBY_RNP_INSTALL"
  pushd "$RUBY_RNP_INSTALL"
  bundle install --path .
  popd
fi


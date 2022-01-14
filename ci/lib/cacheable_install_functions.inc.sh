#!/usr/bin/env bash
# shellcheck disable=SC1090
# shellcheck disable=SC1091
#
# All of the following functions install things into the
# CACHE_DIR, so they could be safely skipped in case of a
# cache hit.  Conversely, these should not attempt to export
# environment variables (unless for self consumption), nor
# modify other system parts (again, unless for self
# consumption), as these will not be available in case of
# cache hits.

install_botan() {
  # botan
  local botan_build=${LOCAL_BUILDS}/botan
  if [[ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ]] && \
     [[ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.dylib" ]] && \
     [[ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.a" ]]; then

    if [[ -d "${botan_build}" ]]; then
      rm -rf "${botan_build}"
    fi

    git clone --depth 1 --branch 2.17.3 https://github.com/randombit/botan "${botan_build}"
    pushd "${botan_build}"

    local osparam=()
    local cpuparam=()
    local run=run
    case "${OS}" in
      msys)
        osparam=(--os=mingw)
        ;;
      linux)
        case "${DIST_VERSION}" in
          centos-8|fedora-*|debian-*)
            run=run_in_python_venv
            ;;
        esac
        ;;
    esac

    [[ -z "$CPU" ]] || cpuparam=(--cpu="$CPU" --disable-cc-tests)

    "${run}" ./configure.py --prefix="${BOTAN_INSTALL}" --with-debug-info --cxxflags="-fno-omit-frame-pointer" \
      ${osparam+"${osparam[@]}"} ${cpuparam+"${cpuparam[@]}"} --without-documentation --without-openssl --build-targets=shared \
      --minimized-build --enable-modules="$BOTAN_MODULES"
    ${MAKE} -j"${MAKE_PARALLEL}" install
    popd
  fi
}

# TODO:
# /tmp/rnp-local-installs/jsonc-install/lib
# | If you ever happen to want to link against installed libraries
# | in a given directory, LIBDIR, you must either use libtool, and
# | specify the full pathname of the library, or use the '-LLIBDIR'
# | flag during linking and do at least one of the following:
# |    - add LIBDIR to the 'LD_LIBRARY_PATH' environment variable
# |      during execution
# |    - add LIBDIR to the 'LD_RUN_PATH' environment variable
# |      during linking
# |    - use the '-Wl,-rpath -Wl,LIBDIR' linker flag
# |    - have your system administrator add LIBDIR to '/etc/ld.so.conf'
install_jsonc() {
  local jsonc_build=${LOCAL_BUILDS}/json-c
  if [[ ! -e "${JSONC_INSTALL}/lib/libjson-c.so" ]] && \
     [[ ! -e "${JSONC_INSTALL}/lib/libjson-c.dylib" ]] && \
     [[ ! -e "${JSONC_INSTALL}/lib/libjson-c.a" ]]; then

     if [ -d "${jsonc_build}" ]; then
       rm -rf "${jsonc_build}"
     fi

    mkdir -p "${jsonc_build}"
    pushd "${jsonc_build}"
    wget https://s3.amazonaws.com/json-c_releases/releases/json-c-"${RECOMMENDED_JSONC_VERSION}".tar.gz -O json-c.tar.gz
    tar xzf json-c.tar.gz --strip 1

    autoreconf -ivf
    local cpuparam=()
    [[ -z "$CPU" ]] || cpuparam=(--build="$CPU")
    env CFLAGS="-fno-omit-frame-pointer -Wno-implicit-fallthrough -g" ./configure ${cpuparam+"${cpuparam[@]}"} --prefix="${JSONC_INSTALL}"
    ${MAKE} -j"${MAKE_PARALLEL}" install
    popd
  fi
}

_install_gpg() {
  local VERSION_SWITCH=$1
  local NPTH_VERSION=$2
  local LIBGPG_ERROR_VERSION=$3
  local LIBGCRYPT_VERSION=$4
  local LIBASSUAN_VERSION=$5
  local LIBKSBA_VERSION=$6
  local PINENTRY_VERSION=$7
  local GNUPG_VERSION=$8

  local gpg_build="$PWD"
  local gpg_install="${GPG_INSTALL}"
  mkdir -p "${gpg_build}" "${gpg_install}"
  git clone --depth 1 https://github.com/rnpgp/gpg-build-scripts
  pushd gpg-build-scripts

  local cpuparam=()
  [[ -z "$CPU" ]] || cpuparam=(--build="$CPU")

  # configure_opts="\
  #     --prefix=${gpg_install} \
  #     --with-libgpg-error-prefix=${gpg_install} \
  #     --with-libassuan-prefix=${gpg_install} \
  #     --with-libgcrypt-prefix=${gpg_install} \
  #     --with-ksba-prefix=${gpg_install} \
  #     --with-npth-prefix=${gpg_install} \
  #     --disable-doc \
  #     --extra-cflags=\"-O3 -fomit-frame-pointer\" \
  #     --enable-pinentry-curses \
  #     --disable-pinentry-emacs \
  #     --disable-pinentry-gtk2 \
  #     --disable-pinentry-gnome3 \
  #     --disable-pinentry-qt \
  #     --disable-pinentry-qt4 \
  #     --disable-pinentry-qt5 \
  #     --disable-pinentry-tqt \
  #     --disable-pinentry-fltk \
  #     --enable-maintainer-mode \
  #     ${cpuparam+"${cpuparam[@]}"}"

  local configure_opts=(
      "--prefix=${gpg_install}"
      "--with-libgpg-error-prefix=${gpg_install}"
      "--with-libassuan-prefix=${gpg_install}"
      "--with-libgcrypt-prefix=${gpg_install}"
      "--with-ksba-prefix=${gpg_install}"
      "--with-npth-prefix=${gpg_install}"
      "--disable-doc"
      "--enable-pinentry-curses"
      "--disable-pinentry-emacs"
      "--disable-pinentry-gtk2"
      "--disable-pinentry-gnome3"
      "--disable-pinentry-qt"
      "--disable-pinentry-qt4"
      "--disable-pinentry-qt5"
      "--disable-pinentry-tqt"
      "--disable-pinentry-fltk"
      "--enable-maintainer-mode"
      ${cpuparam+"${cpuparam[@]}"}
    )

  local common_args=(
      --force-autogen
      --verbose
      --trace
      --build-dir "${gpg_build}"
      --configure-opts "${configure_opts[*]}"
  )

  case "${OS}" in
    linux)
      if [[ "${DIST}" != "ubuntu" ]]; then
        common_args+=(--ldconfig)
      fi
      ;;
  esac

  # For "tee"-ing to /etc/ld.so.conf.d/gpg-from_build_scripts.conf from option `--ldconfig`
  if [[ "${SUDO}" = "sudo" && "${DIST}" != "ubuntu" ]]; then
    common_args+=(--sudo)
  fi

  # Workaround to correctly build pinentry on the latest GHA on macOS. Most likely there is a better solution.
  export CFLAGS="-D_XOPEN_SOURCE_EXTENDED"
  export CXXFLAGS="-D_XOPEN_SOURCE_EXTENDED"

  for component in libgpg-error:$LIBGPG_ERROR_VERSION \
                   libgcrypt:$LIBGCRYPT_VERSION \
                   libassuan:$LIBASSUAN_VERSION \
                   libksba:$LIBKSBA_VERSION \
                   npth:$NPTH_VERSION \
                   pinentry:$PINENTRY_VERSION \
                   gnupg:$GNUPG_VERSION; do
    local name="${component%:*}"
    local version="${component#*:}"

    ./install_gpg_component.sh \
      --component-name "$name" \
      --"$VERSION_SWITCH" "$version" \
      "${common_args[@]}"
  done
  popd
}


install_gpg() {
  # gpg - for msys/windows we use shipped gpg2 version
  local gpg_build=${LOCAL_BUILDS}/gpg

  if [[ ! -e "${GPG_INSTALL}/bin/gpg" ]]; then
    mkdir -p "${gpg_build}"
    pushd "${gpg_build}"

    case "${GPG_VERSION}" in
      stable)
        #                              npth libgpg-error libgcrypt libassuan libksba pinentry gnupg
        _install_gpg component-version 1.6  1.39         1.8.7     2.5.4     1.5.0   1.1.0    2.2.24
        # _install_gpg component-version 1.6  1.42         1.9.2     2.5.5     1.5.0   1.1.1    2.2.27
        ;;
      beta)
        #                              npth    libgpg-error libgcrypt libassuan libksba pinentry gnupg
        _install_gpg component-git-ref 2501a48 f73605e      d9c4183   909133b   3df0cd3 0e2e53c  c6702d7
        # _install_gpg component-git-ref 7e45b50 c66594d      cf88dca   57cf9d6   4243085 6e8ad31  d4e5979
        ;;
      *)
        >&2 echo "\$GPG_VERSION is set to invalid value: ${GPG_VERSION}"
        exit 1
    esac
    popd
  fi
}

#!/usr/bin/env bash
# shellcheck disable=SC1090
# shellcheck disable=SC1091

: "${GPG_VERSION:=stable}"
: "${BUILD_SHARED_LIBS:=off}"
: "${USE_STATIC_DEPENDENCIES:=}"
: "${OS:=}"
: "${DIST:=}"
: "${DIST_VERSION:=}"
: "${DIST_VERSION_ID:=}"
: "${MINIMUM_RUBY_VERSION:=2.5.0}"
: "${RECOMMENDED_RUBY_VERSION:=2.5.8}"
: "${MINIMUM_CMAKE_VERSION:=3.14.0}"
: "${RECOMMENDED_CMAKE_VERSION:=3.14.5}"
: "${RECOMMENDED_PYTHON_VERSION:=3.9.2}"
: "${RECOMMENDED_JSONC_VERSION:=0.12.1}"

: "${VERBOSE:=1}"


if [[ "${OS}" = "freebsd" ]] || \
   [[ "${DIST}" = "ubuntu" ]] || \
   [[ "${DIST}" = "centos" ]] || \
   [[ "${DIST}" = "fedora" ]]
then
  SUDO="${SUDO:-sudo}"
else
  SUDO="${SUDO:-run}"
fi

# Simply run its arguments.
run() {
  "$@"
}

macos_install() {
  brew update-reset
  # homebrew fails because `openssl` is a symlink while it tries to remove a directory.
  rm /usr/local/Cellar/openssl || true
  # homebrew fails to update python 3.9.1 to 3.9.1.1 due to unlinking failure
  rm /usr/local/bin/2to3 || true
  brew bundle
}

freebsd_install() {
  local packages=(
    git
    readline
    bash
    gnupg
    devel/pkgconf
    wget
    cmake
    gmake
    autoconf
    automake
    libtool
    gettext-tools
    python
    ruby26
  )

  # Note: we assume sudo is already installed
  "${SUDO}" pkg install -y "${packages[@]}"

  cd /usr/ports/devel/ruby-gems
  "${SUDO}" make -DBATCH RUBY_VER=2.5 install
  cd

  mkdir -p ~/.gnupg
  echo "disable-ipv6" >> ~/.gnupg/dirmngr.conf
  dirmngr </dev/null
  dirmngr --daemon
}

openbsd_install() {
  echo ""
}

netbsd_install() {
  echo ""
}

linux_prepare_ribose_yum_repo() {
  "${SUDO}" rpm --import https://github.com/riboseinc/yum/raw/master/ribose-packages.pub
  "${SUDO}" curl -L https://github.com/riboseinc/yum/raw/master/ribose.repo \
    -o /etc/yum.repos.d/ribose.repo
}

# Prepare the system by updating and optionally installing repos
yum_prepare_repos() {
  yum_install "${util_depedencies_yum[@]}"
  linux_prepare_ribose_yum_repo
  "${SUDO}" "${YUM}" -y update
  if [[ $# -gt 0 ]]; then
    yum_install "$@"
  fi
}

linux_install_fedora() {
  yum_prepare_repos
  yum_install_build_dependencies \
    cmake
  yum_install_dynamic_build_dependencies_if_needed

  ensure_cmake
  ensure_ruby
  rubygem_install_build_dependencies
}

linux_install_centos() {
  case "${DIST_VERSION}" in
    centos-7)
      linux_install_centos7
      ;;
    centos-8)
      linux_install_centos8
      ;;
    *)
      >&2 echo "Error: unsupported CentOS version \"${DIST_VERSION_ID}\" (supported: 7, 8).  Aborting."
      exit 1
  esac
}

declare util_depedencies_yum=(
  sudo # NOTE: Needed to avoid "sudo: command not found"
  wget
  git
)

declare basic_build_dependencies_yum=(
  # cmake3 # XXX: Fedora 22+ only has cmake
  clang
  gcc
  gcc-c++
  make
  autoconf
  automake
  libtool
  bzip2
  gzip
)

declare build_dependencies_yum=(
  ncurses-devel
  bzip2-devel
  zlib-devel
  byacc
  gettext-devel
  bison
  ribose-automake116
  python3
  ruby-devel
)

declare dynamic_build_dependencies_yum=(
  botan2-devel
  json-c12-devel
  python2-devel # TODO: needed?
)


apt_install() {
  local apt_command=(apt -y -q install "$@")
  if command -v sudo >/dev/null; then
    sudo "${apt_command[@]}"
  else
    "${apt_command[@]}"
  fi
}

yum_install() {
  local yum_command=("${YUM}" -y -q install "$@")
  if command -v sudo >/dev/null; then
    sudo "${yum_command[@]}"
  else
    "${yum_command[@]}"
  fi

  post_yum_install_set_env
}

yum_install_build_dependencies() {
  yum_install \
    "${basic_build_dependencies_yum[@]}" \
    "${build_dependencies_yum[@]}" \
    "$@"
}

linux_install_centos7() {
  yum_prepare_repos epel-release centos-release-scl
  yum_install_build_dependencies \
    cmake3 \
    rh-ruby25 rh-ruby25-ruby-devel \
    llvm-toolset-7.0

  yum_install_dynamic_build_dependencies_if_needed

  ensure_cmake
  ensure_ruby
  rubygem_install_build_dependencies
}

linux_install_centos8() {
  yum_prepare_repos epel-release
  yum_install_build_dependencies \
    cmake3

  yum_install_dynamic_build_dependencies_if_needed

  ensure_cmake
  ensure_ruby
  rubygem_install_build_dependencies
}

is_use_static_dependencies() {
  [[ -n "${USE_STATIC_DEPENDENCIES}" ]] && \
    [[ no  != "${USE_STATIC_DEPENDENCIES}" ]] && \
    [[ off != "${USE_STATIC_DEPENDENCIES}" ]] && \
    [[ 0   != "${USE_STATIC_DEPENDENCIES}" ]]
}

yum_install_dynamic_build_dependencies_if_needed() {
  if ! is_use_static_dependencies; then
    yum_install_dynamic_build_dependencies
  fi
}

install_static_build_dependencies_if_needed() {
  if is_use_static_dependencies; then
    install_static_build_dependencies
  fi
}

install_static_build_dependencies() {
  mkdir -p "$LOCAL_BUILDS"

  local default=(botan jsonc gpg bundler asciidoctor)
  local items=("${@:-${default[@]}}")
  for item in "${items[@]}"; do
    install_"$item"
  done
}

rubygem_install_build_dependencies() {
  install_bundler
  install_asciidoctor
}

yum_install_dynamic_build_dependencies() {
  yum_install \
    "${dynamic_build_dependencies_yum[@]}"

  # Work around pkg-config giving out wrong include path for json-c:
  ensure_symlink_to_target /usr/include/json-c12 /usr/include/json-c
}

# Make sure cmake is at least 3.14+ as required by rnp
# Also make sure ctest is available.
# If not, build cmake from source.
ensure_cmake() {
  ensure_symlink_to_target /usr/bin/cmake3 /usr/bin/cmake
  ensure_symlink_to_target /usr/bin/cpack3 /usr/bin/cpack

  local cmake_version
  cmake_version=$({
    command -v cmake  >/dev/null && command cmake --version || \
    command -v cmake3 >/dev/null && command cmake3 --version
    } | head -n1 | cut -f3 -d' '
  )

  local need_to_build_cmake=

  # Make sure ctest is also in PATH.  If not, build cmake from source.
  # TODO: Check CentOS7 tests in GHA.
  if ! command -v ctest >/dev/null; then
    >&2 echo "ctest not found."
    need_to_build_cmake=1
  elif ! is_version_at_least cmake "${MINIMUM_CMAKE_VERSION}" echo "${cmake_version}"; then
    >&2 echo "cmake version lower than ${MINIMUM_CMAKE_VERSION}."
    need_to_build_cmake=1
  fi

  if [[ "${need_to_build_cmake}" != 1 ]]; then
    >&2 echo "cmake rebuild is NOT needed."
    return
  fi

  >&2 echo "cmake rebuild is needed."

  pushd "$(mktemp -d)" || return 1

  install_prebuilt_cmake Linux-x86_64

  command -v cmake

  # Abort if ctest still not found.
  if ! command -v ctest >/dev/null; then
    >&2 echo "Error: ctest not found.  Aborting."
    exit 1
  fi
}

# E.g. for i386
# NOTE: Make sure cmake's build prerequisites are installed.
build_and_install_cmake() {
  local cmake_build=${LOCAL_BUILDS}/cmake
  mkdir -p "${cmake_build}"
  pushd "${cmake_build}"
  wget https://github.com/Kitware/CMake/releases/download/v"${RECOMMENDED_CMAKE_VERSION}"/cmake-"${RECOMMENDED_CMAKE_VERSION}".tar.gz -O cmake.tar.gz
  tar xzf cmake.tar.gz --strip 1

  PREFIX="${PREFIX:-/usr}"
  mkdir -p "${PREFIX}"
  ./configure --prefix="${PREFIX}" && ${MAKE} -j"${MAKE_PARALLEL}" && "${SUDO}" make install
  popd
  CMAKE="${PREFIX}"/bin/cmake
}

# 'arch' corresponds to the last segment of GitHub release URL
install_prebuilt_cmake() {
  local arch="${1:?Missing architecture}"
  local cmake_build=${LOCAL_BUILDS}/cmake
  mkdir -p "${cmake_build}"
  pushd "${cmake_build}"
  curl -L -o \
    cmake.sh \
    https://github.com/Kitware/CMake/releases/download/v"${RECOMMENDED_CMAKE_VERSION}"/cmake-"${RECOMMENDED_CMAKE_VERSION}"-"${arch}".sh

  PREFIX="${PREFIX:-/usr}"
  mkdir -p "${PREFIX}"
  "${SUDO}" sh cmake.sh --skip-license --prefix="${PREFIX}"
  popd
  CMAKE="${PREFIX}"/bin/cmake
}

build_and_install_python() {
  python_build=${LOCAL_BUILDS}/python
  mkdir -p "${python_build}"
  pushd ${python_build}
  curl -L -o python.tar.xz https://www.python.org/ftp/python/"${RECOMMENDED_PYTHON_VERSION}"/Python-"${RECOMMENDED_PYTHON_VERSION}".tar.xz
  tar -xf python.tar.xz --strip 1
  ./configure --enable-optimizations --prefix=/usr && ${MAKE} -j"${MAKE_PARALLEL}" && "${SUDO}" make install
  ${SUDO} ln -sf /usr/bin/python3 /usr/bin/python
  popd
}

build_and_install_automake() {
  # automake
  automake_build=${LOCAL_BUILDS}/automake
  mkdir -p "${automake_build}"
  pushd ${automake_build}
  curl -L -o automake.tar.xz https://ftp.gnu.org/gnu/automake/automake-1.16.1.tar.xz
  tar -xf automake.tar.xz --strip 1
  ./configure --enable-optimizations --prefix=/usr && ${MAKE} -j${MAKE_PARALLEL} && ${SUDO} make install
  popd
}

# json-c is installed with install_jsonc
# asciidoctor is installed with install_asciidoctor
linux_install_ubuntu() {
  "${SUDO}" apt-get update
  "${SUDO}" apt-get -y install ruby-dev g++-8 cmake libbz2-dev zlib1g-dev build-essential gettext \
    ruby-bundler libncurses-dev
}

declare util_dependencies_deb=(
  sudo
  wget
  git
)

declare basic_build_dependencies_deb=(
  autoconf
  automake
  make
  build-essential
  cmake
  libtool
)

declare build_dependencies_deb=(
  bison
  byacc
  curl
  gettext
  libbz2-dev
  libncurses5-dev
  libssl-dev
  python3
  python3-venv
  ruby-dev
  zlib1g-dev
)

declare ruby_build_dependencies_deb=(
  bison
  curl
  libbz2-dev
  libssl-dev
  ruby-bundler
  rubygems
  zlib1g-dev
)

linux_install_debian() {
  "${SUDO}" apt-get update
  apt_install \
    "${util_dependencies_deb[@]}" \
    "${basic_build_dependencies_deb[@]}" \
    "${build_dependencies_deb[@]}" \
    "$@"

  build_and_install_automake
  build_and_install_cmake
}

linux_install() {
  if type "linux_install_${DIST}" | grep -qwi 'function'; then
    "linux_install_${DIST}"
  fi
}

msys_install() {
  local packages=(
    tar
    zlib-devel
    libbz2-devel
    git
    automake
    autoconf
    libtool
    automake-wrapper
    gnupg2
    make
    pkg-config
    mingw64/mingw-w64-x86_64-cmake
    mingw64/mingw-w64-x86_64-gcc
    mingw64/mingw-w64-x86_64-json-c
    mingw64/mingw-w64-x86_64-python3
  )

  pacman --noconfirm -S --needed "${packages[@]}"

  # any version starting with 2.14 up to 2.17.3 caused the application to hang
  # as described in https://github.com/randombit/botan/issues/2582
  # fixed with https://github.com/msys2/MINGW-packages/pull/7640/files
  botan_pkg="mingw-w64-x86_64-libbotan-2.17.3-2-any.pkg.tar.zst"
  pacman --noconfirm -U https://repo.msys2.org/mingw/x86_64/${botan_pkg} || \
  pacman --noconfirm -U https://sourceforge.net/projects/msys2/files/REPOS/MINGW/x86_64/${botan_pkg}

  # msys includes ruby 2.6.1 while we need lower version
  #wget http://repo.msys2.org/mingw/x86_64/mingw-w64-x86_64-ruby-2.5.3-1-any.pkg.tar.xz -O /tmp/ruby-2.5.3.pkg.tar.xz
  #pacman --noconfirm --needed -U /tmp/ruby-2.5.3.pkg.tar.xz
  #rm /tmp/ruby-2.5.3.pkg.tar.xz
}

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

# Mainly for all python scripts with shebangs pointing to 'python', which is
# unavailable in CentOS 8 by default.
#
# This creates an environment where straight 'python' is available.
prepare_python_virtualenv() {
  python3 -m venv ~/.venv
}

# Run its arguments inside a python-virtualenv-enabled sub-shell.
run_in_python_venv() {
  if [[ ! -e ~/.venv ]] || [[ ! -f ~/.venv/bin/activate ]]; then
    prepare_python_virtualenv
  fi

  (
    # Avoid issues like '_OLD_VIRTUAL_PATH: unbound variable'
    set +u
    . ~/.venv/bin/activate
    set -u
    "$@"
  )
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

# ruby-rnp
install_bundler() {
  gem_install bundler bundle
}

install_asciidoctor() {
  gem_install asciidoctor
}

declare ruby_build_dependencies_yum=(
  git-core
  zlib
  zlib-devel
  gcc-c++
  patch
  readline
  readline-devel
  libyaml-devel
  libffi-devel
  openssl-devel
  make
  bzip2
  autoconf
  automake
  libtool
  bison
  curl
  sqlite-devel
  which # for rbenv-doctor
)


ensure_ruby() {
  if is_version_at_least ruby "${MINIMUM_RUBY_VERSION}" command ruby -e 'puts RUBY_VERSION'; then
    return
  fi

  # XXX: Fedora20 seems to have problems installing ruby build dependencies in
  # yum?
  # "${YUM}" repolist all
  # "${SUDO}" rpm -qa | sort

  if [[ "${DIST_VERSION}" = fedora-20 ]]; then
    ruby_build_dependencies_yum+=(--enablerepo=updates-testing)
  fi

  case "${DIST}" in
    centos|fedora)
      yum_install "${ruby_build_dependencies_yum[@]}"
      setup_rbenv
      rbenv install -v "${RECOMMENDED_RUBY_VERSION}"
      rbenv global "${RECOMMENDED_RUBY_VERSION}"
      rbenv rehash
      sudo chown -R "${USER}" "$(rbenv prefix)"
      ;;
    debian)
      apt_install "${ruby_build_dependencies_deb[@]}"
      ;;
    *)
      # TODO: handle ubuntu?
      >&2 echo Error: Need to install ruby ${MINIMUM_RUBY_VERSION}+
      exit 1
  esac
}


# shellcheck disable=SC2016
setup_rbenv() {
  pushd "$(mktemp -d)" || return 1
  local rbenv_rc=$HOME/setup_rbenv.sh
  git clone https://github.com/sstephenson/rbenv.git ~/.rbenv
  echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> "${rbenv_rc}"
  echo 'eval "$($HOME/.rbenv/bin/rbenv init -)"' >> "${rbenv_rc}"

  git clone https://github.com/sstephenson/ruby-build.git ~/.rbenv/plugins/ruby-build
  echo 'export PATH="$HOME/.rbenv/plugins/ruby-build/bin:$PATH"' >> "${rbenv_rc}"
  echo ". \"${rbenv_rc}\"" >> ~/.bash_profile
  . "${rbenv_rc}"

  # Verify rbenv is set up correctly
  curl -fsSL https://github.com/rbenv/rbenv-installer/raw/master/bin/rbenv-doctor | bash
  popd || return 1
}

is_version_at_least() {
  local bin_name="${1:?Missing bin name}"; shift
  local version_constraint="${1:?Missing version constraint}"; shift
  local need_to_build=0

  if ! command -v "${bin_name}"; then
    >&2 echo "Warning: ${bin_name} not installed."
    need_to_build=1
  fi

  local installed_version installed_version_major installed_version_minor #version_patch
  installed_version="$("$@")"

  # shellcheck disable=SC2181
  if [[ $? -ne 0 ]]; then
    need_to_build=1
  else
    installed_version_major="${installed_version%%.*}"
    installed_version_minor="${installed_version#*.}"
    installed_version_minor="${installed_version_minor%%.*}"

    local need_version_major
    need_version_major="${version_constraint%%.*}"
    need_version_minor="${version_constraint#*.}"
    need_version_minor="${need_version_minor%%.*}"

    # Naive semver comparison
    if [[ "${installed_version_major}" -lt "${need_version_major}" ]] || \
       [[ "${installed_version_major}" = "${need_version_major}" && "${installed_version_minor}" -lt "${need_version_minor}" ]]; then
      need_to_build=1
    fi
  fi

  if [[ 1 = "${need_to_build}" ]]; then
    >&2 echo "Warning: Need to build ${bin_name} since version constraint ${version_constraint} not met."
  fi

  return "${need_to_build}"
}

# Install specified gem.
# Use rbenv when available.  Otherwise use system 'gem', and use 'sudo'
# depending on OS.
# Set SUDO_GEM to 'sudo' to force use of sudo.
# Set SUDO_GEM to 'run' to disable sudo.
gem_install() {
  local gem_name="${1:?Missing gem name}"
  local bin_name="${2:-${gem_name}}"
  if ! command -v "${bin_name}" >/dev/null; then
    if command -v rbenv >/dev/null; then
      gem install "${gem_name}"
      rbenv rehash
    else
      "${SUDO_GEM:-${SUDO:-run}}" gem install "${gem_name}"
    fi
  fi
}

# build+install
build_and_install() {

  export cmakeopts=(
    -DBUILD_SHARED_LIBS="${BUILD_SHARED_LIBS}"
    -DBUILD_TESTING=no
    -DCMAKE_INSTALL_PREFIX="${1:-/tmp}"
  )

  if [[ $# -gt 0 ]]; then
    shift
  fi

  build_rnp "$@"
  make_install VERBOSE="${VERBOSE}"
}

build_rnp() {
  "${CMAKE:-cmake}" "${cmakeopts[@]}" "${1:-.}"
}

make_install() {
  make -j"${MAKE_PARALLEL}" install "$@"
}

is_true_cmake_bool() {
  local arg="${1:?Missing parameter}"
  case "${arg}" in
    yes|on|true|y)
      true
      ;;
    no|off|false|n)
      false
      ;;
    *)
      >&2 echo "Warning: unrecognized boolean expression ($arg).  Continuing and interpreting as 'false' anyway."
      false
  esac
}

# check for install issues
check_build() {
  if is_true_cmake_bool "${BUILD_SHARED_LIBS}"; then
    export pkgflags=
    export gccflags=
    if ! find /usr/lib64/ -maxdepth 1 -type f -name 'librnp*.so' | grep -q . || \
         find /usr/lib64/ -maxdepth 1 -type f -name 'librnp*.a'  | grep -q .; then
      >&2 echo "librnp installed libraries incorrect"
    fi
  else
    export pkgflags=--static
    export gccflags=-lstdc++
    if  find /usr/lib64/ -maxdepth 1 -type f -name 'librnp*.so' | grep -q . || \
      ! find /usr/lib64/ -maxdepth 1 -type f -name 'librnp*.a'  | grep -q .; then
      >&2 echo "librnp installed libraries incorrect"
    fi
  fi
}

# build an example using pkg-config
build_example_pkgconfig() {
  local rnpsrc="$PWD"
  pushd "$(mktemp -d)" || return 1

  gcc "${rnpsrc}/src/examples/generate.c" -ogenerate $(pkg-config --cflags --libs $pkgflags librnp) $gccflags
  ./generate
  readelf -d generate
  if is_true_cmake_bool "${BUILD_SHARED_LIBS}"; then
    readelf -d generate | grep -q 'librnp\>'
  else
    readelf -d generate | grep -qv 'librnp\>'
  fi

  # remove the pkgconfig for the next test
  >&2 echo "Checking if librnp- is found in pkg-config list:"
  pkg-config --list-all
  pkg-config --list-all | grep -q '^librnp\>'

  # XXX: debug
  find /usr/lib64 -type f -name 'librnp*'
  find /usr/lib -type f -name 'librnp*'

  find /usr/lib64/pkgconfig -regextype sed -regex '.*librnp\>.*' -exec rm {} +

  # XXX: debug
  find /usr/lib64 -type f -name 'librnp*'
  find /usr/lib -type f -name 'librnp*'

  # should not be found
  >&2 echo "Checking if librnp- is NOT found in pkg-config list:"
  pkg-config --list-all
  pkg-config --list-all | grep -qv '^librnp\>'

  # build an example using cmake targets
  mkdir rnp-project
  pushd rnp-project || return 1

  cat <<"EOF" > mytest.cpp
  #include <rnp/rnp.h>

  int main(int argc, char *argv[]) {
      printf("RNP version: %s\n", rnp_version_string());
      return 0;
  }
EOF

  cat <<"EOF" > CMakeLists.txt
  set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}")
  find_package(BZip2 REQUIRED)
  find_package(ZLIB REQUIRED)
  find_package(JSON-C 0.11 REQUIRED)
  find_package(Botan2 2.14.0 REQUIRED)
  find_package(rnp REQUIRED)

  cmake_minimum_required(VERSION 3.12)
  add_executable(mytest mytest.cpp)
  target_link_libraries(mytest rnp::librnp)
EOF

  cp "${rnpsrc}"/cmake/Modules/* .
  cmake .
  make VERBOSE="${VERBOSE}"
  ./mytest
  # popd
}

# Derived from: https://gist.github.com/marcusandre/4b88c2428220ea255b83
get_os() {
  local ostype=$(echo $OSTYPE | tr '[:upper:]' '[:lower:]')
  if [ -z "$ostype" ]; then
    ostype=$(uname | tr '[:upper:]' '[:lower:]')
  fi

  case $ostype in
    freebsd*) echo "freebsd" ;;
    netbsd*) echo "netbsd" ;;
    openbsd*) echo "openbsd" ;;
    darwin*) echo "macos" ;;
    linux*) echo "linux" ;;
    cygwin*) echo "cygwin" ;;
    msys*) echo "msys" ;;
    mingw*) echo "win" ;;
    *) echo "unknown"; exit 1 ;;
  esac
}

get_linux_dist() {
  if [ -f /etc/os-release ]; then
    sh -c '. /etc/os-release && echo $ID'
  elif type lsb_release >/dev/null 2>&1; then
    lsb_release -si | tr '[:upper:]' '[:lower:]'
  fi
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

build_and_install_cmake() {
  # cmake
  cmake_build=${LOCAL_BUILDS}/cmake
  mkdir -p "${cmake_build}"
  pushd ${cmake_build}
  wget https://github.com/Kitware/CMake/releases/download/v3.19.6/cmake-3.19.6.tar.gz -O cmake.tar.gz
  tar xzf cmake.tar.gz --strip 1
  ./configure --prefix=/usr && ${MAKE} -j${MAKE_PARALLEL} && ${SUDO} make install
  popd
  CMAKE=/usr/bin/cmake
}

build_and_install_python() {
  # python
  python_build=${LOCAL_BUILDS}/python
  mkdir -p "${python_build}"
  pushd ${python_build}
  curl -L -o python.tar.xz https://www.python.org/ftp/python/3.9.2/Python-3.9.2.tar.xz
  tar -xf python.tar.xz --strip 1
  ./configure --enable-optimizations --prefix=/usr && ${MAKE} -j${MAKE_PARALLEL} && ${SUDO} make install
  ${SUDO} ln -sf /usr/bin/python3 /usr/bin/python
  popd
}

#!/usr/bin/env bash
set -eux

. ci/env.inc.sh

: "${GPG_VERSION:=stable}"
: "${BUILD_MODE:=normal}"

: "${RNP_TESTS=${RNP_TESTS-.*}}"
: "${LD_LIBRARY_PATH:=}"

: "${DIST:=}"
: "${DIST_VERSION:=}"

: "${SKIP_TESTS:=0}"
: "${BUILD_TYPE:=Release}"

prepare_build_prerequisites() {
  CMAKE=cmake

  case "${OS}-${CPU}" in
#    linux-i386)                                       #  For i386/Debian (the only 32 bit run) python3 is already installed by
#      build_and_install_python                        #  linux_install @ install_functions.inc.sh called from install_cacheable_dependencies.sh
#      ;;                                              #  If there is a distribution that does not have python3 pre-apckeges (highly unlikely)
    linux-*)                                           #  it shall be implemented like ensure_cmake
      ensure_cmake
      ;;
  esac

  export CMAKE
}

prepare_test_env() {
  prepare_build_tool_env

  if [[ "${BUILD_TYPE}" == "Debug" ]]; then
    build_type_subdir="/debug"
  else
    build_type_subdir=""
  fi

  lib_path="${VCPKG_ROOT}/installed/${VCPKG_TRIPLET}${build_type_subdir}/lib"

  export LD_LIBRARY_PATH="${lib_path}"

  export PATH="${VCPKG_ROOT}/installed/${VCPKG_TRIPLET}/tools/botan:$PATH"

  # update dll search path for windows
  if [[ "${OS}" = "msys" ]]; then
    export PATH="${lib_path}:$PATH"
  fi
}

prepare_tests() {
  : "${COVERITY_SCAN_BRANCH:=0}"
  [[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

  # workaround macOS SIP
  if [[ "${BUILD_MODE}" != "sanitize" ]] && \
     [[ "${OS}" = "macos" ]]; then
    pushd "$RUBY_RNP_INSTALL"
    cp "${RNP_INSTALL}/lib"/librnp* /usr/local/lib
    popd
  fi
}

build_tests() {
  #  use test costs to prioritize
  mkdir -p "${LOCAL_BUILDS}/rnp-build/Testing/Temporary"
  cp "${rnpsrc}/cmake/CTestCostData.txt" "${LOCAL_BUILDS}/rnp-build/Testing/Temporary"

  local run=run
  case "${DIST_VERSION}" in
    centos-8|fedora-*)
      run=run_in_python_venv
      ;;
  esac

  "${run}" ctest -j"${CTEST_PARALLEL}" -R "$RNP_TESTS" --output-on-failure
  popd
}

main() {
  if [[ ${SKIP_TESTS} = 0 ]]; then
    prepare_test_env
  fi
  prepare_build_prerequisites

  export rnpsrc="$PWD"

  mkdir -p "${LOCAL_BUILDS}/rnp-build"
  pushd "${LOCAL_BUILDS}/rnp-build"

  cmakeopts=(
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"   # RelWithDebInfo -- DebInfo commented out to speed up recurring CI runs.
    -DBUILD_SHARED_LIBS=yes
    -DCMAKE_INSTALL_PREFIX="${RNP_INSTALL}"
  )

  [ -n "${VCPKG_TRIPLET:-}" ] && [ -n "${VCPKG_ROOT:-}" ] && {
    cmakeopts+=(-DVCPKG_TARGET_TRIPLET="${VCPKG_TRIPLET}")
    cmakeopts+=(-DCMAKE_TOOLCHAIN_FILE="${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
  }

  [[ ${SKIP_TESTS} = 1 ]] && cmakeopts+=(-DBUILD_TESTING=OFF)
  [[ "${BUILD_MODE}" = "coverage" ]] && cmakeopts+=(-DENABLE_COVERAGE=yes)
  [[ "${BUILD_MODE}" = "sanitize" ]] && cmakeopts+=(-DENABLE_SANITIZERS=yes)
  [ -n "${GTEST_SOURCES:-}" ] && cmakeopts+=(-DGTEST_SOURCES="${GTEST_SOURCES}")
  [ -n "${DOWNLOAD_GTEST:-}" ] && cmakeopts+=(-DDOWNLOAD_GTEST="${DOWNLOAD_GTEST}")
  [ -n "${DOWNLOAD_RUBYRNP:-}" ] && cmakeopts+=(-DDOWNLOAD_RUBYRNP="${DOWNLOAD_RUBYRNP}")
  [ -n "${CRYPTO_BACKEND:-}" ] && cmakeopts+=(-DCRYPTO_BACKEND="${CRYPTO_BACKEND}")

  if [[ "${OS}" = "msys" ]]; then
    cmakeopts+=(-G "MSYS Makefiles")
  fi
  build_rnp "${rnpsrc}"
  make_install                  # VERBOSE=1 -- verbose flag commented out to speed up recurring CI runs. Uncomment if you are debugging CI

  if [[ ${SKIP_TESTS} = 0 ]]; then
    echo "TESTS NOT SKIPPED"
    prepare_tests
    build_tests
  fi
}

main "$@"

exit 0

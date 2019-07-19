#!/usr/bin/env bash
set -eux

. ci/utils.inc.sh

: "${RNP_TESTS:=.*}"

CMAKE=cmake

# check for use of uninitialized or unused vars in CMake
function cmake {
  log=$(mktemp)
  command ${CMAKE} --warn-uninitialized --warn-unused "$@" 2>&1 | tee "$log"
  if grep -Fqi 'cmake warning' "$log"; then exit 1; fi
}

if [[ "$(get_os)" = "linux" ]]; then
  pushd /
  sudo curl -L -o cmake.sh https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.sh
  sudo sh cmake.sh --skip-license
  popd
  CMAKE=/bin/cmake
fi

cmakeopts=(
  "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
  "-DBUILD_SHARED_LIBS=yes"
  "-DCMAKE_INSTALL_PREFIX=${RNP_INSTALL}"
  "-DCMAKE_PREFIX_PATH=${BOTAN_INSTALL};${CMOCKA_INSTALL};${JSONC_INSTALL};${GPG_INSTALL}"
  "-Dcmocka_DIR=${CMOCKA_INSTALL}/cmocka"
)
[ "$BUILD_MODE" = "coverage" ] && cmakeopts+=("-DENABLE_COVERAGE=yes")
[ "$BUILD_MODE" = "sanitize" ] && cmakeopts+=("-DENABLE_SANITIZERS=yes")

mkdir -p "${LOCAL_BUILDS}/rnp-build"
rnpsrc="$PWD"
pushd "${LOCAL_BUILDS}/rnp-build"
export LD_LIBRARY_PATH="${GPG_INSTALL}/lib:${BOTAN_INSTALL}/lib:${JSONC_INSTALL}/lib:${RNP_INSTALL}/lib"

cmake "${cmakeopts[@]}" "$rnpsrc"
make -j${MAKE_PARALLEL} VERBOSE=1 install

: "${COVERITY_SCAN_BRANCH:=0}"
[[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

# workaround macOS SIP
if [ "$BUILD_MODE" != "sanitize" ]; then
  pushd "$RUBY_RNP_INSTALL"
  [[ "$(get_os)" = "macos" ]] && cp "${RNP_INSTALL}/lib"/librnp* /usr/local/lib
  popd
fi

#  use test costs to prioritize
mkdir -p "${LOCAL_BUILDS}/rnp-build/Testing/Temporary"
cp "${rnpsrc}/cmake/CTestCostData.txt" "${LOCAL_BUILDS}/rnp-build/Testing/Temporary"

ctest -j"${CTEST_PARALLEL}" -R "$RNP_TESTS" --output-on-failure
popd

exit 0


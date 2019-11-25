#!/usr/bin/env bash
set -eux

. ci/utils.inc.sh

: "${RNP_TESTS:=.*}"
: "${LD_LIBRARY_PATH:=}"

CMAKE=cmake

if [[ "$(get_os)" = "linux" ]]; then
  pushd /
  sudo curl -L -o cmake.sh https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.sh
  sudo sh cmake.sh --skip-license --prefix=/usr
  popd
  CMAKE=/usr/bin/cmake
fi

cmakeopts=(
  "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
  "-DBUILD_SHARED_LIBS=yes"
  "-DCMAKE_INSTALL_PREFIX=${RNP_INSTALL}"
  "-DCMAKE_PREFIX_PATH=${BOTAN_INSTALL};${JSONC_INSTALL};${GPG_INSTALL}"
)
[ "$BUILD_MODE" = "coverage" ] && cmakeopts+=("-DENABLE_COVERAGE=yes")
[ "$BUILD_MODE" = "sanitize" ] && cmakeopts+=("-DENABLE_SANITIZERS=yes")

if [[ "$(get_os)" = "msys" ]]; then
  cmakeopts+=("-G")
  cmakeopts+=("MSYS Makefiles")
fi

mkdir -p "${LOCAL_BUILDS}/rnp-build"
rnpsrc="$PWD"
pushd "${LOCAL_BUILDS}/rnp-build"
export LD_LIBRARY_PATH="${GPG_INSTALL}/lib:${BOTAN_INSTALL}/lib:${JSONC_INSTALL}/lib:${RNP_INSTALL}/lib:$LD_LIBRARY_PATH"

# update dll search path for windows
if [[ "$(get_os)" = "msys" ]]; then
  export PATH="${LOCAL_BUILDS}/rnp-build/lib:${LOCAL_BUILDS}/rnp-build/bin:${LOCAL_BUILDS}/rnp-build/src/lib:$PATH"
fi

${CMAKE} "${cmakeopts[@]}" "$rnpsrc"
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


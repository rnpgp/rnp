#!/usr/bin/env bash
set -eux

[ "$BUILD_MODE" = "style-check" ] && exec ci/style-check.sh

: "${CORES:=2}"
: "${RNP_TESTS:=all}"

# check for use of uninitialized or unused vars in CMake
function cmake {
  log=$(mktemp)
  command cmake --warn-uninitialized --warn-unused "$@" 2>&1 | tee "$log"
  if grep -Fqi 'cmake warning' "$log"; then exit 1; fi
}

cmakeopts=(
  "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
  "-DBUILD_SHARED_LIBS=yes"
  "-DCMAKE_INSTALL_PREFIX=${RNP_INSTALL}"
  "-DCMAKE_PREFIX_PATH=${BOTAN_INSTALL};${CMOCKA_INSTALL};${JSONC_INSTALL};${GPG_INSTALL}"
  "-Dcmocka_DIR=${CMOCKA_INSTALL}/cmocka"
)
[ "$BUILD_MODE" = "coverage" ] && cmakeopts+=("-DENABLE_COVERAGE=yes")
[ "$BUILD_MODE" = "sanitize" ] && cmakeopts+=("-DENABLE_SANITIZERS=yes")

mkdir build
pushd build
export LD_LIBRARY_PATH="${GPG_INSTALL}/lib"

cmake "${cmakeopts[@]}" ..
make -j${CORES} VERBOSE=1 install

: "${COVERITY_SCAN_BRANCH:=0}"
[[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

case "$RNP_TESTS" in
  cmocka)
    ctest -R rnp_tests --output-on-failure
    ;;
  cli)
    ctest -R cli_tests --output-on-failure
    ;;
  all)
    ctest -j${CORES} --output-on-failure
    ;;
  *) exit 1 ;;
esac
popd

# don't run ruby-rnp tests when librnp is built with sanitizers (various issues)
if [ "$BUILD_MODE" != "sanitize" ]; then
  pushd "$RUBY_RNP_INSTALL"
  env CI=false \
      LD_LIBRARY_PATH="${BOTAN_INSTALL}/lib:${JSONC_INSTALL}/lib:${RNP_INSTALL}/lib" \
      bundle exec rspec
  popd
fi

exit 0


#!/usr/bin/env bash
set -euxo pipefail

main() {
  pushd "${LOCAL_BUILDS}/rnp-build"
  local build_type_subdir
  if [[ "${BUILD_TYPE}" == "Debug" ]]; then
    build_type_subdir="/debug"
  else
    build_type_subdir=""
  fi
  cpack -G DEB -D CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS="${VCPKG_ROOT}/installed/${VCPKG_TRIPLET}${build_type_subdir}/lib"
  popd
}

main "$@"

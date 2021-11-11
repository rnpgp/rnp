#!/usr/bin/env bash
# shellcheck disable=SC1091
set -exu

. ci/env.inc.sh
echo " --> install_cacheable_dependencies.sh"
echo "CXXFLAGS=${CXXFLAGS}"
install_static_cacheable_build_dependencies_if_needed "$@"

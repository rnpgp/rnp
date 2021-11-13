#!/usr/bin/env bash
# shellcheck disable=SC1091
set -exu

. ci/env.inc.sh

"${OS}_install"
rubygem_install_build_dependencies "$@"

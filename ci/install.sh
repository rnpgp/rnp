#!/usr/bin/env bash
# shellcheck disable=SC1091
set -exu

. ci/env.inc.sh

install_static_build_dependencies "$@"

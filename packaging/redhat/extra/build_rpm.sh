#!/bin/bash
#
# (c) 2017 Ribose Inc.
#
# Specify the version (default: 1) of the RPM with the first argument or 
# $VERSION env var.

# Try to read the NETPGP_BASE_VERSION from source and take it as the RPM 
# version number.

readonly __file_dir=$(dirname $0)
readonly version_file=${__file_dir}/../../../src/lib/version.h

if [ -r ${version_file} ]; then
  readonly default_version=$( \
    /usr/bin/env grep define.*RNP_BASE_VERSION ${version_file} | \
    awk '{print $3}' | \
    sed 's/"//g' \
  )
fi

VERSION=${1:-${VERSION:-${default_version}}}
RELEASE=${2:-${RELEASE:-1}}

echo ${__file_dir}/package-builder.sh "${VERSION}" "${RELEASE}"
${__file_dir}/package-builder.sh "${VERSION}" "${RELEASE}"

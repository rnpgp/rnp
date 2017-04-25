#!/bin/bash
#
# (c) 2017 Ribose Inc.
# Frank Trampe, Jeffrey Lau and Ronald Tse.
#
# It is hereby released under the license of the enclosing project.
#
# Preconditions:
#  - $ ls
#    rnp/
#
# Call this with:
#
#  - the desired version number as the first argument;
#  - the desired rpm release number as the second argument;
#
#  - the path where the source code is as the third optional argument;
#    (default: the same as the package name, $PNAME.
#
#  - the directory to place the generated spec file as the fourth optional
#    argument;
#    (default: ~/rpmbuild/SPECS)
#

readonly __progname="$(basename $0)"

usage() {
  echo "Usage: ${__progname} <version> [source_path] [target_spec_dir]" >&2
}

main() {
  # Make sure at least the version is supplied.
  if [ $# -lt 1 ]; then
    usage
    exit 1
  fi

  readonly local PNAME=rnp
  readonly local PVERSION="$1"
  readonly local PRELEASE="$2"
  readonly local PPATH="${3:-${PNAME}}"
  readonly local SPEC_DIR="${4:-${HOME}/rpmbuild/SPECS}"
  readonly local PNAMEVERSION="${PNAME}-${PVERSION}"
  # readonly local SOURCES_DIR="${SOURCES_DIR:-${HOME}/rpmbuild/SOURCES}"

  # Create the SPEC_DIR.
  mkdir -p "${SPEC_DIR}"

  # readonly local PSOURCE_PATH="${SOURCES_DIR}/${PNAMEVERSION}.tar.bz2"
  readonly local PSOURCE_PATH="${PNAMEVERSION}.tar.bz2"
  #readonly local PSOURCE_PATH="https://api.github.com/repos/riboseinc/rp/tarball/${PVERSION}"

  # Generate the spec file, and copy it to the source directory.
  readonly local PSPEC_PATH="${SPEC_DIR}/${PNAME}.spec"
  m4 \
    -D "PACKAGE_VERSION=${PVERSION}" \
    -D "SOURCE_TARBALL_NAME=${PSOURCE_PATH}" \
    -D "RELEASE=${PRELEASE}" \
    < "packaging/redhat/m4/rnp.spec.m4" \
    > "${PSPEC_PATH}" && \

  chown $(id -u):$(id -g) "${PSPEC_PATH}" && \
  cp "${PSPEC_PATH}" "$(dirname $0)/"
}

main "$@"

# vim:sw=2:et

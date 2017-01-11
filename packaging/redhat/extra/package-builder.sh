#!/bin/bash
#
# Jan 2017
#
# This is a project-specific variant of a script written by Frank Trampe,
# with modifications by Jeffrey Lau.
#
# It is hereby released under the license of the enclosing project.
# Call this with:
#  - the desired version number as the first argument;
#  - the path where the source code is as the second optional argument;
#    (default: the same as the package name, $PNAME.
#  - the directory to place the generated spec file as the third optional
#    argument.
#    (default: ~/rpmbuild/SPECS)

usage() {
	echo "Usage: ${0} <version> [source_path] [target_spec_dir]" >&2
}

main() {
	# Make sure at least the version is supplied.
	if [ $# -lt 1 ]; then usage ; exit 1; fi
	local PNAME=netpgp
	local PVERSION="$1"
	local PPATH="${2:-${PNAME}}"
	local SPEC_DIR="${3:-${HOME}/rpmbuild/SPECS}"
	local PNAMEVERSION="${PNAME}-${PVERSION}"
	local SOURCES_DIR="${SOURCES_DIR:-${HOME}/rpmbuild/SOURCES}"

	# Make a new copy of the sources and name by version, clearing any remnant from before.
	if [ -e "${PNAMEVERSION}" ]; then rm -rf "${PNAMEVERSION}"; fi
	cp -pRP "$PPATH" "${PNAMEVERSION}"

	# Clean the new sources.
	# Make sure to commit everything first before running this script!
	# (cd "${PNAMEVERSION}"; if [ -e .git ]; then git clean -fdx; git reset --hard; fi;)

	# Make the source tarball for the build.
	tar -cjf "${PNAMEVERSION}".tar.bz2 "${PNAMEVERSION}"

	# Copy the source tarball into the source directory for rpmbuild.
	local PSOURCE_PATH="${SOURCES_DIR}/"${PNAMEVERSION}".tar.bz2"
	cp -pRP "${PNAMEVERSION}".tar.bz2 "${PSOURCE_PATH}"
	chown $(id -u):$(id -g) "${PSOURCE_PATH}"

	# Generate the spec file.
	local PSPEC_PATH="${SPEC_DIR}/${PNAMEVERSION}.spec"
	chown $(id -u):$(id -g) "${PSPEC_PATH}"
	m4 \
		-D "PACKAGE_VERSION=${PVERSION}" \
		-D "PREFIX=/usr" \
		-D "SOURCE_TARBALL_NAME=${PSOURCE_PATH}" < "${PNAMEVERSION}"/packaging/redhat/m4/rpm.spec > "${PSPEC_PATH}"

	# Build the packages.
	rpmbuild -ba --nodeps "${PSPEC_PATH}"
}

main "$@"

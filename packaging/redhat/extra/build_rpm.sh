#!/bin/bash
#
# (c) 2017 Ribose Inc.
#
# Specify the version (default: 1) of the RPM with the first argument or 
# $VERSION env var.

VERSION=${1:-${VERSION:-1}}
cd /usr/local/ || \
	exit 1
netpgp/packaging/redhat/extra/package-builder.sh "${VERSION}"

#!/bin/bash
#
# Copyright (c) 2017 Ribose Inc.
# build_macos.sh

OPENSSL_ROOT_DEFAULT='/usr/local'

find_openssl_root_homebrew() {

	# Check that brew is available on the search path and that OpenSSL
	# is installed:

	if command -v brew >/dev/null; then
		if brew --prefix openssl 2>/dev/null; then
			return 0
		fi
	fi
	return 1
}

find_openssl_root() {
	if ! find_openssl_root_homebrew; then
		OPENSSL_ROOT="$OPENSSL_ROOT_DEFAULT"
	fi
}

# You can override the OpenSSL root directory from the environment if you
# wish; e.g. if using a different package manager:
#
# OPENSSL_ROOT='/opt/pkg' ./build_macos.sh

[ -z "$OPENSSL_ROOT" ] && OPENSSL_ROOT="$(find_openssl_root)"

ACFLAGS="--with-openssl=$OPENSSL_ROOT"

# configure will check that the given OpenSSL path is probably OpenSSL but
# we still need to add OPENSSL_ROOT to the preprocessor and linker search
# paths. We set up that environment here:

CFLAGS="$CFLAGS -I$OPENSSL_ROOT/include"

LDFLAGS="$LDFLAGS -L$OPENSSL_ROOT/lib"

export CFLAGS LDFLAGS

. build_main.inc.sh

#!/bin/bash
#
# Copyright (c) 2017 Ribose Inc.
# build_macos.sh

[ -z "$OPENSSL_ROOT" ] && OPENSSL_ROOT="/usr/local/opt/openssl"

reconf() {

	# Check that the ./m4/ directory exists.
	if [ ! -e m4 ]; then
		mkdir m4
	elif [ -f m4 ]; then
		echo "fatal: $(dirname $0)/m4 is not a directory. Please " \
		     "move or delete it and try again."
		return 1
	fi

	autoreconf -ivf
}

configure() {

	# configure will check that OpenSSL is OpenSSL but we must still
	# manually specify that we want it on the preprocessor and linker
	# search paths.
	#
	# If you're using a different package manager (like pkgin) you can
	# invoke this script with a suitable OPENSSL_ROOT:
	#
	# $ OPENSSL_ROOT='/opt/pkg' ./build_macos.sh

	CFLAGS="-I$OPENSSL_ROOT/include" \
	LDFLAGS="-L$OPENSSL_ROOT/lib" \
		./configure --with-openssl="$OPENSSL_ROOT"
}

main() {
	if reconf; then
		if configure; then
			make
		fi
	fi
}

interactive() {
	echo $- | grep i >/dev/null
}

if ! interactive; then
	main
fi

#!/bin/bash
#
# Copyright (c) 2017 Ribose Inc.
# build_common.inc.sh

rnpbuild_reconf() {

	# Check that the ./m4/ directory exists.
	if [ ! -e m4 ]; then
		mkdir m4
	elif [ -f m4 ]; then
		echo "fatal: $(dirname $0)/m4 is not a directory. Please " \
		     "move or delete it and try again."
		return 1
	fi

	which autoreconf 2>&1 >/dev/null
	if [ $? -ne 0 ]; then
		echo "fatal: autoreconf not found. Hint: 'brew install" \
		    "autoconf automake'"
		return 1
	fi

	autoreconf -ivf
}

rnpbuild_configure() {
	export CFLAGS=${CFLAGS:-"-g3 -O0"}
	./configure
}

rnpbuild_main() {
	if rnpbuild_reconf; then
		if rnpbuild_configure; then
			make
		fi
	fi
}

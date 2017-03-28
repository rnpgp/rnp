#!/bin/bash
#
# Copyright (c) 2017 Ribose Inc.
# build_main.inc.sh

. build_common.inc.sh

interactive() {
	! echo $- | grep i >/dev/null
}

interactive && rnpbuild_main

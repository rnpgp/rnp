#!/bin/sh
set -eux

. ci/env.inc.sh
ci/before_install.sh
ci/install.sh
ci/main.sh


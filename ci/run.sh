#!/bin/sh
set -eux

ci/before_install.sh
. ci/env.inc.sh
ci/install.sh
ci/main.sh
ci/success.sh


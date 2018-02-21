#!/bin/bash
set -eux

rsync -a /usr/local/rnp /tmp
sudo -iu travis bash <<EOF
cd /tmp/rnp
env GPG_VERSION=$GPG_VERSION BUILD_MODE=$BUILD_MODE ci/run-local.sh
EOF


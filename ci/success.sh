#!/bin/bash
set -eu

if [ "$BUILD_MODE" = "coverage" ]; then
  bash <(curl -s https://codecov.io/bash) \
    -K \
    -p "${LOCAL_BUILDS}/rnp-build" \
    -R "$GITHUB_WORKSPACE"
fi

